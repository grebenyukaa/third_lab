from flask import *
#from session import SqliteSessionInterface
import os

app = Flask(__name__)
app.config.update(dict(
    SQLALCHEMY_DATABASE_URI='sqlite:///{0}'.format(os.path.join(app.root_path, 's_lab.db')),
    DEBUG=True
))
app.secret_key = "Very secret key for flask"

from sqlite3 import dbapi2 as sqlite
from sqlalchemy.orm import sessionmaker, aliased

from datetime import datetime, timedelta
import hashlib, string, random

### Models ###

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import *

db = SQLAlchemy(app)

def random_string(size):
    return ''.join([random.choice(string.ascii_letters) for i in range(size)])

class User(db.Model):
    __tablename__ = "user"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    username = db.Column(db.String(100), unique=True)
    pw_hash = db.Column(db.String(256))
    mail = db.Column(db.String(200))
    phone = db.Column(db.String(11))
    
    auths = db.relationship("Authorization", cascade="all, delete-orphan")
    sessions = db.relationship("UserSession", cascade="all, delete-orphan")
    clients = db.relationship("Client", cascade="all, delete-orphan")
    posts = db.relationship("Post")
    comments = db.relationship("Comment")
    
    def __init__(self, username, pw_hash, phone, mail):
        self.username = username
        self.pw_hash = pw_hash
        self.mail = mail
        self.phone = phone

    def __repr__(self):
        return 'username: {0}, mail: {1}, phone: {2}'.format(self.username, self.mail, self.phone)
    
    def to_dict(self):
        return {'username': self.username, 'password': self.pw_hash, 'mail': self.mail, 'phone': self.phone}

class UserSession(db.Model):
    __tablename__ = "usersession"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    session_id = db.Column(db.String(32), unique = True)
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    def __init__(self, user):
        self.session_id = random_string(32)
        self.user_id = user.id

class AppCode(db.Model):
    lifetime_min = 10
    __tablename__ = "appcode"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    code = db.Column(db.String(32), unique = True)
    timestamp = db.Column(db.DateTime)
    client_id = db.Column(ForeignKey("client.id"), nullable=False)
    auth_id = db.Column(ForeignKey("authorization.id"))
    
    def __init__(self, client):
        self.code = random_string(32)
        self.client_id = client.id
        self.timestamp = datetime.utcnow()
        
    def is_valid(self):
        return (self.timestamp - datetime.utcnow()) < timedelta(minutes = self.lifetime_min)

class Client(db.Model):
    __tablename__ = "client"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    client_id = db.Column(db.String(32), unique = True)
    secret_id = db.Column(db.String(256), unique = True)
    redirect_uri = db.Column(db.String(100))
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    appcodes = db.relationship("AppCode", cascade="all, delete-orphan")
    
    def __init__(self, redirect_uri, user_id):
        self.client_id = random_string(32)
        self.secret_id = hashlib.sha256(random_string(32).encode('utf-8')).hexdigest()
        self.redirect_uri = redirect_uri
        self.user_id = user_id
        
    def __repr__(self):
        return 'cl_id: {0}, username: {1}, redir_uri: {2}'.format(self.client_id, self.username, self.redirect_uri)
    
    def to_dict(self):
        return {'cl_id': self.client_id, 'secret_id': self.secret_id, 'username': self.username, 'redirect_uri': self.redirect_iri}

class Authorization(db.Model):
    __tablename__ = "authorization"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    access_token = db.Column(db.String(32), unique=True)
    refresh_token = db.Column(db.String(32), unique=True)
    timestamp = db.Column(db.DateTime)
    is_authorized = db.Column(db.Boolean(), default=False)
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    appcodes = db.relationship("AppCode", cascade="all, delete-orphan")
    
    def __init__(self, user):
        self.user_id = user.id
        self.token_refresh()
        
    def __repr__(self):
        return 'cl_id: {0}, access_token: {1}, authorized: {2}, ts: {3}'.format(self.client_id, self.access_token, self.is_authorized, self.timestamp)
    
    def unauthorize(self):
        self.is_authorized = False
    
    def authorize(self):
        if self.access_token:
            self.is_authorized = True
        else:
            self.token_refresh()
    
    def token_revoke(self):
        self.access_token = ""
        self.refresh_token = ""
        self.is_authorized = False
    
    def token_refresh(self):
        self.access_token = random_string(32)
        self.refresh_token = random_string(32)
        self.timestamp = datetime.utcnow()
        self.is_authorized = True
        
    def token_expired(self):
        return (self.timestamp - datetime.utcnow()) >= timedelta(hours = 1)

    def authorized(self):
        return (not self.token_expired()) and self.is_authorized

class Post(db.Model):
    __tablename__ = "post"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    caption = db.Column(db.String(100))
    text = db.Column(db.Text())
    author_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    comments = db.relationship("Comment", cascade="all, delete-orphan")
    
    def __init__(self, user_id, caption, text):
        self.author_id = user_id
        self.caption = caption
        self.text = text
        
    def __repr__(self):
        return 'id: {0}, author: {1}, caption: {2}'.format(self.id, self.author_id, self.caption)

    def to_dict(self):
        return {'id': self.id, 'author_id': self.author_id, 'caption': self.caption, 'text': self.text}
    
    def to_dict_short(self):
        return {'id': self.id, 'author_id': self.author_id, 'caption': self.caption}

class Comment(db.Model):
    __tablename__ = "comment"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    text = db.Column(db.Text())
    author_id = db.Column(ForeignKey("user.id"), nullable=False)
    post_id = db.Column(ForeignKey("post.id"), nullable=False)
    deleted = db.Column(db.Boolean(), default = False)
    
    def __init__(self, user_id, post_id, text):
        self.author_id = user_id
        self.post_id = post_id
        self.text = text
        
    def __repr__(self):
        return 'id: {0}, author: {1}'.format(self.id, self.author_id)

    def to_dict(self):
        return {'id': self.id, 'author_id': self.author_id, 'post_id': self.post_id, 'text': self.text if not self.deleted else '', 'deleted': self.deleted}
        
    def delete(self):
        self.deleted = True
        
### Views ###

def response_builder(r, s):
    resp = jsonify(r)
    resp.status_code = s
    return resp

def get_url_parameter(name):
    rjson = request.get_json()
    if name in request.args:
        return request.args[name]
    elif name in request.form:
        return request.form[name]
    elif name in request.headers:
        return request.headers[name]
    elif rjson:
        if name in rjson:
            return rjson[name]
    else:
        return None
                                                                             
def has_url_parameter(name):
    rjson = request.get_json()
    part = (name in request.args) or (name in request.form) or (name in request.headers)
    return ((name in rjson) and part) if rjson else part

def get_access_token():
    if has_url_parameter('Authorization'):
        ah = get_url_parameter('Authorization')
        t, token = ah.split(' ')
        if t == 'bearer':
            return token
        else:
            return None
    else:
        return get_url_parameter('access_token')

@app.errorhandler(404)
def api_404(msg = 'Not found'):
    return response_builder({'error': msg}, 404)

@app.errorhandler(401)
def api_401(msg = 'Not authorized'):
    return response_builder({'error': msg}, 401)

@app.errorhandler(403)
def api_403(msg = 'Forbidden'):
    return response_builder({'error': msg}, 403)

@app.errorhandler(406)
def api_406(msg = 'Unacceptable'):
    return response_builder({'error': msg}, 406)

@app.errorhandler(200)
def api_200(data = {}):
    return response_builder(data, 200)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        uname = get_url_parameter('username')
        pw = hashlib.sha256(get_url_parameter('password').encode('utf-8')).hexdigest()
        mail = get_url_parameter('mail')
        phone = get_url_parameter('phone')
        
        if not User.query.filter_by(username = uname).all():
            user = User(uname, pw, mail, phone)
            db.session.add(user)
            db.session.commit()
            return api_200()
        else:
            error = 'User already exists'
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        un = get_url_parameter('username')
        pw = get_url_parameter('password')
        
        user = User.query.filter_by(username = un).first()
        if user:
            s = UserSession(user)
            db.session.add(s)
            db.session.commit()
            
            resp = None
            if has_url_parameter('back_to_code'):
                resp = redirect(url_for('code', session_id = s.session_id))
            else:
                resp = api_200({'session_id' : s.session_id})
            resp.set_cookie('session_id', s.session_id)
            return resp
        else:
            error = 'User not found'
            
    if (has_url_parameter('back_to_code')):        
        return render_template(\
            'login.html',\
            error=error,\
            back_to_code = True,\
            client_id = get_url_parameter('client_id'),\
            secret_id = get_url_parameter('secret_id'),\
            state = get_url_parameter('state')\
        )
    else:
        return render_template('login.html', error=error, back_to_code = False)

@app.route('/logout', methods=['POST'])
def logout():
    if has_url_parameter('session_id'):
        sid = get_url_parameter('session_id')
        s = UserSession.query.filter_by(session_id = sid).first()
        if s:
            db.session.delete(s)
            db.session.commit()
            return api_200()
        else:
            return api_401()
    else:
        return api_406('Required parameters: session_id')

@app.route('/register_app', methods=['POST'])
def register_app():
    if has_url_parameter('session_id') and has_url_parameter('redirect_uri'):
        sid = get_url_parameter('session_id')
        ruri = get_url_parameter('redirect_uri')
                
        s = UserSession.query.filter_by(session_id = sid).first()
        if s:
            cli = Client(ruri, s.user_id)
            db.session.add(cli)
            db.session.commit()
            return api_200({'client_id': cli.client_id, 'secret_id': cli.secret_id})
        else:
            return api_401()
    else:
        return api_406('Required parameters: session_id, redirect_uri')

@app.route('/code', methods=['GET'])
def code():
    s = UserSession.query.filter_by(session_id = request.cookies.get('session_id')).first()
    if has_url_parameter('client_id') and has_url_parameter('secret_id') and has_url_parameter('state'):
        clid = get_url_parameter('client_id')
        sidh = get_url_parameter('secret_id')
        state = get_url_parameter('state')
    else:
        return api_406('Required parameters: client_id, secret_id, state')
    if s:      
        cli = Client.query.filter_by(client_id = clid, secret_id = sidh).first()
        if cli:
            code = AppCode(cli)
            db.session.add(code)    
            db.session.commit()    
            return redirect(cli.redirect_uri + '?state={0}&code={1}&lifetime_minutes={2}'.format(state, code.code, code.lifetime_min))
        else:
            return api_401('Invalid client_id - secret_id pair')
    else:
        return redirect(url_for('login', back_to_code = True, client_id = clid, secret_id = sidh, state = state))

@app.route('/access_token', methods=['GET'])
def access_token():
    cli = None
    if has_url_parameter('code') and has_url_parameter('client_id') and has_url_parameter('secret_id'):
        code = get_url_parameter('code')
        clid = get_url_parameter('client_id')
        sech = get_url_parameter('secret_id')
        code = AppCode.query.filter_by(code = code).first()
        if code:
            if code.is_valid():
                cli = Client.query.filter_by(id = code.client_id, client_id = clid, secret_id = sech).first()
            else:
                return api_401('Code is no more valid')
            
    if cli:
        auth = Authorization.query.join(AppCode, AppCode.auth_id == Authorization.id).filter(AppCode.id == code.id).first()
        if not auth:
            auth = Authorization(cli)
            db.session.add(auth)
            db.session.commit()
        return api_200({'access_token' : auth.access_token, 'refresh_token' : auth.refresh_token})
    else:
        return api_401()
        
@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    cli = None
    if has_url_parameter('client_id') and has_url_parameter('secret_id'):
        cli = Client.query.filter_by(client_id = get_url_parameter('client_id'), secret_id = get_url_parameter('secret_id')).first()
    if cli:
        if has_url_parameter('refresh_token'):
            rt = get_url_parameter('refresh_token')
            auth = Authorization.query.filter_by(refresh_token = rt).first()
            if auth:
                auth.token_refresh()
                db.session.commit()
                return api_200({'access_token' : auth.access_token, 'refresh_token' : auth.refresh_token})
        else:
            return api_406('Required parameters: client_id, secret_id, refresh_token')
    return api_401()
    
@app.route('/revoke_token', methods=['POST'])
def revoke_token():
    cli = None
    if has_url_parameter('client_id') and has_url_parameter('secret_id'):
        cli = Client.query.filter_by(client_id = get_url_parameter('client_id'), secret_id = get_url_parameter('secret_id')).first()
    if cli:
        if has_url_parameter('refresh_token'):
            rt = get_url_parameter('refresh_token')
            auth = Authorization.query.filter_by(refresh_token = rt).first()
            if auth:
                #auth.token_revoke()
                db.session.delete(auth)
                db.session.commit()
                return api_200()
        else:
            return api_406('Required parameters: client_id, secret_id, refresh_token')
    return api_401()

@app.route('/me', methods=['GET'])
def me():
    at = get_access_token()
    auth = Authorization.query.filter_by(access_token = at).first()
    if auth:
        if auth.authorized():
            user = User.query.filter_by(id = auth.user_id).first()
            retv = user.to_dict()
            return api_200(retv)
    return api_401('Not authorized or token expired')

@app.route('/authorized_users', methods=['GET'])
def authorized_users():
    clis = User.query.join(Authorization, Authorization.user_id == User.id).filter(Authorization.is_authorized == True).all()
    return api_200({'Authorized_users':[c.username for c in clis]})

@app.route('/', methods=['GET'])
def root():
    return 'It is main page, yep!'

def is_authorized(auth):
    if auth:
        return auth.authorized()
    return False

# Posts

@app.route('/posts', methods=['GET'])
def get_posts():
    if has_url_parameter('author_un'):        
        author = get_url_parameter('author_un')
        posts = Post.query\
            .join(User.posts)\
            .filter(User.username == author)\
            .all()
        return api_200({'Posts': [p.to_dict_short() for p in posts]})
    else:
        return api_200({'Posts': [p.to_dict_short() for p in Post.query.all()]})

@app.route('/posts', methods=['POST'])
def post_post():
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        
        author = get_url_parameter('author_un')
        if (user.username == author):
            text = get_url_parameter('text')
            caption = get_url_parameter('caption')
            p = Post(user.id, caption, text)
            db.session.add(p)
            db.session.commit()
            return api_200({'post_id': p.id})
        else:
            return api_403()

@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    p = Post.query.filter_by(id = post_id).first()
    return api_200(p.to_dict()) if p else api_404() 

@app.route('/posts/<int:post_id>', methods=['PUT'])
def put_post(post_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        p = Post.query.filter_by(id = post_id).first()
        if p:
            user = User.query.filter_by(id = auth.user_id).first()
            author = get_url_parameter('author_un')
            if (user.username == author):
                text = get_url_parameter('text')
                caption = get_url_parameter('caption')
                p.text = text
                p.caption = caption
                db.session.commit()
                return api_200()
            else:
                return api_403()
        return api_404()
    return api_401('Not authorized or token expired')

@app.route('/posts/<int:post_id>', methods=['DELETE'])
def del_post(post_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        p = Post.query.filter_by(id = post_id).first()
        if p:
            user = User.query.filter_by(id = auth.user_id).first()
            author = get_url_parameter('author_un')
            if (user.username == author):
                db.session.delete(p)
                db.session.commit()
                return api_200()
            else:
                return api_403()
        else:
            return api_404()
    return api_401('Not authorized or token expired')

# Comments

@app.route('/comments', methods=['GET'])
def get_comments():
    pid = get_url_parameter('post_id')
    rpp = get_url_parameter('res_per_page')
    cnt = get_url_parameter('limit')
    offset = get_url_parameter('offset')
    cs = None
    if has_url_parameter('author_un'):        
        author = get_url_parameter('author_un')
        cs = Comment.query\
            .join(User.comments)\
            .filter(User.username == author)\
            .filter(Comment.post_id == pid)\
            .offset(offset).limit(cnt)\
            .all()
    else:
        cs = Comment.query.filter(Comment.post_id == pid).offset(offset).limit(cnt).all()
    retv = []
    results_per_page = int(rpp)
    for i, c in enumerate(cs):
        page = int(i / results_per_page)
        crepr = c.to_dict()
        crepr.update({'page': page})
        retv += [crepr]
    return api_200({'Comments': retv})

@app.route('/comments', methods=['POST'])
def post_comment():
    
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        
        pid = get_url_parameter('post_id')
        author = get_url_parameter('author_un')
        if (user.username == author):
            text = get_url_parameter('text')
            c = Comment(user.id, pid, text)
            db.session.add(c)
            db.session.commit()
            return api_200({'comment_id': c.id})
        else:
            return api_403()

@app.route('/comments/<int:comment_id>', methods=['GET'])
def get_comment(comment_id):
    c = Comment.query.filter_by(id = comment_id).first()
    return api_200(c.to_dict()) if c else api_404()

@app.route('/comments/<int:comment_id>', methods=['PUT'])
def put_comment(comment_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        author = get_url_parameter('author_un')
        if (user.username == author):
            text = get_url_parameter('text')
            c = Comment.query.filter_by(id = comment_id).first()
            if c:
                if not c.deleted:
                    c.text = text
                    db.session.commit()
                    return api_200()
                else:
                    return api_403('Comment was deleted')
            else:
                return api_404()
        else:
            return api_403()
    return api_401('Not authorized or token expired')

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def del_comment(comment_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        author = get_url_parameter('author_un')
        if (user.username == author):
            text = get_url_parameter('text')
            c = Comment.query.filter_by(id = comment_id).first()
            if c:
                c.delete()
                db.session.commit()
                return api_200()
            else:
                return api_404()
        else:
            return api_403()
    return api_401('Not authorized or token expired')

### Other ###

if __name__ == '__main__':
    app.run()
    
### Testing ###
