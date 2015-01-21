import settings
from models import *
from common import *

from flask import *

app = Flask(__name__)
app.config.update(dict(\
    SQLALCHEMY_DATABASE_URI=settings.DATABASE_PATH),\
    DEBUG=True\
)

@app.route('/session/register', methods=['POST'])
def session_register():
    if has_url_parameter('username') and has_url_parameter('password') and has_url_parameter('mail') and has_url_parameter('phone'):
        uname = get_url_parameter('username')
        pw = get_url_parameter('password')
        mail = get_url_parameter('mail')
        phone = get_url_parameter('phone')
        
        u = User.query.filter_by(username = uname).first()
        if not u:
            u = User(uname, pw, phone, mail)
            db_session.add(u)
            db_session.commit()
            return api_200({'user_id': u.id})
        else:
            return api_403('User already exists')
    else:
        return api_406('Required parameters: username, password, mail, phone')

@app.route('/session/login', methods=['GET'])
def session_login():
    un = get_url_parameter('username')
    pw = get_url_parameter('password')
    
    u = User.query.filter_by(username = un, pw_hash = pw).first()
    if u:
        s = UserSession.query.filter_by(user_id = u.id).first()
        if s:
            if not s.session_expired():
                return api_200({'session_id': s.session_id})
            else:
                s.refresh()
        else:
            s = UserSession(u.id)
            db_session.add(s)
        db_session.commit()
        return api_200({'session_id': s.session_id})
    else:
        return api_401('Invalid credentials specified')

@app.route('/session/logout', methods=['POST'])
def session_logout():
    sid = get_url_parameter('session_id')
    s = UserSession.query.filter_by(session_id = sid).first()
    if s:
        db_session.delete(s)
        db_session.commit()
        return api_200()
    else:
        return api_401()

@app.route('/session/check', methods=['GET'])
def session_check():
    sid = get_url_parameter('session_id')
    s = UserSession.query.filter_by(session_id = sid).first()
    if s:
        if not s.session_expired():
            return api_200({'user_id': s.user_id})
        else:
            return api_403('Session expired')
    return api_404('Invalid session_id')   

### Users ###

@app.route('/session/users', methods=['GET'])
def session_user_by_session_id():
    if has_url_parameter('session_id'):
        sid = get_url_parameter('session_id')
        u = User.query.join(UserSession, User.id == UserSession.user_id).filter(UserSession.session_id == sid).first()
        if u:
            return api_200(u.to_dict())
        else:
            return api_403()
    elif has_url_parameter('username'):
        un = get_url_parameter('username')
        u = User.query.filter_by(username = un).first()
        if u:
            return api_200(u.to_dict())
        else:
            return api_404()
    else:
        return api_406('Required parameters: session_id or username')
    
@app.route('/session/users/<int:user_id>', methods=['GET'])
def session_user_by_user_id(user_id):
    uid = get_url_parameter('session_id')
    u = User.query.filter_by(id = uid)
    if u:
        return api_200(u.to_dict())
    else:
        return api_404('Invalid user_id')

### Error handlers ###
        
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

### Other ###

if __name__ == '__main__':
    protocol, host, port = settings.backends['session'].split(':')
    app.run(host = host[2:], port = int(port))