import settings
from models import *
from common import *

from flask import *

app = Flask(__name__)
app.config.update(dict(\
    SQLALCHEMY_DATABASE_URI=settings.DATABASE_PATH),\
    DEBUG=True\
)

@app.route('/posts', methods=['GET'])
def get_posts():
    posts = None
    if has_url_parameter('user_id'):
        uid = get_url_parameter('user_id')
        posts = db_session.query(Post, User)\
            .filter(User.id == Post.author_id)\
            .filter(Post.author_id == uid)\
            .all()
    else:
        posts = db_session.query(Post, User)\
            .filter(User.id == Post.author_id)\
            .all()
        
    resp = []
    for p, u in posts:
        r = p.to_dict_short()
        r.update({'username': u.username})
        resp += [r]
    return api_200({'Posts' : resp})

@app.route('/posts', methods=['POST'])
def post_post():
    user_id = get_url_parameter('user_id')
    text = get_url_parameter('text')
    caption = get_url_parameter('caption')
    p = Post(user_id, caption, text)
    db_session.add(p)
    db_session.commit()
    return api_200({'post_id': p.id})

@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    p = Post.query.filter_by(id = post_id).first()
    return api_200(p.to_dict()) if p else api_404() 

@app.route('/posts/<int:post_id>', methods=['PUT'])
def put_post(post_id):
    p = Post.query.filter_by(id = post_id).first()
    if p:
        text = get_url_parameter('text')
        caption = get_url_parameter('caption')
        p.text = text
        p.caption = caption
        db_session.commit()
        return api_200()
    else:
        return api_404()

@app.route('/posts/<int:post_id>', methods=['DELETE'])
def del_post(post_id):
    p = Post.query.filter_by(id = post_id).first()
    if p:
        db_session.delete(p)
        db_session.commit()
        return api_200()
    else:
        return api_404()

### Error handlers ###

@app.errorhandler(404)
def api_404(msg = 'Not found'):
    return response_builder({'error': msg}, 404)

@app.errorhandler(200)
def api_200(data = {}):
    return response_builder(data, 200)

### Other ###

if __name__ == '__main__':
    protocol, host, port = settings.backends['posts'].split(':')
    app.run(host = host[2:], port = int(port))