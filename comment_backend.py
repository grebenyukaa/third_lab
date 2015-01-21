import settings
from models import *
from common import *

from flask import *

app = Flask(__name__)
app.config.update(dict(\
    SQLALCHEMY_DATABASE_URI=settings.DATABASE_PATH),\
    DEBUG=True\
)

@app.route('/comments', methods=['GET'])
def get_comments():
    pid = get_url_parameter('post_id')
    rpp = get_url_parameter('res_per_page')
    cnt = get_url_parameter('limit')
    offset = get_url_parameter('offset')
    cs = None
    if has_url_parameter('user_id'):        
        uid = get_url_parameter('user_id')
        if offset and cnt:
            cs = Comment.query.filter_by(author_id = uid, post_id = pid).offset(offset).limit(cnt).all()
        else:
            cs = Comment.query.filter_by(author_id = uid, post_id = pid).all()
    else:
        if offset and cnt:
            cs = Comment.query.filter_by(post_id = pid).offset(offset).limit(cnt).all()
        else:
            cs = Comment.query.filter_by(post_id = pid).all()
    
    retv = []
    results_per_page = int(rpp) if rpp else None
    for i, c in enumerate(cs):
        crepr = c.to_dict()
        if results_per_page:
            page = int(i / results_per_page)
            crepr.update({'page': page})
        crepr.update({'username': User.query.filter_by(id = c.author_id).first().username})
        retv += [crepr]
    return api_200({'Comments': retv})

@app.route('/comments', methods=['POST'])
def post_comment():
    pid = get_url_parameter('post_id')
    uid = get_url_parameter('user_id')
    text = get_url_parameter('text')
    c = Comment(uid, pid, text)
    db_session.add(c)
    db_session.commit()
    return api_200({'comment_id': c.id})

@app.route('/comments/<int:comment_id>', methods=['GET'])
def get_comment(comment_id):
    c = Comment.query.filter_by(id = comment_id).first()
    return api_200(c.to_dict()) if c else api_404()

@app.route('/comments/<int:comment_id>', methods=['PUT'])
def put_comment(comment_id):
    text = get_url_parameter('text')
    c = Comment.query.filter_by(id = comment_id).first()
    if c:
        if not c.deleted:
            c.text = text
            db_session.commit()
            return api_200()
        else:
            return api_403('Comment was deleted')
    else:
        return api_404()

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def del_comment(comment_id):
    text = get_url_parameter('text')
    c = Comment.query.filter_by(id = comment_id).first()
    if c:
        c.delete()
        db_session.commit()
        return api_200()
    else:
        return api_404()

### Error handlers ###

@app.errorhandler(404)
def api_404(msg = 'Not found'):
    return response_builder({'error': msg}, 404)

@app.errorhandler(403)
def api_403(msg = 'Forbidden'):
    return response_builder({'error': msg}, 403)

@app.errorhandler(200)
def api_200(data = {}):
    return response_builder(data, 200)

### Other ###

if __name__ == '__main__':
    protocol, host, port = settings.backends['comments'].split(':')
    app.run(host = host[2:], port = int(port))