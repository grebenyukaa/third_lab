import settings
from models import *
from common import *

from flask import *

import requests as pyrequests
import json as pyjson

app = Flask(__name__)
app.config.update(dict(\
    SQLALCHEMY_DATABASE_URI=settings.DATABASE_PATH),\
    DEBUG=True\
)

@app.route('/logic/register', methods=['POST'])
def logic_register():
    if has_url_parameter('username') and has_url_parameter('password') and has_url_parameter('mail') and has_url_parameter('phone'):
        uname = get_url_parameter('username')
        pw = get_url_parameter('password')
        mail = get_url_parameter('mail')
        phone = get_url_parameter('phone')
        
        return from_pyresponce(pyrequests.post(\
            api_func(settings.backends['session'], 'session/register'),\
            params = {'username': uname, 'password': pw, 'mail': mail, 'phone': phone}\
        ))
    else:
        return api_406('Required parameters: username, password, mail, phone')

@app.route('/logic/login', methods=['GET'])
def logic_login():
    un = get_url_parameter('username')
    pw = get_url_parameter('password')
    
    return from_pyresponce(pyrequests.get(\
            api_func(settings.backends['session'], 'session/login'),\
            params = {'username': un, 'password': pw}\
    ))

@app.route('/logic/logout', methods=['POST'])
def logic_logout():
    sid = get_url_parameter('session_id')
    return from_pyresponce(pyrequests.post(\
            api_func(settings.backends['session'], 'session/logout'),\
            params = {'session_id': sid}\
    ))

def logic_validate():
    sid = get_url_parameter('session_id')
    return pyrequests.get(api_func(settings.backends['session'], 'session/check'), params = {'session_id': sid})

@app.route('/logic/validate', methods=['GET'])
def logic_validate_method():
    sid = get_url_parameter('session_id')
    return from_pyresponce(logic_validate())

@app.route('/logic/users', methods=['GET'])
def logic_users():
    resp = logic_validate()
    if resp.status_code == 200:
        sid = get_url_parameter('session_id')
        return from_pyresponce(pyrequests.get(api_func(settings.backends['session'], 'session/users'), params = {'session_id': sid}))
    else:
        return api_401()

@app.route('/logic/posts', methods=['GET'])
def logic_posts_get():
    return from_pyresponce(pyrequests.get(api_func(settings.backends['posts'], 'posts')))
  
@app.route('/logic/posts', methods=['POST'])
def logic_posts_post():
    resp = logic_validate()
    if resp.status_code == 200:
        uid = resp.json()['user_id']
        if has_url_parameter('text') and has_url_parameter('caption'):
            text = get_url_parameter('text')
            cap = get_url_parameter('caption')
            return from_pyresponce(pyrequests.post(\
                api_func(settings.backends['posts'], 'posts'),\
                params = {'user_id': uid},\
                data = pyjson.dumps({'text': text, 'caption': cap}),\
                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}\
            ))
        else:
            return api_406('Required parameters: text, caption')
    else:
        return api_401()
  
@app.route('/logic/posts/<int:post_id>', methods=['GET', 'PUT', 'DELETE'])
def logic_post(post_id):
    if request.method == 'GET':
        return from_pyresponce(pyrequests.get(api_func(settings.backends['posts'], 'posts/{0}'.format(post_id))))
    else:
        resp = logic_validate()
        if resp.status_code == 200:
            uid = resp.json()['user_id']
            pr = pyrequests.get(api_func(settings.backends['posts'], 'posts/{0}'.format(post_id)))
            if pr.status_code != 404:
                if (pr.json()['author_id'] == uid):
                    if request.method == 'PUT':
                        if has_url_parameter('text') and has_url_parameter('caption'):
                            text = get_url_parameter('text')
                            cap = get_url_parameter('caption')
                            return from_pyresponce(pyrequests.put(\
                                api_func(settings.backends['posts'], 'posts/{0}'.format(post_id)),\
                                data = pyjson.dumps({'text': text, 'caption': cap}),\
                                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}\
                            ))
                        else:
                            return api_406('Required parameters: text, caption')
                    else:
                        return from_pyresponce(pyrequests.delete(api_func(settings.backends['posts'], 'posts/{0}'.format(post_id))))
                else:
                    return api_403()
            else:
                return api_404()
        else:
            return api_401()

@app.route('/logic/comments', methods=['GET'])
def logic_comments_get():
    if has_url_parameter('post_id') and has_url_parameter('limit') and has_url_parameter('res_per_page') and has_url_parameter('offset'):
        pid = get_url_parameter('post_id')
        rpp = get_url_parameter('res_per_page')
        cnt = get_url_parameter('limit')
        offset = get_url_parameter('offset')
        author_un = get_url_parameter('author_un')
    comments = None
    if author_un:
        userr = pyrequests.get(api_func(settings.backends['session'], '/session/users'), params = {'username': author_un})
        if userr.status_code != 404:
            user = userr.json()
            comments = pyrequests.get(\
                api_func(settings.backends['comments'], 'comments'),\
                params = {'post_id': pid, 'res_per_page': rpp, 'limit': cnt, 'offset': offset, 'user_id': user['user_id']}\
            )
        else:
            return api_404()
    else:
        comments = pyrequests.get(\
            api_func(settings.backends['comments'], 'comments'),\
            params = {'post_id': pid, 'res_per_page': rpp, 'limit': cnt, 'offset': offset}\
        )
    return api_200(comments.json())

@app.route('/logic/comments', methods=['POST'])
def logic_comments_post():
    resp = logic_validate()
    if resp.status_code == 200:
        uid = resp.json()['user_id']
        if has_url_parameter('text') and has_url_parameter('post_id'):
            pid = get_url_parameter('post_id')
            text = get_url_parameter('text')
            return from_pyresponce(pyrequests.post(\
                api_func(settings.backends['comments'], 'comments'),\
                params = {'user_id': uid, 'post_id': pid},\
                data = pyjson.dumps({'text': text}),\
                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}\
            ))
        else:
            return api_406('Required parameters: text, post_id')
    else:
        return api_401()
              
@app.route('/logic/comments/<int:comment_id>', methods=['GET', 'PUT', 'DELETE'])
def logic_comment(comment_id):
    if request.method == 'GET':
        return from_pyresponce(pyrequests.get(api_func(settings.backends['comments'], 'comments/{0}'.format(comment_id))))
    else:
        resp = logic_validate()
        if resp.status_code == 200:
            uid = resp.json()['user_id']
            cr = pyrequests.get(api_func(settings.backends['comments'], 'comments/{0}'.format(comment_id)))
            if cr.status_code != 404:
                if cr.json()['author_id'] == uid:
                    if request.method == 'PUT':
                        if has_url_parameter('text'):
                            text = get_url_parameter('text')
                            return from_pyresponce(pyrequests.put(\
                                api_func(settings.backends['comments'], 'comments/{0}'.format(comment_id)),\
                                data = pyjson.dumps({'text': text}),\
                                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}\
                            ))
                        else:
                            return api_406('Required parameters: text')
                    else:
                        return from_pyresponce(pyrequests.delete(api_func(settings.backends['comments'], 'comments/{0}'.format(comment_id))))
                else:
                    return api_403()
            else:
                return api_404()
        else:
            return api_401()

### Special query ###

@app.route('/logic/complex_query', methods=['GET'])
def logic_complex_query():
    if has_url_parameter('user_id'):
        uid = get_url_parameter('user_id')
        postsr = pyrequests.get(api_func(settings.backends['posts'], 'posts'), params = {'user_id': uid})
        posts = postsr.json()['Posts']
        comments = []
        comr = pyrequests.get(\
            api_func(settings.backends['comments'], 'comments'),\
            data = pyjson.dumps({'post_ids': [p['id'] for p in posts]}),\
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}\
        )
        return from_pyresponce(comr)
    else:
        return api_406('Required parameters: user_id')

### Error handlers ###
 
def from_pyresponce(pyresp):
   if pyresp.status_code == 200:
       return api_200(pyresp.json())
   elif pyresp.status_code == 406:
       return api_406(pyresp.json()['error'])
   elif pyresp.status_code == 404:
       return api_404(pyresp.json()['error'])
   elif pyresp.status_code == 403:
       return api_403(pyresp.json()['error'])
   elif pyresp.status_code == 401:
       return api_401(pyresp.json()['error'])
   else:
       return pyresp
       
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
    protocol, host, port = settings.backends['logic'].split(':')
    app.run(host = host[2:], port = int(port))