import settings
from models import db_session, Post
from common import *

from flask import *

import requests as pyrequests
import hashlib

app = Flask(__name__)
app.config.update(dict(\
    SQLALCHEMY_DATABASE_URI=settings.DATABASE_PATH),\
    DEBUG=True\
)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        uname = get_url_parameter('username')
        pw = hashlib.sha256(get_url_parameter('password').encode('utf-8')).hexdigest()
        mail = get_url_parameter('mail')
        phone = get_url_parameter('phone')
        
        resp = pyrequests.post(\
            api_func(settings.backends['logic'], 'logic/register'),\
            params = {'username': uname, 'password': pw, 'mail': mail, 'phone': phone}\
        )
        if resp.status_code == 200:
            return redirect(url_for('login'))
        else:
            error = resp.json()['error']
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        un = get_url_parameter('username')
        pw = hashlib.sha256(get_url_parameter('password').encode('utf-8')).hexdigest()
        
        resp = pyrequests.get(api_func(settings.backends['logic'], 'logic/login'), params = {'username': un, 'password': pw})
        if resp.status_code == 200:
            cliresp = redirect(url_for('root'))
            cliresp.set_cookie('session_id', resp.json()['session_id'])
            return cliresp
        else:
            error = resp.json()['error']
    else:
        if 'session_id' in request.cookies:
            sid = request.cookies.get('session_id')
            resp = pyrequests.get(api_func(settings.backends['logic'], 'logic/validate'), params = { 'session_id': sid })
            if resp.status_code == 200:
                return redirect(url_for('root'))
    return render_template('login.html', error=error)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        sid = None
        if has_url_parameter('session_id'):
            sid = get_url_parameter('session_id')
        else:
            sid = request.cookies.get('session_id')
        
        if sid:
            resp = pyrequests.post(api_func(settings.backends['logic'], 'logic/logout'), params = {'session_id': sid})
            if resp.status_code == 200:
                cliresp = redirect(url_for('root'))
                cliresp.set_cookie('session_id', '')
                return cliresp
        return redirect(url_for('login'))
    return render_template('logout.html')

@app.route('/me', methods=['GET'])
def get_me():
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        resp = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if resp.status_code == 200:
            cliresp = api_200(resp.json())
            return cliresp
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
def root():
    postsr = pyrequests.get(api_func(settings.backends['logic'], 'logic/posts'))
    return render_template('main.html', posts = postsr.json()['Posts'])
  
@app.route('/posts', methods=['POST'])
def post_posts():
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        error = None
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        
        if userr.status_code == 200:
            cap = get_url_parameter('caption')
            text = get_url_parameter('text')
            
            if cap:
                postidr = pyrequests.post(\
                    api_func(settings.backends['logic'], 'logic/posts'),\
                    params = {'user_id': userr.json()['id'], 'session_id': sid, 'text': text, 'caption': cap}\
                )
                return redirect(url_for('root'))
            else:
                error = 'Caption required'
                return render_template('new_post.html', text = text, caption = cap, error = error)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    postr = pyrequests.get(api_func(settings.backends['logic'], 'logic/posts/{0}'.format(post_id)))
    if postr.status_code == 200:
        commentsr = pyrequests.get(\
            api_func(settings.backends['logic'], 'logic/comments'),\
            params={'post_id': post_id, 'limit': 100, 'res_per_page': 100, 'offset': 0}\
        )
        if commentsr.status_code == 200:
            return render_template('show_post.html', post = postr.json(), comments = commentsr.json()['Comments'])
        else:
            return from_pyresponce(commentsr)
    else:
        return from_pyresponce(postr)

@app.route('/posts/<int:post_id>/edit', methods=['POST'])
def put_post(post_id):
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        error = None
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            postr = pyrequests.get(api_func(settings.backends['logic'], 'logic/posts/{0}'.format(post_id)))
            if postr.status_code == 200:
                post = postr.json()
                cap = post['caption']
                text = post['text']
                finished = get_url_parameter('editing_finished')
                if finished:
                    cap = get_url_parameter('caption')
                    text = get_url_parameter('text')
                    postidr = pyrequests.put(\
                        api_func(settings.backends['logic'], 'logic/posts/{0}'.format(post_id)),\
                        params = {'user_id': user['id'], 'session_id': sid, 'text': text, 'caption': cap}\
                    )
                    if postidr.status_code == 200:
                        return redirect(url_for('root'))
                    else:
                        return from_pyresponce(postidr)
                else:
                    return render_template('edit_post.html', text = text, caption = cap, error = error, post_id = post_id)
            else:
                return from_pyresponce(postr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        error = None
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            postr = pyrequests.get(api_func(settings.backends['logic'], 'logic/posts/{0}'.format(post_id)))
            if postr.status_code == 200:
                post = postr.json()
                resp = pyrequests.delete(\
                    api_func(settings.backends['logic'], 'logic/posts/{0}'.format(post_id)),\
                    params = {'user_id': user['id'], 'session_id': sid}\
                )
                if resp.status_code == 200:
                    return redirect(url_for('root'))
                else:
                    return from_pyresponce(resp)
            else:
                return from_pyresponce(postr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/comments', methods=['POST'])
def post_comments():
    if 'session_id' in request.cookies:
        error = None
        sid = request.cookies.get('session_id')
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            pid = get_url_parameter('post_id')
            postr = pyrequests.get(api_func(settings.backends['logic'], 'logic/posts/{0}'.format(pid)))
            if postr.status_code == 200:
                post = postr.json()
                text = get_url_parameter('text')
                
                if text:
                    commentidr = pyrequests.post(\
                        api_func(settings.backends['logic'], 'logic/comments'),\
                        params = {'user_id': user['id'], 'post_id': pid, 'session_id': sid, 'text': text}\
                    )
                    return redirect(url_for('get_post', post_id = pid))
                else:
                    error = 'Text required'
                    return render_template('new_comment.html', error = error, text = text, post = post)
            else:
                return from_pyresponce(postr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/comments/<int:comment_id>/edit', methods=['POST'])
def put_comment(comment_id):
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        error = None
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            comr = pyrequests.get(api_func(settings.backends['logic'], 'logic/comments/{0}'.format(comment_id)))
            if comr.status_code == 200:
                comment = comr.json()
                text = comment['text']
                post_id = get_url_parameter('post_id')
                finished = get_url_parameter('editing_finished')
                if finished:
                    text = get_url_parameter('text')
                    comidr = pyrequests.put(\
                        api_func(settings.backends['logic'], 'logic/comments/{0}'.format(comment_id)),\
                        params = {'user_id': user['id'], 'session_id': sid, 'text': text}\
                    )
                    if comidr.status_code == 200:
                        return redirect(url_for('get_post', post_id = post_id))
                    else:
                        return from_pyresponce(comidr)
                else:
                    return render_template('edit_comment.html', text = text, error = error, comment_id = comment_id, post_id = post_id)
            else:
                return from_pyresponce(comr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        error = None
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            comr = pyrequests.get(api_func(settings.backends['logic'], 'logic/comments/{0}'.format(comment_id)))
            if comr.status_code == 200:
                post_id = get_url_parameter('post_id')
                comment = comr.json()
                resp = pyrequests.delete(\
                    api_func(settings.backends['logic'], 'logic/comments/{0}'.format(comment_id)),\
                    params = {'user_id': user['id'], 'session_id': sid}\
                )
                if resp.status_code == 200:
                    return redirect(url_for('get_post', post_id = post_id))
                else:
                    return from_pyresponce(resp)
            else:
                return from_pyresponce(comr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/complex_query', methods=['GET'])
def complex_query():
    if 'session_id' in request.cookies:
        sid = request.cookies.get('session_id')
        userr = pyrequests.get(api_func(settings.backends['logic'], 'logic/users'), params = {'session_id': sid})
        if userr.status_code == 200:
            user = userr.json()
            comr = pyrequests.get(\
                api_func(settings.backends['logic'], 'logic/complex_query'),\
                params = {'user_id': user['id']}\
            )
            return from_pyresponce(comr)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))
    
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
       return response_builder({'errc': pyresp.status_code}, pyresp.status_code)
        
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
    protocol, host, port = settings.backends['frontend'].split(':')
    app.run(host = host[2:], port = int(port))