import base64
import json
import jwt
from app import app
from app import mongo
from app import authpublickey
from app import authprivatekey
from flask import request, escape
from flask import jsonify
from flask import render_template
from flask import session
from client import Client
from user import User
from datetime import datetime

@app.route('/', methods=['GET'])
def hello():
    return jsonify({'greeting' : 'Hello, World'})

@app.route('/authclient', methods=['POST'])
def auth():
    if 'clientToken' not in request.form:
        return "Bad Request", 400
    clienttoken = request.form['clientToken']
    try:
        clienttoken = base64.standard_b64decode(bytes(clienttoken, 'ascii'))
        clienttoken = jwt.decode(clienttoken, authpublickey, algorithms='RS256')
    except Exception as err:
        app.logger.error(str(err))
        return "Invalid token", 400
    if 'exp' in clienttoken and clienttoken['exp'] < datetime.utcnow().timestamp():
        return "Token Expired", 403
    clientobj = False
    if 'reference' in clienttoken:
        clientobj = Client()
        clientobj.db = mongo.db
        doc = clientobj.readbyreference(clienttoken['reference'])
        if doc and 'blocked' in doc and doc['blocked'] == True:
            return "Blocked", 403
        elif not doc:
            clientobj = False
    if not clientobj:
        return "Forbidden", 403
    alertmessage = ''
    if ('uname' in request.form and 'upass' in request.form):
        if (not request.form['uname'] or not request.form['upass']):
            alertmessage = 'Please enter your username and password'
        else:
            u = User()
            u.db = mongo.db
            if not u.check_password(doc['ref'], request.form['uname'], request.form['upass']):
                alertmessage = 'Your username and password do not match our records'
            else:
                jwttoken = u.create_access_token(authprivatekey, doc['cert'])
                return render_template('redirect.html',
                    data={
                        'clientToken': jwttoken,
                        'redirectURL': doc['redirectURL']
                    })
    return render_template('login.html',
        data={
            'clientToken': request.form['clientToken'],
            'alertMessage': alertmessage
        })
