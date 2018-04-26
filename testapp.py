import os
from functools import wraps
from flask import Flask, render_template
from flask import request, escape, redirect, url_for
from authverify.authorise import Authorise

app = Flask(__name__)

def check_authorisation(required_authorisation=None):
    def decorator(func):
        @wraps(func)
        def check_auth(*args, **kwargs):
            auth = Authorise(
                keyfilelocation='',
                authpublickeyfile='authsign_public.pem',
                privatekeyfile='clientencrypt.pem',
                privatekeypassphrase='password123'
            )
            if not auth.authorise_user(required_authorisation, request.headers, request.data, request.form):
                #return redirect(url_for('root'), code=302)
                return 'Not Authorised', 403
            return func(*args, **kwargs)
        return check_auth
    return decorator

@app.route('/', methods=['GET'])
def root():
    data = {
        'clientToken': 'ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUo5LmV5SnVZVzFsSWpvaWRHVnpkREVpTENKeVpXWmxjbVZ1WTJVaU9pSjBaWE4wTVRJek5DSXNJbVY0Y0NJNk1UVTFOakkxT1RFMk1DNHdPREkwTXpWOS5DWWZOaF9pcC0wODhKWGFScjJ6VTBRSzFlZ1A3TUlYWnh5QnN1N2o3WWk5MHVRVFBxa0VadTR1ZUtJVGNHSXo0R090NHA1R3M2RlNPem4wU1k5M1pvSG84dk41U3BLanJIeHlHTTFtRTJMV1lYTnhHem1kSGZVTXc4YTFmNmg1NHBpWEJJWlVfc2dkSWdSOWpnb1EtUHdhc2xzdk82V2JZSkxOVS1GanVFdWY2endsZXRlb0w2ZEhCazhiNXA3V1hGRHh2NzQwcEVzU25oMXdtemE5Y2RobXpMVDRoZVhmYlpRLTlYUGlIdzloQVduRVpqZVdwOE84NnJzVUxoQ05fZDIzWHN4QmdkMElkWEx1QmJGTXJRU1hHckZtcVFNU3hXM29QVV91TU14ZFhuSlh0VFRycEtveFhpZ0p6RE5YN3Fsc0kwUjBzTHlvbHJLMXlabWZ5Nmc=',
        'postURL': 'http://localhost:5001/authclient'
    }
    return render_template('testapp.html', data=data)

@app.route('/testresult', methods=['GET', 'POST'])
@check_authorisation('test_page')
def testresult():
    # TODO: save the user access token in the session
    return 'Congratulations! You have successfully authenticated and are authorised to see this page.'

if __name__ == "__main__":
    app.run(port=5999, debug=True)
