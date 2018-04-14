import os
from functools import wraps
from flask import Flask, render_template
from flask import request, escape
from authverify.verify import verify_user

app = Flask(__name__)

def check_authorisation(required_authorisation=None):
    def decorator(func):
        @wraps(func)
        def check_auth(*args, **kwargs):
            if not verify_user(required_authorisation, request.headers, request.data, request.form):
                return 'Not Authorised', 403
            return func(*args, **kwargs)
        return check_auth
    return decorator

@app.route('/', methods=['GET'])
def root():
    data = {
        'clientToken': 'ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUo5LmV5SnVZVzFsSWpvaVZHVnpkQ0JEYkdsbGJuUWlMQ0p5WldabGNtVnVZMlVpT2lKMFpYTjBNREVpTENKbGVIQWlPakUxTlRNNE56YzVNakF1TURVNU5EUTJmUS4xVVRDd0gxMk1yYk1OTF9sWjVoT01WTWoyOHlpXzlVYVczcUtEWG5qOUJRdVlQYUVnMUVzQU9KaDBDNGM5RTdpRmRCYUNEdXdFMWQzWXlEXzlNdnFPOERRU29uVy1seWluZTBZd190cFZEc3EyVUE1UHQ0aXdRR1pqSFdVZDhNQXpESmRaekIwQWxUN0xucEp0T0wtU0QtemZHRW5aVXhkMW5MemRFUWNoR3pWa1JIS01rLUxhS2hGbm1kLVlscFIyaC1VbEVfbHhFTTJCOTU2aVJCZ05ScjNuWTdMOXd4LTlTWW5yN2VnajlUNnlRVFdSUkFaOE9CLW85V2hlLXExUTlja0VqUUJxNGtxX0x0b1RfVjFsOFEya2JWeGxIWnE5Ylo2alh0WUNaWlR6OVp1d2tDSWR5bHlpLXd4Q3V1dHVZZ0hrY2F0WlRKRU1oeGZzeHVBY0E=',
        'postURL': 'http://localhost:5001/authclient'
    }
    return render_template('testapp.html', data=data)

@app.route('/testresult', methods=['GET', 'POST'])
@check_authorisation('test_page')
def testresult():
    return 'Congratulations! You have successfully authenticated and are authorised to see this page.'

if __name__ == "__main__":
    app.run(port=5999, debug=True)
