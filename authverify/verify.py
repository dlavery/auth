import json

def verify_user(required_authorisation, httpheaders, requestdata=None, formdata=None):
    if httpheaders:
        if 'X-Client-Token' in httpheaders:
            return check_token(httpheaders['X-Client-Token'], required_authorisation)
    if requestdata:
        try:
            data = json.loads(requestdata)
            if 'clientToken' in data:
                return check_token(data['clientToken'], required_authorisation)
        except Exception as err:
            pass
    if formdata and 'clientToken' in formdata:
        return check_token(formdata['clientToken'], required_authorisation)
    return False

def check_token(token, authorisation):
    print(authorisation)
    print(token)
    return True
