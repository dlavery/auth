import re
import jwt
import base64
from datetime import datetime

def validate_client(func):
    def validate(obj):
        if not obj.db:
            raise ClientException("client needs a database")
        elif not obj.name:
            raise ClientException("client needs a name")
        elif not obj.cert:
            raise ClientException("client needs a certificate")
        elif not obj.ref:
            raise ClientException("client needs a reference")
        elif not obj.redirectURL:
            raise ClientException("client needs a redirection URL")
        elif not obj.prvkey:
            raise ClientException("private key missing")
        else:
            return func(obj)

    return validate

class Client:

    def __init__(self):
        self.db = None
        self.name = ''
        self.cert = ''
        self.ref = ''
        self.redirectURL = ''
        self.prvkey = ''

    def setup(self):
        self.db.clients.create_index([('ref', 1)], unique=True) # index ascending

    @validate_client
    def create(self):
        self.setup()
        doc = {
            "name": self.name,
            "cert": self.cert,
            "ref": self.ref,
            "redirectURL": self.redirectURL,
            "blocked": False,
            "created": str(datetime.utcnow())
            }
        # create access token valid for 365 days
        token = jwt.encode({'name': doc['name'], 'reference': doc['ref'], 'exp': (datetime.utcnow().timestamp() + 31536000)}, self.prvkey, algorithm='RS256')
        base64token = str(base64.standard_b64encode(token), 'ascii')
        doc['jwt'] = base64token
        clientid = self.db.clients.insert(doc)
        return str(clientid)

    def readbyreference(self, reference):
        return self.db.clients.find_one({'ref': reference})

class ClientException(Exception):
    pass
