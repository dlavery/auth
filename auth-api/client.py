import pymongo
import re
from pymongo import MongoClient
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
        else:
            return func(obj)

    return validate

class Client:

    def __init__(self):
        self.name = ''
        self.cert = ''
        self.ref = ''

    def setup(self):
        self.db.clients.create_index([('ref', 1)], unique=True) # index ascending

    @validate_client
    def create(self):
        self.setup()
        doc = {
            "name": self.name,
            "cert": self.cert,
            "ref": self.ref,
            "created": str(datetime.utcnow())
            }
        clientid = self.db.clients.insert(doc)
        return str(clientid)

    def read(self):
        pass

class ClientException(Exception):
    pass
