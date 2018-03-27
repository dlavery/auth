import re
from datetime import date
from datetime import datetime
from Crypto.Hash import SHA256

def validate_user(func):
    def validate(obj):
        if not obj.db:
            raise UserException("user credentials need a database")
        elif not obj.name:
            raise UserException("user credentials need a name")
        elif not obj.uname:
            raise UserException("user credentials need a user name")
        elif not obj.upass:
            raise UserException("user credentials need a password")
        elif not re.match('^[A-Za-z0-9!@#$%]{8,16}$', obj.upass):
            raise UserException("password must be 8-16 characters long and should be a mix of upper and lowercase letters, numbers, and the special characters !@#$%")
        elif not re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", obj.recovery_email):
            raise UserException("invalid recovery email address")
        elif (not type(obj.functions) == list or obj.functions == []):
            raise UserException("user credentials need list of allowed functions")
        else:
            return func(obj)

    return validate

class User:

    def __init__(self):
        self.name = ''
        self.uname = ''
        self.upass = ''
        self.recovery_email = ''
        self.functions = []

    def setup(self):
        self.db.credentials.create_index([('uname', 1)], unique=True, sparse=False)
        self.db.credentials.create_index([('recovery_email', 1)], unique=True, sparse=False)

    @validate_user
    def create(self):
        self.setup()
        hash_object = SHA256.new(data=bytes(self.upass, 'utf-8'))
        dig = hash_object.digest()
        self.upass = str(dig)
        doc = {
            'name': self.name,
            'uname': self.uname,
            'upass': self.upass,
            'recovery_email': self.recovery_email,
            'functions': self.functions,
            'created': str(datetime.utcnow())
        }
        task_id = self.db.credentials.insert(doc)
        return str(task_id)

    def read(self):
        pass

    def update(self):
        pass

    def delete(self):
        pass

class UserException(Exception):
    pass
