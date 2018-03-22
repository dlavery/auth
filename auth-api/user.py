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
        elif (obj.recovery_email
        and not re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", obj.recovery_email)):
            raise UserException("invalid recovery email address")
        else:
            func(obj)

    return validate

class User:

    def __init__(self):
        self.name = ''
        self.uname = ''
        self.upass = ''
        self.recovery_SMS = ''
        self.recovery_email = ''

    def setup(self):
        self.db.credentials.create_index([('uname', 1)], unique=True, sparse=True)
        self.db.credentials.create_index([('recovery_email', 1)], unique=True, sparse=True)
        self.db.credentials.create_index([('recovery_SMS', 1)], unique=True, sparse=True)

    @validate_user
    def create(self):
        self.creds_coll = self.db.credentials
        attrs = {}
        attrs['name'] = self.name
        if (self.uname):
            attrs['uname'] = self.uname
        if self.upass:
            hash_object = SHA256.new(data=bytes(self.upass, 'utf-8'))
            dig = hash_object.digest()
            self.upass = str(dig)
            attrs['upass'] = self.upass
        if (self.recovery_SMS):
            attrs['recovery_SMS'] = self.recovery_SMS
        if (self.recovery_email):
            attrs['recovery_email'] = self.recovery_email
        attrs['created'] = str(datetime.utcnow())
        task_id = self.creds_coll.insert(attrs)
        return str(task_id)

    def read(self):
        pass

class UserException(Exception):
    pass
