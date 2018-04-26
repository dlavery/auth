import re
import jwt
import base64
import datetime
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def validate_user(func):
    def validate(obj):
        if not obj.db:
            raise UserException("user credentials need a database")
        elif not obj.clientref:
            raise UserException("user credentials need a client reference")
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
        self.db = None
        self.clientref = ''
        self.name = ''
        self.uname = ''
        self.upass = ''
        self.recovery_email = ''
        self.functions = []

    def setup(self):
        self.db.credentials.create_index([('clientref', 1), ('uname', 1)], unique=True, sparse=False)
        self.db.credentials.create_index([('clientref', 1), ('recovery_email', 1)], unique=True, sparse=False)

    @validate_user
    def create(self):
        self.setup()
        self.upass = str(self.hashit(self.upass))
        doc = {
            'clientref': self.clientref,
            'name': self.name,
            'uname': self.uname,
            'upass': self.upass,
            'recovery_email': self.recovery_email,
            'functions': self.functions,
            'created': str(datetime.datetime.utcnow())
        }
        task_id = self.db.credentials.insert(doc)
        return str(task_id)

    def hashit(self, s):
        hash_object = SHA256.new(data=bytes(s, 'utf-8'))
        return hash_object.digest()

    def read(self):
        pass

    def check_password(self, clientref, uname, upass):
        self.clientref = clientref
        self.uname = uname
        u = self.db.credentials.find_one({'clientref': self.clientref, 'uname': self.uname})
        if not u:
            self.uname = ''
            return False
        self.name = u['name']
        self.functions = u['functions']
        dig = str(self.hashit(upass))
        return (dig == u['upass'])

    def update(self):
        pass

    def delete(self):
        pass

    def create_access_token(self, privatekey, clientcert):
        if not self.uname:
            return ''
        # encode jwt w/ auth private key
        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        encoded = jwt.encode({'uname': self.uname, 'name': self.name, 'functions': self.functions, 'exp': exp}, privatekey, algorithm='RS256')
        # encrypt jwt w/ client public key
        recipient_key = RSA.import_key(clientcert)
        session_key = get_random_bytes(16)
        # encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        # encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(encoded)
        encrypted_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
        data = str(base64.standard_b64encode(encrypted_payload), 'ascii')
        return data

class UserException(Exception):
    pass
