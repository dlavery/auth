import os
import json
import jwt
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

class Authorise:

    def __init__(self, keyfilelocation='', authpublickeyfile='', privatekeyfile='', privatekeypassphrase=''):
        self.keylocation = keyfilelocation
        self.authpublickeyfile = authpublickeyfile
        self.privatekeyfile = privatekeyfile
        self.privatekeypassphrase = privatekeypassphrase
        try:
            self.authpublickeyfile = os.path.join(self.keylocation, self.authpublickeyfile)
            self.privatekeyfile = os.path.join(self.keylocation, self.privatekeyfile)
        except Exception as err:
            pass

    def authorise_user(self, required_authorisation, httpheaders, requestdata=None, formdata=None):
        if httpheaders:
            if 'X-Client-Token' in httpheaders:
                return self.check_token(httpheaders['X-Client-Token'], required_authorisation)
        if requestdata:
            try:
                data = json.loads(requestdata)
                if 'clientToken' in data:
                    return self.check_token(data['clientToken'], required_authorisation)
            except Exception as err:
                pass
        if formdata and 'clientToken' in formdata:
            return self.check_token(formdata['clientToken'], required_authorisation)
        return False

    def check_token(self, token, authorisation):
        try:
            # decrypt jwt w/ client private key
            b = base64.standard_b64decode(bytes(token, 'ascii'))
            private_key = RSA.import_key(open(self.privatekeyfile).read(), passphrase=self.privatekeypassphrase)
            x = private_key.size_in_bytes()
            enc_session_key = b[:x]
            nonce = b[x: x+16]
            x = x+16
            tag = b[x: x+16]
            x = x+16
            ciphertext = b[x:]
            # decrypt the session key with the public RSA key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            # decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            decrypted_payload = cipher_aes.decrypt_and_verify(ciphertext, tag)
            # decode jwt w/ auth public key
            pubkey = RSA.import_key(open(self.authpublickeyfile).read()).exportKey()
            decoded = jwt.decode(decrypted_payload, pubkey, algorithms='RS256')
            # return authorisation decision
            if 'functions' in decoded and authorisation in decoded['functions']:
                return True
        except Exception as err:
            pass
        return False
