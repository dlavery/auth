from Crypto.PublicKey import RSA
import jwt

prvkey = RSA.import_key(open('auth.pem').read(), passphrase='password').exportKey()
pubkey = bytes(open('auth_public.pem').read(), 'UTF-8')

encoded = jwt.encode({'some': 'payload'}, prvkey, algorithm='RS256')
decoded = jwt.decode(encoded, pubkey, algorithms='RS256')
print(decoded)
