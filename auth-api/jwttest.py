from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import jwt
import base64
import json

dic = {'some': 'payload', 'list': ['a', 'b']}
print("jwt: " + str(dic))

# client public key for encryption
client_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUFHGNkIs9M3geXfLQ5e
Z41seJqXNzY3CI6ebUCAEMtIRBB1XRJSj2fAEVho44FMNxl1gcVpJvyJrd73ziUt
FQ/Ff6Nfcik+NeQCeOKmq+naTmuwSdCV0ST4bwclT7XHzqpiYNXI/e2ajnTd5Yo/
5a0BXTMKKhHDjgShxzxdqSGwbE1v6wQhKRfw/wXSsgD8Ni9a61+NMNU//UKcN1eK
tl+1YKtIBAO5V/CoCe1mWMd1E+AZvWpwrLIjGLAstV2DyXLsU65YYGuFz3odrjDI
L+sA2DPBDj0H8Bn0DpmAnMxq9rqn7KCtsth/ORMmZ0ccwc3W0h4sMuW5jRtIXAoW
CQIDAQAB
-----END PUBLIC KEY-----'''

# encode jwt w/ auth private key
prvkey = RSA.import_key(open('authsign.pem').read(), passphrase='password123').exportKey()
encoded = jwt.encode(dic, prvkey, algorithm='RS256')

# encrypt jwt w/ client public key
recipient_key = RSA.import_key(client_key)
session_key = get_random_bytes(16)
# encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
encrypted_session_key = cipher_rsa.encrypt(session_key)
# encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(encoded)
encrypted_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
data = str(base64.standard_b64encode(encrypted_payload), 'ascii')

# send data
j = json.dumps({'payload': data})
print(j)

# receive data
data = json.loads(j)

# decrypt jwt w/ client private key
b = base64.standard_b64decode(bytes(data['payload'], 'ascii'))
private_key = RSA.import_key(open("clientencrypt.pem").read(), passphrase='password123')
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
pubkey = RSA.import_key(open('authsign_public.pem').read()).exportKey()
decoded = jwt.decode(decrypted_payload, pubkey, algorithms='RS256')
print("Equivalient: " + str(dic == decoded))
print("Decoded: " + str(decoded))
