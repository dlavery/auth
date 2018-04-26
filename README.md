# Auth
## Summary
An authentication/authorisation suite for use in any enterprise grade application.

## Authentication/Authorisation Flow
![Sequence diagram](AuthFlow.png)
Components of this repo are:
* auth-api - contains the Authorisation Service shown
* authverify - an authorisation module that can be used within a Resource Service to control access to resources
* root directory - contains a test version of a Requesting Service (which is also a Resource Service)

## Dependencies
Python modules:
- cryptography
- Flask
- Flask-PyMongo
- PyCryptodome
- PyJWT
- PyMongo
- base64

## Setup
### PKI
Create a public/private key pair for the Authorisation Service using OpenSSL, entering a passphrase (in this repo we have used 'password123' for all passphrases):

`openssl genrsa -des3 -out auth.pem 2048`

Export the public key:

`openssl rsa -in auth.pem -outform PEM -pubout -out auth_public.pem`

Edit the auth-api.cfg config file (PKI section) with the key details.

### Example Requesting/Resource Service
Create a client public/private key for the Resource Service as shown above. The client public key (in the example it's the certfile clientencrypt_public.pem) is passed to the Authorisation Service so that service can encrypt user access tokens. Create the client Requesting Service in the Authorisation Service using the script loadclient.py passing the client name, certfile location, client reference number and the URL for redirection upon authentication. This will create a token for the client that the client will use to identify itself when requesting user authentication. This token should be passed to the Requesting Service.

Run the script loaduser.py to create user credentials for the client Requesting Service. 
