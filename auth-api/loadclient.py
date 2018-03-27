import argparse
import configparser
import pymongo
import re
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from client import Client

def loadclient(name, certfile, ref):
    with open(certfile) as f:
        clientcert = f.read()
    config = configparser.ConfigParser()
    config.read('auth-api.cfg')
    mongoclient = MongoClient(config['DATABASE']['dbURI'])
    db = mongoclient[config['DATABASE']['dbName']]
    authclient = Client()
    authclient.db = db
    authclient.name = name
    authclient.cert = clientcert
    authclient.ref = ref
    return authclient.create()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('clientname', help='The name of the client')
    parser.add_argument('clientcert', help="The file containing the client's public certificate")
    parser.add_argument('clientref', help="Short reference number for client")
    args = parser.parse_args()
    try:
        clientid = loadclient(args.clientname, args.clientcert, args.clientref)
        print("Client %s created" % clientid)
    except DuplicateKeyError as dup:
        print("Client reference %s already exists, please try again" % args.clientref)
    except Exception as err:
        print(str(err))
