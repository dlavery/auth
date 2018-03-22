import argparse
import configparser
import pymongo
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

def loadclient(name, certfile, ref):
    with open(certfile) as f:
        clientcert = f.read()
    config = configparser.ConfigParser()
    config.read('auth-api.cfg')
    client = MongoClient(config['DATABASE']['dbURI'])
    db = client[config['DATABASE']['dbName']]
    INDEX_ASCENDING = 1
    INDEX_DESCENDING = -1
    db.clients.create_index([('ref', 1)], unique=True)
    doc = {
        "name": name,
        "cert": clientcert,
        "ref": ref
    }
    task_id = db.clients.insert(doc)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('clientname', help='The name of the client')
    parser.add_argument('clientcert', help="The file containing the client's public certificate")
    parser.add_argument('clientref', help="Short reference number for client")
    args = parser.parse_args()
    try:
        loadclient(args.clientname, args.clientcert, args.clientref)
    except DuplicateKeyError as dup:
        print("Client reference %s already exists, please try again" % args.clientref)
    except Exception as err:
        print(str(err))
