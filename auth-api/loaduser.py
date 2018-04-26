import user
import re
import argparse
import configparser
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from user import User

def loaduser(clientref, name, uname, upass, recovery_email, functions):
    config = configparser.ConfigParser()
    config.read('auth-api.cfg')
    client = MongoClient(config['DATABASE']['dbURI'])
    db = client[config['DATABASE']['dbName']]
    u = User()
    u.db = db
    u.clientref = clientref
    u.name = name
    u.uname = uname
    u.upass = upass
    u.functions = functions
    u.recovery_email = recovery_email
    return u.create()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('clientref', help="The cliemt service reference")
    parser.add_argument('name', help="The name of the user")
    parser.add_argument('uname', help="The username of the user")
    parser.add_argument('upass', help="The user's password")
    parser.add_argument('email', help="An email address for password recovery")
    parser.add_argument('functions', help="A comma separated list of functions the user has access to")
    args = parser.parse_args()
    funcs = re.split(',\s*', args.functions)
    try:
        userid = loaduser(args.clientref, args.name, args.uname, args.upass, args.email, funcs)
        print("User %s created" % userid)
    except DuplicateKeyError as dup:
        print("User already exists, please try again")
    except Exception as err:
        print(str(err))
