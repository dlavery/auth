from flask import Flask
from flask_pymongo import PyMongo
import configparser
import logging

# Value mapping
LOG_LEVELS = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARN': logging.DEBUG, 'ERROR': logging.ERROR}

# Create application
app = Flask(__name__)

# Read external config
config = configparser.ConfigParser()
config.read('auth-api.cfg')
app.config['MONGO_DBNAME'] = config['DATABASE']['dbName']
app.config['MONGO_URI'] = config['DATABASE']['dbURI']
logfile = config['LOGGING']['logFile']
loglevel = LOG_LEVELS[config['LOGGING']['logLevel']]
app.config['SERVER_NAME'] = config['APPLICATION']['servername']
app.config['DEBUG'] = config['APPLICATION']['debug']

# Set up logging
fh = logging.FileHandler(logfile, mode='a', encoding='utf8', delay=False)
fmt = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(lineno)d %(message)s')
fh.setFormatter(fmt)
app.logger.addHandler(fh)
app.logger.setLevel(loglevel)

# Set up database
mongo = PyMongo(app)
