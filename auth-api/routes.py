from app import app
from flask import request, escape
from flask import jsonify

@app.route('/', methods=['GET'])
def hello():
  return jsonify({'greeting' : 'Hello, World'})
