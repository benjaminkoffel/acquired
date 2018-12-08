#!/usr/bin/env python3
import argparse
import json
import logging
import random
import re
import string
import time
from Cryptodome.PublicKey import RSA
import flask
import flask.logging
import jwt
import yaml

app = flask.Flask(__name__)
config = {}
hosts = {}
re_bearer = re.compile('^Bearer (.*)')
tasks = []

def identifier():
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(10))

def configure_logger(level):
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers if gunicorn_logger.handlers else [flask.logging.default_handler]
    app.logger.setLevel(level)

def load_config(path):
    config.clear()
    with open(path, 'r') as f:
        for k, v in yaml.load(f).items():
            config[k] = v

def extract_bearer(header):
    for token in re_bearer.findall(header):
        return token

def issue_token(pem, kid, exp, sub):
    id = identifier()
    timestamp = int(time.time())
    headers = {
        'kid': kid
    }
    claims = {
        'jti': id,
        'iat': timestamp,
        'exp': timestamp + exp,
        'sub': sub
    }
    return jwt.encode(claims, pem, 'RS256', headers).decode('utf-8')

def verify_token(jwks, token):
    headers = jwt.get_unverified_header(token)
    if 'kid' in headers:
        for k in jwks['keys']:
            if k['kid'] == headers['kid']:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
                return jwt.decode(token, key, algorithms='RS256')

@app.route('/schedule/<action>/')
@app.route('/schedule/<action>/<path:path>')
def schedule(action, path=''):
    if extract_bearer(flask.request.headers.get('Authorization')) != config['admin']:
        flask.abort(401)
    if action not in ['memory']:
        flask.abort(400)
    task = {
        'id': identifier(),
        'action': action,
        'path': f'/{path}',
        'expires': int(time.time()) + 600,
    }
    tasks.append(task)
    return json.dumps(task, indent=4)

@app.route('/enrol/<account>/<instance>')
def enrol(account, instance):
    if extract_bearer(flask.request.headers.get('Authorization')) != config['link']:
        flask.abort(401)
    expires = 86400 * 365
    token = issue_token(
        pem=config['pem'], 
        kid=config['jwks']['keys'][0]['kid'], 
        exp=expires, 
        sub=f'/{account}/{instance}')
    return json.dumps({
        'access_token': token,
        'expires_in': expires
    }, indent=4)

@app.route('/poll')
def poll():
    token = extract_bearer(flask.request.headers.get('Authorization'))
    claims = verify_token(config['jwks'], token)
    if not claims:
        flask.abort(401)
    return json.dumps({
        'tasks': [t for t in tasks if claims['sub'].startswith(t['path'])]
    }, indent=4)

@app.route('/task/<task>/<state>')
def done(task, state):
    token = extract_bearer(flask.request.headers.get('Authorization'))
    claims = verify_token(config['jwks'], token)
    if not claims:
        flask.abort(401)
    if state not in ['started', 'completed', 'failed']:
        flask.abort(400)
    return ''

if __name__=='__main__':
    configure_logger(logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=4444)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    ssl_context = (args.cert, args.key) if args.cert and args.key else None
    load_config(args.config)
    app.run(host='0.0.0.0', port=args.port, ssl_context=ssl_context)
