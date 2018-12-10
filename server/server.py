#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import re
import string
import time
import uuid
import boto3
import flask
import flask.logging
import M2Crypto
import M2Crypto.SMIME
import yaml

app = flask.Flask(__name__)
config = {}
re_bearer = re.compile('^Bearer (.*)')
tasks = []

def snapshot_volumes(session, instance):
    client = session.client('ec2')
    volumes = client.describe_volumes(
        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance]}])
    for v in volumes['Volumes']:
        description = 'ACQUIRED INSTANCE {} VOLUME {}'.format(instance, v['VolumeId'])
        client.create_snapshot(
            VolumeId=v['VolumeId'], 
            Description=description)
    return [v['VolumeId'] for v in volumes['Volumes']]

def assume_role(account, role):
    client = boto3.client('sts')
    role = client.assume_role(
        RoleArn='arn:aws:iam::{}:role/{}'.format(account, role), 
        RoleSessionName='acquired', 
        DurationSeconds=900)
    return boto3.Session(
        aws_access_key_id=role['Credentials']['AccessKeyId'], 
        aws_secret_access_key=role['Credentials']['SecretAccessKey'],
        aws_session_token = role['Credentials']['SessionToken'])

def verify_token(certificate, token):
    document = base64.b64decode(token)
    smime = M2Crypto.SMIME.SMIME()
    stack = M2Crypto.X509.X509_Stack()
    stack.push(certificate)
    smime.set_x509_stack(stack)
    store = M2Crypto.X509.X509_Store()
    store.add_x509(certificate)
    smime.set_x509_store(store)
    p7bio = M2Crypto.BIO.MemoryBuffer(document)
    p7 = M2Crypto.SMIME.load_pkcs7_bio(p7bio)
    try:
        return json.loads(smime.verify(p7))
    except M2Crypto.SMIME.PKCS7_Error as e:
        pass

def extract_bearer(header):
    for token in re_bearer.findall(header):
        return token

@app.route('/health')
def health():
    return 'OK'

@app.route('/schedule/<action>/')
@app.route('/schedule/<action>/<path:path>')
def schedule(action, path=''):
    if extract_bearer(flask.request.headers.get('Authorization')) != config['key']:
        flask.abort(401)
    if action not in ['memory']:
        flask.abort(400)
    task = {
        'id': str(uuid.uuid4()).replace('-', ''),
        'action': action,
        'path': '/{}'.format(path),
        'expires': int(time.time()) + 600,
    }
    tasks.append(task)
    return json.dumps(task, indent=4)

@app.route('/poll')
def poll():
    token = extract_bearer(flask.request.headers.get('Authorization'))
    identity = verify_token(config['x509'], token)
    if not identity:
        flask.abort(401)
    sub = '/{}/{}'.format(identity['accountId'], identity['instanceId'])
    return json.dumps({
        'tasks': [t for t in tasks if sub.startswith(t['path'])]
    }, indent=4)

@app.route('/task/<task>/<state>')
def task(task, state):
    token = extract_bearer(flask.request.headers.get('Authorization'))
    identity = verify_token(config['x509'], token)
    if not identity:
        flask.abort(401)
    if not any(t for t in tasks if t['id'] == task):
        flask.abort(403)
    if state not in ['started', 'completed', 'failed']:
        flask.abort(400)
    app.logger.info('event=task account=%s instance=%s task=%s state=%s', 
        identity['accountId'], identity['instanceId'], task, state)
    if state == 'completed':
        session = assume_role(identity['accountId'], 'acquired-role')
        for volume_id in snapshot_volumes(session, identity['instanceId']):
            app.logger.info('event=snapshot account=%s instance=%s volume=%s', 
                identity['accountId'], identity['instanceId'], volume_id)
    return ''

def load_config(path):
    with open(path, 'r') as f:
        for k, v in yaml.load(f).items():
            config[k] = v
    config['x509'] = M2Crypto.X509.load_cert_string(config['cert'])

def configure_logger(level):
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers if gunicorn_logger.handlers else [flask.logging.default_handler]
    app.logger.setLevel(level)

if __name__=='__main__':
    configure_logger(logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=4444)
    parser.add_argument('--cert')
    parser.add_argument('--config', default='server/config.yaml')
    args = parser.parse_args()
    ssl_context = (args.cert, args.key) if args.cert and args.key else None
    load_config(args.config)
    app.run(host='0.0.0.0', port=args.port, ssl_context=ssl_context)
