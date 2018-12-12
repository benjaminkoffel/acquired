#!/usr/bin/env python3
import base64
import json
import logging
import os
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

def load_config(app, level, path):
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers if gunicorn_logger.handlers else [flask.logging.default_handler]
    app.logger.setLevel(level)
    with open(path, 'r') as f:
        config = yaml.load(f)
    config['x509'] = M2Crypto.X509.load_cert_string(config['cert'])
    config['key'] = os.getenv('key')
    return config

app = flask.Flask(__name__)
config = load_config(app, logging.INFO, 'config.yaml')
re_bearer = re.compile('^Bearer (.*)')
tasks = []

def snapshot_volumes(session, region, instance):
    client = session.client('ec2', region)
    volumes = client.describe_volumes(
        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance]}])
    for v in volumes['Volumes']:
        description = 'ACQUIRED INSTANCE {} VOLUME {}'.format(instance, v['VolumeId'])
        snapshot = client.create_snapshot(
            VolumeId=v['VolumeId'], 
            Description=description)
        yield snapshot['VolumeId'], snapshot['SnapshotId']

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

@app.route('/')
def health():
    return 'OK'

@app.route('/schedule/<action>/')
@app.route('/schedule/<action>/<path:path>')
def schedule(action, path=''):
    if extract_bearer(flask.request.headers.get('Authorization')) != config['key']:
        flask.abort(401)
    if action not in ['memory']:
        flask.abort(400)
    app.logger.info('event=schedule action=%s path=%s',
        action, path)
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
    app.logger.info('event=poll account=%s instance=%s',
        identity['accountId'], identity['instanceId'])
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
        try:
            session = assume_role(identity['accountId'], 'acquired-role')
            for volume_id, snapshot_id in snapshot_volumes(session, identity['region'], identity['instanceId']):
                app.logger.info('event=snapshot account=%s instance=%s volume=%s snapshot=%s',
                    identity['accountId'], identity['instanceId'], volume_id, snapshot_id)
        except Exception:
            app.logger.exception('event=snapshot_failed account=%s instance=%s',
                identity['accountId'], identity['instanceId'])
    return ''

if __name__=='__main__':
    app.run(host='0.0.0.0')
