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

app = flask.Flask('acquired-server')
app.logger.handlers = logging.getLogger('gunicorn.error').handlers \
    if logging.getLogger('gunicorn.error').handlers \
    else [flask.logging.default_handler]
app.logger.setLevel(logging.INFO)

cert = M2Crypto.X509.load_cert_string(
'''-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----''')

re_bearer = re.compile('^Bearer (.*)')

key = os.getenv('key')

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

def add_task(path):
    for e in [t for t in tasks if t['expires'] > int(time.time())]:
        tasks.remove(e)
    if len(tasks) < 1000:
        task = {
            'id': str(uuid.uuid4()).replace('-', ''),
            'path': '/{}'.format(path),
            'expires': int(time.time()) + 600,
        }
        tasks.append(task)
        return task

def verify_token(certificate, token):
    try:
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
        return json.loads(smime.verify(p7))
    except Exception:
        pass

def extract_bearer(header):
    try:
        for token in re_bearer.findall(header):
            return token.strip()
    except Exception:
        pass

@app.route('/')
def health():
    return ''

@app.route('/acquire/')
@app.route('/acquire/<path:path>')
def acquire(path=''):
    token = extract_bearer(flask.request.headers.get('Authorization'))
    if not token:
        flask.abort(401)
    if token != key:
        flask.abort(401)
    task = add_task(path)
    if not task:
        flask.abort(429)
    app.logger.info('event=schedule path=%s', path)
    return json.dumps(task)

@app.route('/poll')
def poll():
    token = extract_bearer(flask.request.headers.get('Authorization'))
    if not token:
        flask.abort(401)
    identity = verify_token(cert, token)
    if not identity:
        flask.abort(401)
    app.logger.info('event=poll account=%s instance=%s',
        identity['accountId'], identity['instanceId'])
    path = '/{}/{}'.format(identity['accountId'], identity['instanceId'])
    return json.dumps({
        'tasks': [t for t in tasks if path.startswith(t['path'])]
    })

@app.route('/status/<task>/<state>')
def status(task, state):
    token = extract_bearer(flask.request.headers.get('Authorization'))
    if not token:
        flask.abort(401)
    identity = verify_token(cert, token)
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
            for volume, snapshot in snapshot_volumes(session, identity['region'], identity['instanceId']):
                app.logger.info('event=snapshot account=%s instance=%s volume=%s snapshot=%s',
                    identity['accountId'], identity['instanceId'], volume, snapshot)
        except:
            app.logger.info('event=failed account=%s instance=%s',
                identity['accountId'], identity['instanceId'])
    return ''

if __name__=='__main__':
    app.run(host='0.0.0.0')
