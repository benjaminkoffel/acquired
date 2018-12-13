#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.request
import base64

logging.basicConfig(level=logging.INFO, format='time="%(asctime)s" level=%(levelname)s %(message)s', stream=sys.stdout)

acquired_path = '/usr/local/etc/acquired'
linpmem_path = '/usr/local/sbin/linpmem-2.1.post4'
linpmem_md5 = '4a5a922b0c0c2b38131fb4831cc4ece9'

def http_get(url, status=200, headers={}):
    request = urllib.request.Request(url=url, headers=headers)
    with urllib.request.urlopen(request) as r:
        if r.getcode() != status:
            raise Exception('GET {} returned unexpected status code {}.'.format(url, r.getcode()))
        return r.read()

def http_poll(url, token):
    return json.loads(http_get(url='{}/poll'.format(url), headers={'Authorization': 'Bearer {}'.format(token)}))

def http_status(url, token, task, state):
    http_get(url='{}/status/{}/{}'.format(url, task, state), headers={'Authorization': 'Bearer {}'.format(token)})

def http_token():
    pkcs7 = http_get('http://169.254.169.254/latest/dynamic/instance-identity/pkcs7').decode('utf-8')
    data = '-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----'.format(pkcs7).encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

def acquire():
    md5 = hashlib.md5()
    with open(linpmem_path, 'rb') as f:
        md5.update(f.read())
    if str(md5.hexdigest()) != linpmem_md5:
        raise Exception('Integrity check failed {} {}.'.format(linpmem_path, linpmem_md5))
    filename = '{}/artefacts/memory.{}.aff4r'.format(acquired_path, int(time.time()))
    subprocess.check_call([linpmem_path, '-o', filename], stdout=subprocess.PIPE)

def monitor(task_queue, url):
    while True:
        try:
            task = task_queue.get()
            token = http_token()
            logging.info('event=started task=%s', task['id'])
            http_status(url, token, task['id'], 'started')
            try:
                acquire()
                logging.info('event=completed task=%s', task['id'])
                http_status(url, token, task['id'], 'completed')
            except:
                logging.exception('event=failed task=%s', task['id'])
                http_status(url, token, task['id'], 'failed')
            task_queue.task_done()
        except:
            logging.exception('event=monitor')

def schedule(task_queue, task):
    task_path = '{}/tasks/{}'.format(acquired_path, task['id'])
    if not os.path.exists(task_path):
        with open(task_path, 'w') as f:
            f.write(json.dumps(task))
        if task['expires'] > int(time.time()):
            logging.info('event=schedule task=%s', task['id'])
            task_queue.put(task)
        else:
            logging.info('event=expired task=%s', task['id'])

def poll(task_queue, url):
    try:
        token = http_token()
        logging.info('event=poll url=%s', url)
        for task in http_poll(url, token)['tasks']:
            schedule(task_queue, task)
    except Exception:
        logging.exception('poll')
    time.sleep(60)

def main():
    try:
        with open('{}/url'.format(acquired_path), 'r') as f:
            url = f.read().strip()
        task_queue = queue.Queue()
        thread = threading.Thread(target=monitor, args=(task_queue, url))
        thread.daemon = True
        thread.start()
        while True:
            poll(task_queue, url)
    except Exception:
        logging.exception('main')

if __name__ == '__main__':
    main()
