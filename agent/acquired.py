#!/usr/bin/env python3
import argparse
import http.client
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

logging.basicConfig(level=logging.DEBUG, format='time="%(asctime)s" level=%(levelname)s %(message)s', stream=sys.stdout)

path = '/usr/local/etc/acquired'

def http_get(url, status=200, headers={}):
    request = urllib.request.Request(url=url, headers=headers)
    with urllib.request.urlopen(request) as r:
        if r.getcode() != status:
            raise Exception('GET {} returned unexpected status code {}.'.format(url, r.getcode()))
        return r.read()

def http_poll(url, token):
    return json.loads(http_get(url='{}/poll'.format(url), headers={'Authorization': 'Bearer {}'.format(token)}))

def http_task(url, token, task, state):
    http_get(url='{}/task/{}/{}'.format(url, task, state), headers={'Authorization': 'Bearer {}'.format(token)})

def http_token():
    pkcs7 = http_get('http://169.254.169.254/latest/dynamic/instance-identity/pkcs7').decode('utf-8')
    data = '-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----'.format(pkcs7).encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

def memory():
    filename = '{}/artefacts/memory.{}.aff4r'.format(path, int(time.time()))
    subprocess.check_call(['/usr/bin/local/linpmem-2.1.post4', '-o', filename], stdout=subprocess.PIPE)

def monitor(task_queue, url):
    while True:
        try:
            task = task_queue.get()
            token = http_token()
            logging.info('event=started task=%s action=%s', task['id'], task['action'])
            http_task(url, token, task['id'], 'started')
            try:
                if task['action'] == 'memory':
                    memory()
                else:
                    raise Exception('Action not supported.')
                logging.info('event=completed task=%s action=%s', task['id'], task['action'])
                http_task(url, token, task['id'], 'completed')
            except:
                logging.exception('event=failed task=%s action=%s', task['id'], task['action'])
                http_task(url, token, task['id'], 'failed')
            task_queue.task_done()
        except:
            logging.exception('monitor')

def schedule(task_queue, task):
    task_path = '{}/tasks/{}'.format(path, task['id'])
    if not os.path.exists(task_path):
        with open(task_path, 'w') as f:
            f.write(json.dumps(task))
        if task['expires'] < int(time.time()):
            logging.info('event=schedule task=%s', task['id'])
            task_queue.put(task)
        else:
            logging.info('event=expired task=%s', task['id'])

def poll(task_queue, url):
    try:
        token = http_token()
        logging.debug('event=poll url=%s', url)
        for task in http_poll(url, token)['tasks']:
            schedule(task_queue, task)
    except Exception:
        logging.exception('poll')
    time.sleep(10)

def main():
    try:
        with open('{}/url'.format(path), 'r') as f:
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
