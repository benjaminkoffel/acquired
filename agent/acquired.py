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

logging.basicConfig(level=logging.DEBUG, format='time="%(asctime)s" level=%(levelname)s %(message)s', stream=sys.stdout)

path = '/etc/acquired'

def http_enrol(url, key, account, instance):
    headers = {'Authorization': f'Bearer {key}'}
    request = urllib.request.Request(f'{url}/enrol/{account}/{instance}', headers=headers)
    with urllib.request.urlopen(request) as r:
        status = r.getcode()
        if status != 200:
            raise Exception(f'enrol returned unexpected status code {status}')
        return json.loads(r.read())

def http_poll(url, token):
    headers = {'Authorization': f'Bearer {token}'}
    request = urllib.request.Request(f'{url}/poll', headers=headers)
    with urllib.request.urlopen(request) as r:
        status = r.getcode()
        if status != 200:
            raise Exception(f'poll returned unexpected status code {status}')
        return json.loads(r.read())

def http_task(url, token, task, state):
    headers = {'Authorization': f'Bearer {token}'}
    request = urllib.request.Request(f'{url}/task/{task}/{state}', headers=headers)
    with urllib.request.urlopen(request) as r:
        status = r.getcode()
        if status != 200:
            raise Exception(f'task returned unexpected status code {status}')

def enrol(url, key):
    logging.info('event=enrol url=%s', url)
    account, instance = '11111111', 'aaaaaaaa' # todo: get ec2 metadata
    response = http_enrol(url, key, account, instance)
    if not os.path.exists(path):
        os.makedirs(path)
        os.chmod(path, 0o700)
        os.makedirs(path + '/tasks')
        os.makedirs(path + '/artefacts')
    with open(path + '/url', 'w') as f:
        f.write(url)
    with open(path + '/token', 'w') as f:
        f.write(response['access_token'])

def memory():
    timestamp = int(time.time())
    subprocess.check_call(['/usr/bin/local/linpmem-2.1.post4', '-o', f'{path}/artefacts/memory.{timestamp}.aff4r'], stdout=subprocess.PIPE)

def monitor(task_queue, url, token):
    while True:
        try:
            task = task_queue.get()   
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
        logging.info('event=schedule task=%s', task['id'])
        with open(task_path, 'w') as f:
            f.write(json.dumps(task))
        task_queue.put(task)

def poll():
    if not os.path.exists(path):
        logging.error('Agent has not been enrolled.')
        return
    with open(f'{path}/url', 'r') as f:
        url = f.read()
    with open(f'{path}/token', 'r') as f:
        token = f.read()
    task_queue = queue.Queue()
    thread = threading.Thread(target=monitor, args=(task_queue, url, token))
    thread.daemon = True
    thread.start()
    while True:
        try:
            logging.debug('event=poll url=%s', url)
            for task in http_poll(url, token)['tasks']:
                schedule(task_queue, task)
            time.sleep(10)
        except Exception:
            logging.exception('poll')

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--url')
        parser.add_argument('--key')
        args = parser.parse_args()
        if args.url and args.key:
            enrol(args.url, args.key)
        else:
            poll()
    except Exception:
        logging.exception('main')
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
