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

def http_get(url, status=200, headers=None):
    request = urllib.request.Request(url=url, headers=headers)
    with urllib.request.urlopen(request) as r:
        if r.getcode() != status:
            raise Exception('GET {} returned unexpected status code {}.'.format(url, r.getcode()))
        return r.read()

def http_document():
    return \
'''{
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "privateIp" : "10.0.1.95",
  "version" : "2017-09-30",
  "instanceType" : "t2.nano",
  "billingProducts" : null,
  "instanceId" : "i-03d629d19cb30deec",
  "accountId" : "568333322432",
  "availabilityZone" : "ap-southeast-2a",
  "kernelId" : null,
  "ramdiskId" : null,
  "architecture" : "x86_64",
  "imageId" : "ami-0aff30363d302d23a",
  "pendingTime" : "2018-12-03T03:02:58Z",
  "region" : "ap-southeast-2"
}'''
    return http_get('http://169.254.169.254/latest/dynamic/instance-identity/document')

def http_pkcs7():
    return \
'''
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHiewog
ICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAibWFya2V0cGxhY2VQcm9kdWN0Q29kZXMi
IDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIxMC4wLjEuOTUiLAogICJ2ZXJzaW9uIiA6ICIyMDE3
LTA5LTMwIiwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5uYW5vIiwKICAiYmlsbGluZ1Byb2R1Y3Rz
IiA6IG51bGwsCiAgImluc3RhbmNlSWQiIDogImktMDNkNjI5ZDE5Y2IzMGRlZWMiLAogICJhY2Nv
dW50SWQiIDogIjU2ODMzMzMyMjQzMiIsCiAgImF2YWlsYWJpbGl0eVpvbmUiIDogImFwLXNvdXRo
ZWFzdC0yYSIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJh
cmNoaXRlY3R1cmUiIDogIng4Nl82NCIsCiAgImltYWdlSWQiIDogImFtaS0wYWZmMzAzNjNkMzAy
ZDIzYSIsCiAgInBlbmRpbmdUaW1lIiA6ICIyMDE4LTEyLTAzVDAzOjAyOjU4WiIsCiAgInJlZ2lv
biIgOiAiYXAtc291dGhlYXN0LTIiCn0AAAAAAAAxggEXMIIBEwIBATBpMFwxCzAJBgNVBAYTAlVT
MRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdB
bWF6b24gV2ViIFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xODEyMDMwMzAzMDZaMCMGCSqGSIb3DQEJ
BDEWBBQ2fwDAlRfkdKZ0jjcL6Gy5nBoGnjAJBgcqhkjOOAQDBC4wLAIUfKtLotTzt7UtlgADpUIB
CDG6insCFHLu1fQwkUgR2WiYP7kTIZPInslJAAAAAAAA
-----END PKCS7-----
'''
    return http_get('http://169.254.169.254/latest/dynamic/instance-identity/pkcs7')

def http_poll(url, token):
    return json.loads(http_get(url='{}/poll'.format(url), headers={'Authorization': 'Bearer {}'.format(token)}))

def http_task(url, token, task, state):
    http_get(url='{}/task/{}/{}'.format(url, task, state), headers={'Authorization': 'Bearer {}'.format(token)})

def get_token():
    data = '{}\n-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----'.format(http_document(), http_pkcs7())
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def memory():
    filename = '{}/artefacts/memory.{}.aff4r'.format(path, int(time.time()))
    subprocess.check_call(['/usr/bin/local/linpmem-2.1.post4', '-o', filename], stdout=subprocess.PIPE)

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
        with open(task_path, 'w') as f:
            f.write(json.dumps(task))
        if task['expires'] < int(time.time()):
            logging.info('event=schedule task=%s', task['id'])
            task_queue.put(task)
        else:
            logging.info('event=expired task=%s', task['id'])

def poll(task_queue, url, token):
    try:
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
        token = get_token()
        token = 'x'
        task_queue = queue.Queue()
        thread = threading.Thread(target=monitor, args=(task_queue, url, token))
        thread.daemon = True
        thread.start()
        while True:
            poll(task_queue, url, token)
    except Exception:
        logging.exception('main')

if __name__ == '__main__':
    main()
