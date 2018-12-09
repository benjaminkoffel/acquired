# acquired

Proof of concept for simple forensic data acquisition for AWS.

The intention is to create a response agent that can be deployed with the least possible effort.

It can be baked into an AMI, does not require service restart and does not require instance profile permissions.

It is provided as an alternative to feature-rich solutions like GRR for when you only want acquisition.

Agents are installed as a daemon and poll the server to collect any tasks that need performing.

The server authenticates agents via PKCS#7 instance metadata and provides tasks to them if applicable.

The agent stores collected data in `/usr/local/etc/acquired/artefacts` and notifies the server of completion status.

A further objective is to trigger an EBS snapshot upon successful completion.

## Server
```
cd server
docker build -t acquired .
docker run -d -p 4444:4444 acquired
```

## Agent
```
# update server url in install.sh then execute
sudo sh agent/install.sh
```

## Usage
```
actions:
- memory: linpmem memory dump

schedule action for all instances:
curl http://localhost:4444/schedule/[action]/

schedule action for all instances in account:
curl http://localhost:4444/schedule/[action]/[account_id]/

schedule action for single instance:
curl http://localhost:4444/schedule/[action]/[account_id]/[instance_id]

example:
curl http://localhost:4444/schedule/memory/568333322432/i-03d629d19cb30dee
```

## References
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
- https://github.com/google/rekall
