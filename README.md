# AcquireD

Proof of concept for simple forensic data acquisition for AWS.

The intention is to create a response agent that can be deployed with the least possible effort.

It can be baked into an AMI, does not require service restart and does not require instance profile permissions.

It is provided as an alternative to feature-rich solutions like GRR for when you only want acquisition.

Agents are installed as a daemon and poll the server to collect any tasks that need performing.

The server authenticates agents via PKCS#7 instance metadata and provides tasks to them if applicable.

The agent stores collected data in `/usr/local/etc/acquired/artefacts` and notifies the server of completion status.

Upon completion an EBS snapshot is taken of all volumes attached to the instance which can be used for forensic analysis.

## Server
```
# install AWS role "acquired-service-role.yaml" in server account
cd server
docker build -t acquired .
docker run -d -p 5000:5000 -e key=some-secret-key acquired
```

## Agent
```
# install AWS role "acquired-role.yaml" in agent account
sudo ./agent/install.sh http://localhost:5000
```

## Usage
```
# acquire memory from all instances
curl http://localhost:5000/acquire/ -H "Authorization: Bearer [key]"

# acquire memory from all instances in an acount:
curl http://localhost:5000/acquire/[account]/ -H "Authorization: Bearer [key]"

# acquire memory from single instance
curl http://localhost:5000/acquire/[account]/[instance] -H "Authorization: Bearer [key]"

# example
curl http://localhost:5000/acquire/568333322432/i-03d629d19cb30dee -H "Authorization: Bearer some-secret-key"
```

## Forensics
```
# create forensics instance using amazon linux 2 ami
# create volume from snapshot you want to analyze
# attach volume to forensics instance at /dev/sdf
sudo yum update -y
sudo amazon-linux-extras install -y docker
sudo mkdir -p /data
sudo mount /dev/sdf1 /data
sudo docker run -v /data:/data log2timeline/plaso log2timeline /data/disk.plaso /data/tmp
sudo mkdir -p /artefacts
sudo cp /data/disk.plaso /artefacts
sudo cp /usr/local/etc/acquired/artefacts/* /artefacts
sudo umount /data
# detach volume from forensics instance and delete
```

## References
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
- https://github.com/google/rekall
