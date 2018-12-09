FROM python:3
EXPOSE 4444
RUN apt-get update 
RUN apt-get install -y libssl-dev python3-dev swig
COPY . /api
RUN python3 -m pip install -r api/requirements.txt
COPY *.py ./
CMD ./api/api.py
