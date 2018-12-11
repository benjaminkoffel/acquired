FROM python:3
EXPOSE 5000
RUN apt-get update
RUN apt-get install -y libssl-dev python3-dev swig gunicorn
COPY . /server
RUN python3 -m pip install -r server/requirements.txt
WORKDIR /server
HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost:5000/health || exit 1
CMD ["gunicorn", "--config", "gunicorn.conf", "server:app"]
