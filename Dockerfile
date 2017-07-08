FROM ubuntu:16.04

MAINTAINER Panagiotis Moullotou "p.moullotou.16@ucl.ac.uk"

# Update OS
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y python-pip python-dev libssl-dev libffi-dev

 
ADD . /webapp
ENV HOME /webapp
WORKDIR /webapp

# Install uwsgi Python web server
RUN pip install uwsgi
# Install app requirements
RUN pip install .
 
# Create app directory
 
# Set the default directory for our environment
 
# Expose port 8000 for uwsgi
EXPOSE 8000
 
ENTRYPOINT ["uwsgi", "--http", "0.0.0.0:8000", "--wsgi-file", "run_IdP.py","--callable","app", "--processes", "1", "--threads", "8"]
