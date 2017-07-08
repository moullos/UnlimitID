FROM ubuntu:16.04

MAINTAINER Panagiotis Moullotou "p.moullotou.16@ucl.ac.uk"

# Update OS
RUN apt-get update
RUN apt-get -y upgrade
ADD . /webapp
 
# Install uwsgi Python web server
RUN pip install uwsgi
# Install app requirements
RUN pip install -r requirements.txt
 
# Set the default directory for our environment
ENV HOME /webapp
WORKDIR /webapp
 
# Expose port 8000 for uwsgi
EXPOSE 5000
 
ENTRYPOINT ["uwsgi", "--http", "0.0.0.0:5000", "--module", "app:run_IdP", "--processes", "1", "--threads", "8"]
