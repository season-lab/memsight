FROM ubuntu:16.04
MAINTAINER Emilio Coppa <ercoppa@gmail.com>

RUN apt-get update && apt-get install -y sudo nano python-pip time git python-dev build-essential

RUN useradd -m ubuntu && \
 echo ubuntu:ubuntu | chpasswd && \
 cp /etc/sudoers /etc/sudoers.bak && \ 
 echo 'ubuntu  ALL=(root) NOPASSWD: ALL' >> /etc/sudoers

USER ubuntu
WORKDIR /home/ubuntu

COPY fully-symbolic-memory/build/install.sh /home/ubuntu
COPY fully-symbolic-memory /home/ubuntu/memsight
#COPY CGC /home/ubuntu/CGC

USER ubuntu
RUN ./install.sh
