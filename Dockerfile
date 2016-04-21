############################################################
# Dockerfile to build LibScapi Container Images
# Based on Ubuntu 14.04
############################################################

# Set the base image to Ubuntu
FROM ubuntu:14.04

# Update the repository sources list
RUN sudo apt-get update

# Install all required packages
RUN sudo apt-get install -y wget git build-essential libssl-ocaml-dev libssl-dev libgmp3-dev vim

# Download and install boost
RUN cd ~ && wget -O boost_1_60_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download && tar --bzip2 -xf boost_1_60_0.tar.bz2
RUN cd ~/boost_1_60_0 && ./bootstrap.sh && ./b2 ; exit 0

RUN cd ~ && git clone https://github.com/cryptobiu/libscapi.git
RUN cd ~/libscapi && git checkout dev && make

RUN sudo ldconfig ~/boost_1_60_0/stage/lib/ ~/libscapi/install/lib/

