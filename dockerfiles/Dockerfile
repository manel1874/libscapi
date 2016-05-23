############################################################
# Dockerfile to build LibScapi Container Images
# Based on Ubuntu 14.04
############################################################

# Set the base image to libscapi base
FROM scapycryptobiu/libscapi_base:latest

# fetch libscapi and build it
RUN cd ~ && git clone https://github.com/cryptobiu/libscapi.git
RUN cd ~/libscapi && git checkout dev && make

# publish libscapi and boost artificats
RUN sudo ldconfig ~/boost_1_60_0/stage/lib/ ~/libscapi/install/lib/

# build the samples and run one of them
RUN make -C ~/libscapi/samples/
RUN ~/libscapi/samples/libscapi_example.exe dlog
RUN ~/libscapi/samples/libscapi_example.exe sha1

# build the tests and run them
RUN make -C ~/libscapi/test/
RUN ~/libscapi/test/tests.exe

# done
RUN echo DONE!

