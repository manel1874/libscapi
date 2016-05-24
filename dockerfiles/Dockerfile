############################################################
# Dockerfile to build LibScapi Container Image
# Builds only libscapi itself
# Based on scapicryptobiu/libscapi_libs
# Tagged: scapicryptobiu/libscapi
############################################################

# Set the base image to libscapi base
FROM scapicryptobiu/libscapi_libs:latest

# build the samples and run one of them
RUN make -C ~/libscapi/samples/
RUN ~/libscapi/samples/libscapi_example.exe dlog
RUN ~/libscapi/samples/libscapi_example.exe sha1

# build the tests and run them
RUN make -C ~/libscapi/test/
RUN ~/libscapi/test/tests.exe

# done
RUN echo DONE!

