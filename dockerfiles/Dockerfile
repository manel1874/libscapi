############################################################
# Dockerfile to build LibScapi Container Image
# Builds only libscapi itself
# Based on scapicryptobiu/libscapi_libs
# Tagged: scapicryptobiu/libscapi
############################################################

# set the base image to libscapi base
from williamyeh/dummy
RUN echo "null"


ARG tag
FROM scapicryptobiu/libscapi_libs:$tag

# recopying to invalidate new files
WORKDIR /root
COPY . libscapi/ 

# build libscapi
WORKDIR libscapi
RUN make libscapi

# build the samples and run one of them
WORKDIR samples
RUN make
RUN ./libscapi_example.exe dlog
RUN ./libscapi_example.exe sha1

# build the tests and run them
WORKDIR ../test
RUN make
RUN ./tests.exe

# done
RUN echo DONE!

