# delete all existing containers
docker ps -a -q | xargs --no-run-if-empty docker rm
# delete all images
docker images -q | xargs --no-run-if-empty docker rmi
# build a fresh one
docker build --no-cache -t scapicryptobiu/libscapi -f dockerfiles/Dockerfile .