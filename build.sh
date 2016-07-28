#$1 - tag for building the docker
image='scapicryptobiu/libscapi:'$1
dockerfilePath='dockerfiles/Dockerfile'

docker build--build-arg tag=$1 --no-cache -t $image -f $dockerfilePath .
