#$1 - tag for building the docker
image='scapicryptobiu/libscapi:'$1
dockerfilePath='dockerfiles/Dockerfile'

./rebuild_docker_image.sh $image $dockerfilePath

