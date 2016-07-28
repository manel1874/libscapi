#$1 - tag for building the docker

image='scapicryptobiu/libscapi_libs:'$1
dockerfilePath='dockerfiles/DockerfileLibs'

./rebuild_docker_image $image $dockerfilePath
