#$1 - tag for building the docker

base_image='scapicryptobiu/libscapi_base':$1
image='scapicryptobiu/libscapi_libs:'$1
dockerfilePath='dockerfiles/DockerfileLibs'

docker pull $base_image
docker tag libscapi_base $base_image
./rebuild_docker_image $image $dockerfilePath $1
