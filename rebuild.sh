#$1 - tag for building the docker

base_image='scapicryptobiu/libscapi_libs':$1
image='scapicryptobiu/libscapi:'$1
dockerfilePath='dockerfiles/Dockerfile'

docker pull $base_image
docker tag libscapi_libs $base_image
./rebuild_docker_image.sh $image $dockerfilePath $1

