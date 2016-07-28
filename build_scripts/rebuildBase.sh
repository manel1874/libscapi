# $1 tag for the image

./docker_clean.sh

image='scapicryptobiu/libscapi_base:'$1
dockerfilePath='dockerfiles/PrerequisitesDockerfie'

./rebuild_docker_image $image $dockerfilePath $1
