# $1 tag for the image

image='scapicryptobiu/libscapi_base:'$1
dockerfilePath='dockerfiles/PrerequisitesDockerfie'

./rebuild_docker_image $image $dockerfilePath
