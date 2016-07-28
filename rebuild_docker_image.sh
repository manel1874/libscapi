#$1 - image name
#$2 - docker file path


echo 'deleting all containers'
docker ps -a -q | xargs --no-run-if-empty docker rm

echo 'deleting all images'
docker images -q | xargs --no-run-if-empty docker rmi

echo 'building image $1 using dockerfile $2'
docker build --no-cache -t $1 -f $2 .

echo 'pushing image to docker hub'
docker login -u scapicryptobiu -p maliciousyao
docker push $1
