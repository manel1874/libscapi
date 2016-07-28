#$1 - image name
#$2 - docker file path
#$3 - docker tag


echo 'deleting all containers'
docker ps -a -q | xargs --no-run-if-empty docker rm

echo 'deleting all images'
docker images -q | xargs --no-run-if-empty docker rmi

echo 'building image' $1 'using dockerfile' $2
docker build --build-arg tag=$3 --no-cache -t $1 -f $2 .
rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi

echo 'pushing image to docker hub'
docker login -u scapicryptobiu -p maliciousyao
docker push $1
