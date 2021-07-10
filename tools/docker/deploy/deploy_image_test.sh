#! /bin/bash

if [[ $1 != "ubuntu" && $1 != "centos" ]]; then
    echo "Must choose ubuntu/centos."
    exit 1
fi

if [ $1 == "ubuntu" ]; then
    docker build -f Dockerfile_template.ubuntu18.04 -t test-package:ubuntu .
    name=ubuntu_deploy_test
fi

if [ $1 == "centos" ]; then
    docker build -f Dockerfile_template.centos8.1 -t test-package:centos .
    name=centos_deploy_test
fi

docker rm -f $name || true
docker run -it --name="$name" --hostname="$name" --net="host" --privileged --device /dev/isgx test-package:$1 bash -c "cd /root/occlum-instance; occlum run /bin/hello_world"
