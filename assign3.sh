#!/bin/bash

lannetnum="192.168.16"
mgmtnetnum="172.16.1"
prefix=server
startinghostnum=10
remoteadmin="remoteadmin"
numcontainers=1
puppetinstall=no
verbose=yes

source /etc/os-release

function echoverbose {
    [ "$verbose" = "yes" ] && echo "$@"
}


DOCKERS=( docker-edgex-volume docker-core-consul core-config-seed docker-edgex-mongo support-logging \
    support-notifications core-metadata core-data core-command support-scheduler \
    support-rulesengine device-virtual device-bacnet device-bluetooth device-modbus device-mqtt device-snmp)

DOCKERFILE=$1

usage(){
    echo -e "ERROR! Dockerfile name not found."
    echo -e "\tI.E: ./${0} Dockerfile.aarch64"
    exit
}


if [[ -z ${DOCKERFILE} ]]; then
    usage
fi

for m in ${DOCKERS[@]} ;  do
    if [ -d $m ]; then
        echo "Updating git modules... "
        cd $m
        git pull
        cd ..
    else
        echo "Cloning $m"
        git clone https://github.com/edgexfoundry/$m
    fi
    if [ -f $m/docker-files/${DOCKERFILE} ] ; then
        echo "Creating docker image $m"
        cd $m
        docker build . -t edgexfoundry/docker-$m -f docker-files/${DOCKERFILE}
        echo $m
        cd ..

    elif [ -f $m/${DOCKERFILE} ] ; then
        echo "Creating docker image $m"
        cd $m
        docker build . -t edgexfoundry/$m -f ${DOCKERFILE}
        echo $m
        cd ..
    else
        usage
    fi
done


echo "Done!"
