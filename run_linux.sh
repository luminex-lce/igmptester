#!/bin/sh

INTERFACE=$1
TESTS=$2

docker build -t igmptester docker

docker network rm -f igmp-net
docker network create -d macvlan -o parent=$INTERFACE igmp-net

docker run \
    --rm -it \
    --name igmptester \
    --network=igmp-net \
    --cap-add=NET_ADMIN \
    --mount type=bind,source="$(pwd)",target=/App \
    igmptester \
    $TESTS

docker network rm -f igmp-net
