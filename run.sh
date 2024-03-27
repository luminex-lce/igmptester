#!/bin/sh

TESTS=$1

docker build -t igmptester docker

docker run \
    --rm -it \
    --name igmptester \
    --network=host \
    --cap-add=NET_ADMIN \
    --mount type=bind,source="$(pwd)",target=/App \
    igmptester \
    $TESTS
