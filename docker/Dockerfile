FROM python:3.12.2-bookworm

RUN apt-get update && apt-get install --no-install-recommends -y libpcap-dev iproute2

ADD requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

VOLUME ["/App"]
WORKDIR /App

ENV RUNNING_IN_DOCKER Yes

ENTRYPOINT ["/bin/bash", "-c", "python3 -m pytest --junit-xml=./output/result_\"$(date +%Y%m%d_%H%M%S)\".junit"]

