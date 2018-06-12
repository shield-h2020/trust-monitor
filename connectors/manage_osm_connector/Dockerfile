FROM ubuntu:16.04

LABEL maintainer="Giovanni Trivigno <s231595@studenti.polito.it>"

RUN mkdir /logs

WORKDIR /usr/src/app

COPY requirements.txt .

RUN apt-get update && apt-get install -y python \
    python-pip \
    python-dev \
    curl \
    software-properties-common

RUN pip install -r requirements.txt

RUN curl http://osm-download.etsi.org/repository/osm/debian/ReleaseTHREE/OSM%20ETSI%20Release%20Key.gpg | apt-key add -

RUN add-apt-repository -y "deb [arch=amd64] http://osm-download.etsi.org/repository/osm/debian/ReleaseTHREE stable osmclient"

RUN apt-get update  && apt-get install -y python-osmclient

ENV OSM_HOSTNAME=osm_ip

ENV OSM_RO_HOSTNAME=osm_ip

EXPOSE 5000

COPY manage_osm.py .

ENTRYPOINT ["python"]

CMD ["manage_osm.py"]
