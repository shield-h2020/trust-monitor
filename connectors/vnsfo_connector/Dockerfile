FROM ubuntu:16.04

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

RUN mkdir /logs

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get install -y python \
    python-pip \
    python-dev \
    curl \
    software-properties-common

RUN pip install -r requirements.txt

# RUN curl http://osm-download.etsi.org/repository/osm/debian/ReleaseTHREE/OSM%20ETSI%20Release%20Key.gpg | apt-key add -

# RUN add-apt-repository -y "deb [arch=amd64] http://osm-download.etsi.org/repository/osm/debian/ReleaseTHREE stable osmclient"

# RUN apt-get update  && apt-get install -y python-osmclient

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["vnsfo.py"]
