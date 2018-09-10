FROM python:2

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

RUN mkdir /logs /db

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y graphviz-dev gcc

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY ./docker/ssl/certs/* /etc/ssl/certs/

RUN update-ca-certificates

EXPOSE 8000

ENTRYPOINT ["docker/entrypoint.sh"]
