FROM python:2-alpine

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

RUN mkdir /logs /db

RUN echo 'https://dl-3.alpinelinux.org/alpine/v3.4/main' > /etc/apk/repositories  && \
    echo '@testing https://dl-3.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories && \
    echo '@community https://dl-3.alpinelinux.org/alpine/v3.4/community'

WORKDIR /usr/src/app

RUN apk --update --no-cache add \
        graphviz-dev \
        gcc \
        musl-dev

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY ./docker/ssl/certs/* /etc/ssl/certs/

RUN /etc/ca-certificates/update.d/c_rehash

EXPOSE 8000

ENTRYPOINT ["docker/entrypoint.sh"]
