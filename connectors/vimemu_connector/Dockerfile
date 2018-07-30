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

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["vimemu.py"]
