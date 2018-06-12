FROM python:2-alpine

LABEL maintainer="Giovanni Trivigno <s231595@studenti.polito.it>"

RUN mkdir /logs

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY centos_ping_vnfd.yaml .

COPY centos_pong_vnfd.yaml .

COPY store.py .

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["store.py"]
