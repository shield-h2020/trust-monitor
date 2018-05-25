FROM python:2-alpine

LABEL maintainer="Giovanni Trivigno <s231595@studenti.polito.it>"

RUN mkdir /logs

WORKDIR /usr/src/app

COPY dashboard.py .

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["dashboard.py"]
