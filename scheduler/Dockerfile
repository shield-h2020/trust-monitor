FROM python:2-alpine

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "./docker/scheduler.py"]
