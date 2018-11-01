FROM lensa/hdfs3:latest

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

RUN mkdir /logs

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["dare.py"]
