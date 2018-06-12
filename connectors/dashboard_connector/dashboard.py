from flask import Flask
import pika
from flask import request
from flask import jsonify
import json
import logging
import flask

app = Flask('dashboard_connector')


@app.route("/dashboard_connector/attestation_failed",
           methods=["POST"])
def attestation_failed():
    app.logger.debug('In post method of'
                     ' dashboard_connector/attestation_failed')
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='rabbitmq_server'))
    channel = connection.channel()
    channel.queue_declare(queue='dashboard_queue', durable=True)
    app.logger.info('Connect with rabbitmq_server')
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        app.logger.info('Message sent to dashboard_queue')
    else:
        jsonError = {'Error': 'Accept only json objects'}
        app.logger.error(jsonError)
        return flask.Response(json.dumps(jsonError))
    jsonData = json.dumps(data, ensure_ascii=False)
    channel.basic_publish(exchange='',
                          routing_key='dashboard_queue',
                          body=jsonData)
    app.logger.info(jsonData)
    connection.close()
    jsonResponse = {'Message': 'Received'}
    return flask.Response(json.dumps(jsonResponse))


@app.route("/dashboard_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of dashboard_connector')
    jsonResponse = {'Runnging': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/dashboard_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
