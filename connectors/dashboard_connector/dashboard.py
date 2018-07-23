from flask import Flask
import pika
from flask import request
from flask import jsonify
import json
import logging
import flask
import dashboard_settings

app = Flask('dashboard_connector')


@app.route("/dashboard_connector/attestation_failed",
           methods=["POST"])
def attestation_failed():
    app.logger.debug('In post method of'
                     ' dashboard_connector/attestation_failed')
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host=dashboard_settings.DASHBOARD_HOSTNAME,
            port=dashboard_settings.DASHBOARD_PORT,
            connection_attempts=dashboard_settings.DASHBOARD_ATTEMPTS,
            retry_delay=dashboard_settings.DASHBOARD_RETRY_DELAY,
            blocked_connection_timeout=300))

    channel = connection.channel()
    channel.exchange_declare(
        exchange=dashboard_settings.DASHBOARD_EXCHANGE,
        exchange_type='topic')
    app.logger.debug(
        "Connected to dashboard at hostname: " +
        dashboard_settings.DASHBOARD_HOSTNAME + ":" +
        dashboard_settings.DASHBOARD_PORT)

    if request.is_json:
        data = request.get_json()
    else:
        jsonError = {'Result': False}
        app.logger.error(jsonError)
        return flask.Response(json.dumps(jsonError))
    jsonData = json.dumps(data, ensure_ascii=False)

    channel.basic_publish(exchange=dashboard_settings.DASHBOARD_EXCHANGE,
                          routing_key=dashboard_settings.DASHBOARD_TOPIC,
                          body=jsonData)

    app.logger.info("Published notification on failed attestation \
        from TM to dashboard.")
    app.logger.debug(jsonData)
    channel.close()
    connection.close()
    jsonResponse = {'Result': True}
    return flask.Response(json.dumps(jsonResponse))


@app.route("/dashboard_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of dashboard_connector')
    jsonResponse = {'Active': True}
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
