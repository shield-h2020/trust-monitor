from flask import Flask
from flask import request
import json
import logging
import flask
import dare_settings
import requests

app = flask.Flask('dare_connector')


@app.route("/dare_connector/attest_result", methods=["POST"])
def attest_result():
    app.logger.debug('In post method of dare_connector/attest_result')

    data = request.get_json()
    app.logger.debug('Received a json object')
    jsonData = json.dumps(data, ensure_ascii=False)
    url = dare_settings.DARE_BASE_URL
    # app.logger.info(url)
    # TODO: call proper DARE API to store attestation result for audit
    # response = requests.post(url, data=jsonData)
    app.logger.info(jsonData)
    jsonResponse = {'Result': 'True'}
    return flask.Response(json.dumps(jsonResponse))


@app.route("/dare_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of dare_connector')
    jsonResponse = {'Active': True}
    app.logger.debug(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/dare_connector.log")
    fileHandler.setLevel(logging.INFO)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
