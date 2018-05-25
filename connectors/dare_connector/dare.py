from flask import Flask
from flask import request
import json
import logging
import flask

app = flask.Flask('dare_connector')


@app.route("/dare_connector/attest_result", methods=["POST"])
def result_attestation():
    app.logger.debug('In post method of dare_connector/attest_result')
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        jsonData = json.dumps(data, ensure_ascii=False)
        app.logger.info('The data are: %s' % jsonData)
        jsonResponse = {'Message': 'Received'}
        return flask.Response(json.dumps(jsonResponse))
    else:
        jsonError = {'Error': 'Accept only json objects'}
        app.logger.error(jsonError)
        return flask.Response(json.dumps(jsonError))


@app.route("/dare_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of dare_connector')
    jsonResponse = {'Runnging': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/dare_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
