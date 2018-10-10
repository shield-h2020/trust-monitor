from flask import Flask
from flask import request
import json
import logging
import flask
import dare_settings
import requests
from pathlib import Path
from dateutil.parser import parse
import io

app = flask.Flask('dare_connector')


def get_results(node, from_date=None, to_date=None):

    audit_list = []
    p = Path(dare_settings.DARE_ROOT_PATHNAME)
    node_path = p / node

    # First. check that the node has some audits
    if not node_path.exists():
        app.logger.debug('DARE audit component directory does not exist yet.')

    if node_path.exists() and node_path.is_dir():

        # If so, get all the subdirs with date for the node
        p_subdirs = [x for x in node_path.iterdir() if x.is_dir()]

        # If a start, stop date was provided, filter them
        if from_date and to_date:
            app.logger.debug("Dates provided for audit")
            # To do so, first consider only the last 10 characters of the
            # full path (the date)
            # and compare the date to start and stop dates
            p_subdirs = filter(lambda x:
                               (str(x)[-10:] >= from_date
                                and str(x)[-10:] <= to_date), p_subdirs)

        else:
            # Else, only the latest subdir must be retrieved
            app.logger.debug("Dates not provided for audit.")
            p_subdirs = sorted(p_subdirs,
                               key=lambda x: str(x),
                               reverse=True)
            p_subdirs = [p_subdirs[0]]

        # Now, cycle for all subdirs (only one in case of no date span)
        for p_subdir in p_subdirs:

            # First, sort the files in order
            json_files = [x for x in p_subdir.iterdir() if x.is_file()]
            json_files = sorted(json_files,
                                key=lambda x: str(x),
                                reverse=True)
            # In case of no date span, easy solution: get only latest file
            if not from_date and not to_date:
                json_files = [json_files[0]]

            # For each file, load its json content and append in audit list
            for json_file in json_files:
                app.logger.debug('JSON file open for read: ' + str(json_file))
                with open(str(json_file)) as data_file:
                    audit_list.append(json.load(data_file))

    # Return audit list
    return {'node': node, 'audit': audit_list}


def save_to_path(data, node, time):
    p = Path(dare_settings.DARE_ROOT_PATHNAME)
    # Fuzzy parser to accept timestring even if unknown tokens inside
    dateobj = parse(time, fuzzy=True)
    date_dir = dateobj.strftime("%Y-%m-%d")

    # If path does not exist, create the dir for the node
    if not p.exists():
        app.logger.debug('DARE audit root directory does not exist. Create now')
        p.mkdir(parents=True)

    # The audit dir for the node has dirs with dates
    audit_dir = p / node / date_dir
    app.logger.debug('Saving attestation result for ' + node +
                     ' in directory ' + str(audit_dir))
    if not audit_dir.exists():
        audit_dir.mkdir(parents=True)
    # Each filename in each date dir has the node name, the full date string
    # from attestation result and the .json extension

    filename = node + dateobj.strftime("%Y-%m-%d_%H:%M:%S.%f") + '.json'
    audit_filepath = audit_dir / filename
    app.logger.debug('Saving attestation result in file ' + filename)
    # Create empty file
    audit_filepath.touch()
    # Dump JSON data in it
    with io.open(str(audit_filepath), 'w', encoding="utf-8") as logfile:
        logfile.write(unicode(json.dumps(data, ensure_ascii=False)))


# Data is a JSON representation of AttestationStatus
def push_attestation_result(json):
    for host in json['hosts']:
        save_to_path(host, host['node'], host['time'])
    for sdn in json['sdn']:
        save_to_path(sdn, sdn['node'], sdn['extra_info']['Time'])


# Data is a JSON with {'node_id': xxx, 'from_date': <format_datestring>,
# 'to_date': <format_datestring>}
def pull_attestation_result(json):
    node = json['node_id']
    from_date = None
    to_date = None
    if 'from_date' in json:
        from_date = json['from_date']
    if 'to_date' in json:
        to_date = json['to_date']

    if from_date and to_date:
        from_date = parse(from_date).strftime("%Y-%m-%d")
        to_date = parse(to_date).strftime("%Y-%m-%d")
        app.logger.debug("Pull audit data for specified timeframe: " +
                         from_date + " --> " + to_date)
        return get_results(node, from_date, to_date)
    else:
        app.logger.debug("Pull audit data for last result")
        return get_results(node)


@app.route("/dare_connector/store_result", methods=["POST"])
def store_result():
    app.logger.debug('In post method of dare_connector/store_result')
    data = request.get_json()
    push_attestation_result(data)
    return flask.Response()


@app.route("/dare_connector/retrieve_audit", methods=["POST"])
def retrieve_audit():
    app.logger.debug('In post method of dare_connector/retrieve_audit')
    data = request.get_json()
    jsonResponse = pull_attestation_result(data)
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
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
