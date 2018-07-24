from flask import Flask
from flask import request
import json
import logging
import flask
from subprocess import *
from docker import *
from requests.exceptions import ConnectionError
import vimemu_settings


app = flask.Flask('vimemu_connector')


@app.route("/vimemu_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of vimemu_connector')
    jsonResponse = {'Active': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


# Start with VIM with thier ip and get the list of vim with docker
@app.route("/vimemu_connector/list_instances", methods=["POST"])
def listVIMEmuInstances():
    app.logger.debug('In vimemu_connector/list_instances')
    if request.is_json:
        app.logger.info('Received a json object')
        list_vim_ip = request.get_json()
        app.logger.info('The data are: %s' % list_vim_ip)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))

    list_vim_docker = get_containers_per_vimemu(list_vim_ip)
    if type(list_vim_docker) == dict:
        return flask.Response(json.dumps(list_vim_docker))
    app.logger.info('VIM-emu instances: %s' % str(list_vim_docker))
    jsonResponse = {'VIM': list_vim_ip}
    return flask.Response(json.dumps(jsonResponse))


# start with list of vim with their ip, this method uses this information to
# define the list of docker in execution for each vim,
# list_vim_ip = [{'ip', 'xxx.xxx.xxx.xxx', 'uuid': 'uuid_vim', 'vim': 'name'}]
# return list_vim_ip with docker_id ['id1', 'id2']
def get_containers_per_vimemu(list_vim_ip):
    app.logger.info('For each vim in the list get Id running docker')
    try:
        for vim in list_vim_ip:
            app.logger.info('Analyze VIM: ' + vim['vim'] + ' ip: ' + vim['ip'])
            client = Client(base_url='tcp://'+vim['ip']+':' +
                            vimemu_settings.VIM_EMU_DOCKER_PORT,
                            timeout=10)
            app.logger.debug('Connected with vim, now get list docker Id')
            list_containers = []
            for container in client.containers():
                if container['State'] == 'running':
                    app.logger.debug('Container Id: %s'
                                     % container['Id'][0:12])
                    list_containers.append(container['Id'][0:12])
            if not list_containers:
                app.logger.warning('No docker running')
            app.logger.info('Add list containers at VIM')
            vim.update({'docker_id': list_containers})
    except ConnectionError as exc:
        jsonResponse = {'Error': 'No response, impossible to connect '
                        'with Docker'}
        app.logger.error(jsonResponse)
        client.close()
        return jsonResponse
    client.close()
    return list_vim_ip


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vimemu_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
