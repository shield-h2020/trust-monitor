from flask import Flask
from flask import request
import json
import logging
import flask
from subprocess import *
from docker import *
from requests.exceptions import ConnectionError


app = flask.Flask('manage_osm connector')


@app.route("/manage_osm_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of manage_osm_connector')
    jsonResponse = {'Runnging': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


# Get list VIM with their IP throught OSM
@app.route("/manage_osm_connector/osm_list_vim_ip", methods=["GET"])
def getVimIp():
    app.logger.debug('In get method of osm_vim_ip')
    list_vim_ip = listVimIp()
    app.logger.info(list_vim_ip)
    return flask.Response(json.dumps(list_vim_ip))


# Start with VIM with thier ip and get the list of vim with docker
@app.route("/manage_osm_connector/osm_vim_docker", methods=["POST"])
def listVIMDocker():
    app.logger.debug('In osm_vim_docker')
    if request.is_json:
        app.logger.info('Received a json object')
        list_vim_ip = request.get_json()
        app.logger.info('The data are: %s' % list_vim_ip)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    list_vim_docker = dockerId(list_vim_ip)
    if type(list_vim_docker) == dict:
        return flask.Response(json.dumps(list_vim_docker))
    app.logger.info('VIM with docker: %s' % str(list_vim_docker))
    jsonResponse = {'VIM': list_vim_ip}
    return flask.Response(json.dumps(jsonResponse))


# Method to get a vim list with their ip
def listVimIp():
    app.logger.info('get list vim with ip')
    bash_vim_osm = "osm vim-list"
    list_vim = []
    list_vim_ip = []
    process_vim_list = Popen(bash_vim_osm.split(),
                             stdout=PIPE, stderr=PIPE)
    output_vim, error = process_vim_list.communicate()
    if not error:
        app.logger.info('Start process to get list VIM')
        for line in output_vim.split('\n')[3:-2]:
            app.logger.debug('analyze vim: %s' % line)
            line_split = line.split()
            if len(line_split) > 1:
                dict = {'vim': line_split[1],
                        'uuid': line_split[3]}
                list_vim.append(dict)
    else:
        app.logger.error('Impossible to connect to OSM')
        jsonResponse = {'Impossible to connect to OSM':
                        error.split('\n')[len(error.split('\n'))-2]}
        return jsonResponse
    if not list_vim:
        jsonError = {'Error': 'No VIM connected with Open Source Mano'}
        app.logger.error(jsonError)
        return jsonError
    for vim in list_vim:
        app.logger.info('Get IP from: %s' % vim['vim'])
        bash_vim_show = "osm vim-show %s" % vim['vim']
        process_vim_show = Popen(bash_vim_show.split(),
                                 stdout=PIPE, stderr=PIPE)
        output_vim_show, error = process_vim_show.communicate()
        if not error:
            app.logger.debug('Get ip address for each vim')
            for line in output_vim_show.split('\n')[3:-2]:
                line_split = line.split()
                if len(line_split) > 1 and line_split[1] == 'vim_url':
                    vim_url = line_split[3]
                    app.logger.debug('vim_url: ' + vim_url +
                                     ' vim: ' + vim['vim'])
                if len(line_split) > 1 and line_split[1] == 'type':
                    app.logger.debug('type vim ' + vim['vim'] + ' ' +
                                     line_split[3])
                    if line_split[3].find("openstack"):
                        if vim_url.find("identity") == -1:
                            ip = vim_url.split(':')[1][2:]
                            app.logger.info('IP address '
                                            + ip + ' for ' + vim['vim'])
                            dict = {'vim': vim['vim'],
                                    'uuid': vim['uuid'],
                                    'ip': ip}
                            list_vim_ip.append(dict)
        else:
            app.logger.error('Impossible to connect to OSM')
            jsonResponse = {'Impossible to connect to OSM':
                            error.split('\n')[len(error.split('\n'))-2]}
            return jsonResponse
    if not list_vim_ip:
        jsonError = {'Error': 'No VIM connected with Open Source Mano'}
        app.logger.error(jsonError)
        return jsonError
    return list_vim_ip


# start with list of vim with their ip, this method uses this information to
# define the list of docker in execution for each vim,
# list_vim_ip = [{'ip', 'xxx.xxx.xxx.xxx', 'uuid': 'uuid_vim', 'vim': 'name'}]
# return list_vim_ip with docker_id ['id1', 'id2']
def dockerId(list_vim_ip):
    app.logger.info('For each vim in the list get Id running docker')
    try:
        for vim in list_vim_ip:
            app.logger.info('Analyze VIM: ' + vim['vim'] + ' ip: ' + vim['ip'])
            client = Client(base_url='tcp://'+vim['ip']+':2375',
                            timeout=10)
            app.logger.debug('Conneted with vim, now get list docker Id')
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


# Get the list of vnf started from list of vim
@app.route("/manage_osm_connector/get_list_vnf", methods=["POST"])
def getListVnf():
    app.logger.info('Get list vnf')
    list_vim_vnf = []
    app.logger.info('Get list VIM by ip')
    if request.is_json:
        app.logger.info('Received a json object')
        req_data = request.get_json()
        app.logger.info('The data are: %s' % req_data)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    app.logger.info('VIM list: %s' % req_data)
    try:
        list_vim = req_data['VIM']
        bash_ns_osm = "osm ns-list"
        process_ns_list = Popen(bash_ns_osm.split(),
                                stdout=PIPE, stderr=PIPE)
        output_ns, error = process_ns_list.communicate()
        if not error:
            app.logger.info('Start process to get list ns in execution')
            for line in output_ns.split('\n')[3:-2]:
                app.logger.debug('analyze ns: %s' % line)
                line_split = line.split()
                if len(line_split) > 1 and line_split[5] == 'running':
                    ns = line_split[1]
                    app.logger.debug('ns_name %s' % ns)
                    data = getVnf(ns, list_vim)
                    if data:
                        app.logger.debug('Data: %s added to the list' % data)
                        list_vim_vnf.append(data)
                    else:
                        app.logger.warning('Data is emply impossible to add '
                                           'this item to the list')
        else:
            app.logger.error('Impossible to connect to OSM')
            jsonResponse = {'Impossible to connect to OSM':
                            error.split('\n')[len(error.split('\n'))-2]}
            return jsonResponse
    except KeyError as ke:
        app.logger.error('No exist the list of VIM')
    if not list_vim_vnf:
        app.logger.warning('No ns in running on OSM')
    jsonResponse = {'vim_vnf': list_vim_vnf}
    return flask.Response(json.dumps(jsonResponse))


def getVnf(ns, list_vim):
    app.logger.info(list_vim)
    vnfd = False
    list_vnf = []
    vim_vnf = {}
    app.logger.debug('Analyze ns_name %s' % ns)
    bash_ns_show = "osm ns-show %s" % ns
    process_ns_show_list = Popen(bash_ns_show.split(),
                                 stdout=PIPE, stderr=PIPE)
    output_ns_show, error = process_ns_show_list.communicate()
    if not error:
        for line in output_ns_show.split('\n')[3:-2]:
            line_split = line.split()
            if len(line_split) > 1:
                if line_split[2].find("constituent-vnfd") != -1:
                    vnfd = True
                if (vnfd is True
                   and line_split[2].find("vnfd-id-ref") != -1):
                    app.logger.debug('vnf name is %s' % line_split[3])
                    list_vnf.append(line_split[3][1:-1])
                if (line_split[1].find('rw-nsr:datacenter') != -1
                   and line_split[3][1:-1] in list_vim):
                    app.logger.info('si')
                    vim = line_split[3][1:-1]
                    app.logger.debug('Create dictionary with vim ' + vim
                                     + ' and vnfs ' + str(list_vnf))
                    vim_vnf = {'vim': vim, 'list_vnf': list_vnf}
    else:
        app.logger.error('Impossible to connect to OSM')
        jsonResponse = {'Impossible to connect to OSM':
                        error.split('\n')[len(error.split('\n'))-2]}
        return jsonResponse
    app.logger.info(vim_vnf)
    return vim_vnf


# started from list of ip of node to get the name of vim with their ip, if the
# ip are equivalent
@app.route("/manage_osm_connector/get_vim_by_ip", methods=["POST"])
def get_vim_by_ip():
    list_ip = []
    app.logger.info('Get list VIM by ip')
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        app.logger.info('The data are: %s' % data)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    list_ip_by_TM = data['ip']
    list_vim_ip = listVimIp()
    if isinstance(list_vim_ip, list):
        app.logger.info('The list of vim with their ip is %s'
                        % str(list_vim_ip))
        for vim in list_vim_ip:
            app.logger.debug('Analyze vim %s' % str(vim))
            if vim['ip'] not in list_ip_by_TM:
                app.logger.debug('Remove vim to the list')
                list_vim_ip.remove(vim)
    return flask.Response(json.dumps(list_vim_ip))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/manage_osm_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
