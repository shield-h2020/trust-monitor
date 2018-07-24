from django.conf import settings
import requests
from requests.exceptions import ConnectionError
import logging
import json
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from trust_monitor.models import Host
from django.http import HttpRequest
import redis
import pycassa
from trust_monitor.verifier.structs import *
from trust_monitor.verifier.instantiateDB import *
from rest_framework.response import Response
from trust_monitor_driver.driverOAT import DriverOAT


driver_oat = DriverOAT()

headers = {'content-type': 'application/json'}
distCassandra = settings.CASSANDRA_LOCATION
port = settings.CASSANDRA_PORT

logger = logging.getLogger('django')


def dare_connector(jsonResult):
    logger.info('Send attestation result to DARE connector')
    # send attestation result to DARE_connector
    try:
        url = settings.BASIC_URL_DARE + "/dare_connector/attest_result"
        resp = requests.post(url, data=json.dumps(jsonResult),
                             headers=headers)
        logger.info('Attestation result sent to DARE connector')
        return resp
    except ConnectionError as e:
        error = {'Error impossible to contact': url}
        logger.error('Error: ' + str(error))
        return Response(error,
                        status=status.HTTP_404_NOT_FOUND)


def dashboard_connector(jsonMessage):
    # if (jsonMessage['NFVI'] == 'untrusted'):
    logger.info('Send attestation notification to dashboard connector')
    try:
        url = (
            settings.BASIC_URL_DASHBOARD +
            "/dashboard_connector/attest_notification")
        response = requests.post(url, data=json.dumps(jsonMessage),
                                 headers=headers)
        logger.info('Attestation failed sent to dashboard connector')
        return response
    except ConnectionError as e:
        error = {'Error impossible to contact': url}
        logger.error('Error: ' + str(error))
        return Response(error,
                        status=status.HTTP_404_NOT_FOUND)


def vnsfo_connector():
    logger.info('Start procedure to obtain the list of VIM with '
                'docker and ip')
    url_vnsfo_connector = (
        settings.BASIC_URL_VNSFO +
        'vnsfo/list_vim_instances'
    )
    try:
        vim_ip = requests.get(url_vnsfo_connector).json()
        if type(vim_ip) == dict:
            return Response(vim_ip,
                            status=status.HTTP_404_NOT_FOUND)

        url_vimemu_connector = (
            settings.BASIC_URL_VIMEMU +
            '/vimemu/list_instances')

        responseJson = requests.post(url_vimemu_connector, json=vim_ip).json()
        list_vim = []
        list_vim_docker = responseJson['VIM']
        logger.info('The list of VIM-emu instances are  %s'
                    % str(list_vim_docker))
        attest_list = []
        for vim in list_vim_docker:
            logger.debug('Analyse %s' % vim['vim'])
            ip_vim = vim['ip']
            try:
                logger.debug('Search ip: %s in TM database...'
                             % ip_vim)
                host = Host.objects.get(address=ip_vim)
                logger.debug('Node found ' + host.hostName + ' with ip '
                             + host.address)
                list_vim.append(vim['vim'])
                list_docker_id = vim['docker_id']
                if not list_docker_id:
                    logger.warning('No Docker running in the VIM')
                    jsonAttest = {'node': host.hostName}
                else:
                    logger.debug('With this docker id: %s'
                                 % str(list_docker_id))
                    jsonAttest = {'node': host.hostName, 'vnfs':
                                  list_docker_id}
                attest_list.append(jsonAttest)
                logger.debug("Json to be sent to attest_node %s"
                             % jsonAttest)
            except ObjectDoesNotExist as objDoesNotExist:
                errorHost = {'Error ip not found in trust_monitor': ip_vim}
                logger.warning(errorHost)
    except KeyError as typeE:
        logger.error(responseJson)
        return Response(responseJson,
                        status=status.HTTP_404_NOT_FOUND)
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible to contact vNSFO/VIM-emu connectors'}
        logger.error(jsonError)
        return Response(jsonError,
                        status=status.HTTP_404_NOT_FOUND)
    list_vim_vnf = get_list_vnf(list_vim)
    check_vnfs(list_vim_vnf, list_vim)
    return call_poll_host(attest_list)


def get_list_vnf():
    try:
        logger.info('Call method of vnsfo_connector to get the '
                    'name of vnfs from vim: %s' % str(list_vim))
        url_vnsfo_connector = (
            settings.BASIC_URL_VNSFO +
            'vnsfo/list_vnf_instances'
        )
        responseJson = requests.get(
            url_vnsfo_connector).json()
        logger.info(responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible to contact VNSFO connector'}
        logger.error(jsonError)
        return False


def check_vnfs(list_vim_vnf, list_vim):
    if list_vim_vnf is False:
        logger.warning('Impossible to get the information of vnfs '
                       'for each vim (list of vNSF is empty)')
    if isinstance(list_vim_vnf, dict):
        list_vnf = []
        for vim in list_vim_vnf['vim_vnf']:
            list_vnf.extend(vim['list_vnf'])
        logger.info('All vnfs are %s' % str(list_vnf))
        list_digest = store_vnsfs_digests(list_vnf)
        if list_digest is False:
            logger.warning('Impossible to obtain the list of digest')
        if list_digest:
            value = redis_db(list_digest)
            if value is not True:
                logger.warning('Impossible to communicate with Redis, '
                               'the measure not are added in DB')
    else:
        logger.warning('No vnf for vim: '+str(list_vim)+' are in executions')


def call_poll_host(node_list):
    logger.info('Call pollHost method used to perform the attestation')
    if node_list:
        logger.info('List to be sent to pollHost %s' % str(node_list))
        value = driver_oat.pollHost(node_list)
        return value
    else:
        errorHost = {'Error': 'list to be sent to pollHost are empty'}
        logger.error('Error: ' + str(errorHost))
        return Response(errorHost,
                        status=status.HTTP_404_NOT_FOUND)


# start with list of vnfs obtained of the method get_list_vnf, and for each
# vnf get the list of digest of the manifest called with the same
# name of the vnf
# list_vnf = ['name_vnf', 'name2_vnf']
# return Measures = [{'pathFile': 'digest_of_measure'}]
def store_vnsfs_digests(list_vnf):
    try:
        logger.info('Call method of store_connector to get the digests of '
                    'vnfs')
        urlStore = (settings.BASIC_URL_STORE +
                    '/store_connector/get_vnsfs_digests')
        jsonListVnf = {'list_vnf': list_vnf}
        responseJson = requests.post(urlStore, json=jsonListVnf).json()
        logger.info('Response is %s' % responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to store connector'}
        logger.error(jsonError)
        return False


# Start with list of digest obtained to the method store_vnsfs_digests
# list_digest = [{'pathFile': 'digest_of_measure'}]
def redis_db(list_digest):
    logger.info('Added digest to Redis DB')
    logger.info('list digest %s' % list_digest)
    try:
        from trust_monitor.verifier.instantiateDB import DigestListUpdater
        redisDB = redis.Redis(host='tm_database_redis', port='6379')
        for digest in list_digest:
            for key, value in digest.items():
                data = redisDB.get(key)
                if data is None:
                    logger.debug('The digest is not present in redis')
                    logger.info('Set in redisDB key: '+key+' value: '+value)
                    redisDB.set(key, value)
                    DigestListUpdater.append_known_digest(value)
                else:
                    if data == value:
                        logger.debug('The digest already exist in redis')
                    else:
                        logger.debug('The digest is changed update redis')
                        redisDB(key, value)
                        DigestListUpdater.remove_known_digest(data)
                        DigestListUpdater.append_known_digest(value)
        return True
    except redis.ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to Redis db'}
        logger.warning(jsonError)
        return jsonError
    finally:
        del redisDB


# method used to instantiate the firsh time the lis of known_digests throught
# redis element
def redis_instantiate():
    logger.info('instantiate known_digests with elements in Redis DB')
    list_digest = []
    try:
        redisDB = redis.Redis(host='tm_database_redis', port='6379')
        list_keys = redisDB.keys('*')
        for key in list_keys:
            logger.debug('Added value of key: %s in list' % key)
            value = redisDB.get(key)
            list_digest.append(value)
    except redis.ConnectionError as e:
        jsonError = {'Error', 'Impossible to contact to Redis DB'}
        logger.warning('Impossible included the digests in Redis DB')
        logger.warning(jsonError)
    return list_digest


def attest_node(list_node):
    logger.info('Get ip from nodes')
    logger.info(list_node)
    node_list = []
    list_vim = []
    list_ip = []
    for node in list_node:
        logger.debug('Analyze node %s' % str(node))
        try:
            logger.debug('Verify if node is in trust_monitor')
            host = Host.objects.get(hostName=node['node'])
            logger.debug('Node found with ip %s' % host.address)
            if host.driver == 'OAT':
                if node['vnfs']:
                    logger.info('Add ip address to the list used to'
                                ' communicate with vNSFO connector')
                    list_ip.append(host.address)
                node_list.append(node)
            else:
                errorHost = {'Error node: %s' % host.hostName:
                             'driver not is OAT'}
                logger.warning(errorHost)
        except ObjectDoesNotExist as objDoesNotExist:
            errorHost = {'Error node not registred with trust_monitor':
                         node['node']}
            logger.warning(errorHost)
        except KeyError as keyErr:
            logger.debug('Node discarded because no Docker analysis required.')
            node_list.append(node)
    if list_ip:
        logger.info('The list of ip address are: '+str(list_ip))
        logger.info('Use ip to get vim name used to obtain the name of vnf to '
                    'get the digest from the store connector')
        jsonListIP = {'ip': list_ip}
        url_vnsfo_connector = (
            settings.BASIC_URL_VNSFO +
            'vnsfo/get_vim_by_ip'
        )
        list_info_vim = requests.post(
            url_vnsfo_connector,
            json=jsonListIP).json()
        if list_info_vim and isinstance(list_info_vim, list):
            for vim in list_info_vim:
                list_vim.append(vim['vim'])
            list_vim_vnf = get_list_vnf(list_vim)
            check_vnfs(list_vim_vnf, list_vim)
        else:
            if not list_info_vim:
                logger.warning('The list of vim are empty')
            else:
                logger.warning(list_info_vim)
    else:
        logger.warning('The list of ip are empty')
    if not node_list:
        jsonError = {'Error': 'No node to attest'}
        logger.error(jsonError)
        return Response(jsonError, status=status.HTTP_404_NOT_FOUND)
    # attest process
    return call_poll_host(node_list)


def attest_single_node(node):
    logger.info('Get ip from single node %s' % node)
    list_ip = []
    attest_list = []
    try:
        logger.debug('Verify if node is in trust_monitor')
        host = Host.objects.get(hostName=node)
        logger.debug('Node found with ip %s' % host.address)
        if host.driver != 'OAT':
            errorHost = {'Error node: %s' % node: 'driver not is OAT'}
            logger.warning(errorHost)
            return Response(errorHost, status=status.HTTP_403_FORBIDDEN)
        list_ip.append(host.address)
        logger.info('Use ip to get vim name')
        jsonListIP = {'ip': list_ip}
        url_vnsfo_connector = (
            settings.BASIC_URL_VNSFO +
            'vnsfo/get_vim_by_ip'
        )
        list_info_vim = requests.post(
            url_vnsfo_connector,
            json=jsonListIP).json()
        if list_info_vim and isinstance(list_info_vim, dict):
            logger.warning(list_info_vim)
            return Response(list_info_vim,
                            status=status.HTTP_404_NOT_FOUND)
        logger.info(list_info_vim)
        url_vimemu_connector = (
            settings.BASIC_URL_VIMEMU +
            '/vimemu/list_instances')
        responseJson = requests.post(
            url_vimemu_connector,
            json=list_info_vim).json()
        list_vim_docker = responseJson['VIM']
        logger.info('The information are %s'
                    % str(list_vim_docker))
        list_docker_id = list_vim_docker[0]['docker_id']
        if not list_docker_id:
            logger.warning('No docker in running')
            jsonAttest = {'node': host.hostName}
        else:
            logger.debug('With this docker id: %s'
                         % str(list_docker_id))
            jsonAttest = {'node': host.hostName, 'vnfs':
                          list_docker_id}
        attest_list.append(jsonAttest)
    except ObjectDoesNotExist as objDoesNotExist:
        errorHost = {'Error node not registred with trust_monitor': node}
        logger.warning(errorHost)
        return Response(errorHost, status=status.HTTP_404_NOT_FOUND)
    except KeyError as typeE:
        logger.error(responseJson)
        return Response(responseJson,
                        status=status.HTTP_404_NOT_FOUND)
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible to contact vNSFO/VIMEMU connector'}
        logger.error(jsonError)
        return Response(jsonError,
                        status=status.HTTP_404_NOT_FOUND)

    list_vim_vnf = get_list_vnf(list_info_vim[0]['vim'])
    check_vnfs(list_vim_vnf, list_info_vim)
    return call_poll_host(attest_list)


def get_status_connectors(message):
    logger.info('Get status of connectors')
    logger.debug('Verify if Cassandra works at: ' + distCassandra + ':' +
                 port)
    try:
        pool = pycassa.ConnectionPool('system', [distCassandra + ':' +
                                                 port])
        pool.dispose()
        message_cass = {'Cassandra works': True}
        logger.info('%s' % str(message_cass))
        message.append(message_cass)
    except pycassa.pool.AllServersUnavailable as e:
        logger.error('Cassandra do not work')
        error_cass = {'Cassandra works': False}
        message.append(error_cass)
    urlDare = settings.BASIC_URL_DARE + '/dare_connector'
    nameConnector = 'DARE'
    getStatusConnector(message, urlDare, nameConnector)
    urlDashboard = settings.BASIC_URL_DASHBOARD + '/dashboard_connector'
    nameConnector = 'Dashboard'
    getStatusConnector(message, urlDashboard, nameConnector)
    urlVNSFO = settings.BASIC_URL_VNSFO + '/vnsfo_connector'
    nameConnector = 'VNSFO'
    getStatusConnector(message, urlVNSFO, nameConnector)
    urlVIMEMU = settings.BASIC_URL_VIMEMU + '/vimemu_connector'
    nameConnector = 'VIMEMU'
    getStatusConnector(message, urlVIMEMU, nameConnector)
    urlStore = settings.BASIC_URL_STORE + '/store_connector'
    nameConnector = 'Store'
    getStatusConnector(message, urlStore, nameConnector)
    getStatusRedis(message)
    return Response(message, status=status.HTTP_200_OK)


def getStatusConnector(message, urlConnector, nameConnector):
    logger.debug('Verify if connector ' + nameConnector + ' works')
    try:
        logger.debug('Try to contact ' + nameConnector +
                     ' connector on %s' % urlConnector)
        resp = requests.get(urlConnector)
        logger.debug('Status = ' + str(resp.status_code))
        mess = {nameConnector + ' connector works': True}
        logger.info('%s' % str(mess))
        message.append(mess)
    except ConnectionError as e:
        error = {nameConnector + ' connector works': False}
        logger.error('Error impossible to contact ' + nameConnector +
                     ' connector')
        message.append(error)


def getStatusRedis(message):
    logger.debug('Verify if redis works')
    try:
        redisDB = redis.Redis('tm_database_redis', '6379')
        redisDB.ping()
        mess = {'Redis works': True}
        logger.info(mess)
        message.append(mess)
    except redis.ConnectionError as e:
        error = {'Redis works': False}
        logger.error('Error impossible to contact Redis')
        message.append(error)
    finally:
        del redisDB
