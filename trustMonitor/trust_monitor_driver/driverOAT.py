import json
import requests
from trust_monitor.models import Host
from rest_framework.response import Response
from rest_framework import status
from requests.exceptions import ConnectionError
from django.core.exceptions import ObjectDoesNotExist
import logging
from django.conf import settings
import pycassa
import redis
from driver_setting import *
from trust_monitor_driver.defineJsonOAT import JsonSingleHost, JsonListHost
from trust_monitor_driver.informationDigest import MapDigest, InformationDigest

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger('django')
distCassandra = settings.CASSANDRA_LOCATION
port = settings.CASSANDRA_PORT
verifier = settings.OAT_LOCATION
jsonSingleHost = JsonSingleHost()
jsonListHost = JsonListHost()


class DriverOAT():

    headers = {'content-type': 'application/json'}

    def registerNode(self, host):
        logger.info('In registerNode method of driverOAT')
        response = self.confOem()
        if (response.status_code == 500):
            return response
        responseAnalysist = self.confAnalysisType(host)
        if (responseAnalysist.status_code == 400):
            return responseAnalysist
        response1 = self.confOs(host)
        if (response1.status_code == 500):
            return response1
        response2 = self.confMle(host)
        if (response2.status_code == 500):
            return response2
        response3 = self.confHost(host)
        if (response3.status_code == 500):
            return response3
        if response3.status_code == 200:
            response4 = self.confPCR(host)
            if response4.status_code > 200:
                return response4
        else:
            return response3
        return response4

    # if the oem already exists, the value returned of resp.status_code
    # is equals to 400, otherwise the oem is set.
    def confAnalysisType(self, host):
        logger.info('Configure AnalysisType')
        try:
            logger.debug('Define Analysis Type')
            analysis = host.analysisType.split(',')[0]
            url = ('https://' + verifier +
                   ':8443/WLMService/resources/analysisTypes')
            jsonAnalysis = {
                    'name': analysis,
                    'module': 'RAVerifier', 'version': '2',
                    'url': PATH_DRIVER,
                    'deleted': '0',
                    'required_pcr_mask': '000000'}
            resp = requests.post(url, data=json.dumps(jsonAnalysis),
                                 headers=self.headers, verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + 'status_code = 400')
            return Response(error,
                            status=status.HTTP_400_BAD_REQUEST)

    # if the oem already exists, the value returned of resp.status_code
    # is equals to 400, otherwise the oem is set.
    def confOem(self):
        logger.info('Configure Oem')
        try:
            url = 'https://'+verifier+':8443/WLMService/resources/oem'
            jsonOem = {'Name': 'OEM1', 'Description': 'Test id'}
            resp = requests.post(url, data=json.dumps(jsonOem),
                                 headers=self.headers,
                                 verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + ' status_code = 500')
            return Response(error,
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # if the os already exists, the value returned of resp.status_code
    # is equals to 400, otherwise the oem is set.
    def confOs(self, host):
        logger.info('Configure Os')
        try:
            url = 'https://'+verifier+':8443/WLMService/resources/os'
            jsonOs = {'Name': host.distribution, 'Version': 'v1234',
                      'Description': 'Test1'}
            resp = requests.post(url, data=json.dumps(jsonOs),
                                 headers=self.headers, verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + ' status_code = 500')
            return Response(error,
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # if the mle already exists, the value returned of resp.status_code
    # is equals to 400, otherwise the oem is set.
    def confMle(self, host):
        logger.info('Configure MLE')
        try:
            url = 'https://'+verifier+':8443/WLMService/resources/mles'
            jsonMle = {'Name': host.hostName + '-' + host.distribution,
                       'Version': '123', 'OsName': host.distribution,
                       'OsVersion': 'v1234', 'Attestation_Type': 'PCR',
                       'MLE_Type': 'VMM', 'Description': 'Test ad'}
            resp = requests.post(url, data=json.dumps(jsonMle),
                                 headers=self.headers, verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + ' status_code = 500')
            return Response(error,
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def confHost(self, host):
        logger.info('Configure Host')
        try:
            url = ('https://' + verifier +
                   ':8443/AttestationService/resources/hosts')
            jsonHost = {'HostName': host.hostName, 'IPAddress': host.address,
                        'Port': '9999',
                        'VMM_Name': host.hostName + '-' + host.distribution,
                        'VMM_Version': '123', 'VMM_OSName': host.distribution,
                        'VMM_OSVersion': 'v1234',
                        'Email': '', 'AddOn_Connection_String': '',
                        'Description': 'null'}
            resp = requests.post(url, data=json.dumps(jsonHost),
                                 headers=self.headers,
                                 verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + ' status_code = 500')
            return Response(error,
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def confPCR(self, host):
        logger.info('Configure pcr value at host: ' + host.hostName)
        try:
            url = ('https://'+verifier+':8443/WLMService/resources/mles'
                   '/whitelist/pcr')
            jsonPcr0 = {'pcrName': '0', 'pcrDigest': host.pcr0,
                        'mleName': host.hostName + '-' + host.distribution,
                        'mleVersion': '123', 'osName': host.distribution,
                        'osVersion': 'v1234'}
            resp = requests.post(url, data=json.dumps(jsonPcr0),
                                 headers=self.headers,
                                 verify=False)
            logger.debug('Response OAT, url: ' + url)
            logger.debug('Status = ' + str(resp.status_code))
            logger.debug('Message: ' + str(resp.text))
            return resp
        except ConnectionError as e:
            error = {'Error impossible to contact': url}
            logger.error('Error: ' + str(error) + ' status_code = 500')
            return Response(error,
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def pollHost(self, node_list):
        logger.info('In pollHost method in driverOAT')
        url = ('https://'+verifier+':8443/AttestationService/resources'
               '/PollHosts')
        listResult = []
        attest = 'trusted'
        for n in node_list:
            logger.info('Analyze node: ' + n['node'])
            listvnf = ''
            try:
                logger.debug('Define list of vnfs for node: '
                             + n['node'])
                for vnf in n['vnfs']:
                    listvnf += vnf + '+'
            except KeyError as keyErr:
                logger.warning('No vnf for node: ' + n['node']
                               + " vnfs set to ''")
            if (listvnf != ""):
                listvnf = listvnf[:-1]
                logger.info('Vnfs for node: ' + n['node'] + ' are: '
                            + str(listvnf))
            try:
                logger.debug('Search node: ' + n['node']
                             + ' in the database of Django')
                host = Host.objects.get(hostName=n['node'])
                InformationDigest.host = n['node']
                logger.info('Node found ' + host.hostName + ' with '
                            'this analysisType: ' + host.analysisType
                            + listvnf)
                jsonAttest = {'hosts': [host.hostName],
                              'analysisType': host.analysisType + listvnf}
                logger.debug('Define json object %s to be sent to OAT '
                             'to perform attestation' % jsonAttest)
                respo = requests.post(url, data=json.dumps(jsonAttest),
                                      headers=self.headers, verify=False)
                jsonResponse = json.loads(respo.text)['hosts']
                for jsonElem in jsonResponse:
                    vtime = jsonElem['vtime']
                    if attest == 'trusted':
                        attest = jsonElem['trust_lvl']
                jsonHost = self.createSingleJson(respo=respo, host=host)
                listResult.append(jsonHost)
                logger.debug('New json object: %s', jsonHost)
                try:
                    del MapDigest.mapDigest[host.hostName]
                except KeyError as ke:
                    logger.warning('Node %s no in map' % host.hostName)
                InformationDigest.host = ''
            except ObjectDoesNotExist as objDoesNotExist:
                errorHost = {'Error host not found': n['node']}
                logger.error('Error: ' + str(errorHost))
                return Response(errorHost,
                                status=status.HTTP_404_NOT_FOUND)
            except ConnectionError as connErr:
                error = {'Error impossible to contact': url}
                logger.error('Error: ' + str(error))
                return Response(error,
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if attest == 'timeout':
            attest = 'untrusted'
        jsonAllNFVI = jsonListHost.defineListHosts(listHost=listResult,
                                                   vtime=vtime,
                                                   trust_lvl=attest)
        return jsonAllNFVI

    def createSingleJson(self, respo, host):
        createJson = jsonSingleHost.defineSingleHost(
                respo, MapDigest.mapDigest, host)
        return createJson

    def getStatus(self):
        logger.info('Get Status of Driver OAT')
        message = []
        try:
            url = 'https://'+verifier+':8443/WLMService/resources/oem'
            logger.debug('Try to contact OAT on %s' % url)
            resp = requests.get(url, verify=False, timeout=5)
            logger.debug('Status = ' + str(resp.status_code))
            message_oat = {'Driver OAT works': True}
            logger.info('%s' % str(message_oat))
            message.append(message_oat)
        except ConnectionError as e:
            error_oat = {'Driver OAT works': False}
            logger.error('Error impossible to contact OAT %s' % e)
            message.append(error_oat)
        return message
