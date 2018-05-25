from trust_monitor.serializer import HostSerializer, ResultSerializer
from trust_monitor.serializer import NodeListSerializer, VerificationValues
from trust_monitor.serializer import VerificationInputNFVI, DigestSerializer
from trust_monitor.serializer import DigestRemoved
from trust_monitor.models import Host, KnownDigest
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import json
import requests
import logging
from trust_monitor.verifier.ra_verifier import RaVerifier
from trust_monitor.verifier import structs
from django.core.exceptions import ObjectDoesNotExist
from trust_monitor.engine import dare_connector, attest_single_node
from trust_monitor.engine import manage_osm_vim_docker, attest_node
from trust_monitor.engine import dashboard_connector, get_status_connectors

if (settings.ATTESTATION_FRAMEWORK == 'OAT'):
    from trust_monitor_driver.driverOAT import Driver
    driver = Driver()

logger = logging.getLogger('django')

# Create your views here.


class RegisterNode(APIView):
    """
    List of all physical host or register new host, this class has two
    methods, a get methods to see list of all node register with
    Trust Monitor and
    post method used to register a new host.
    """

    def get(self, request, format=None):
        """
        This method return a list of all physical host already register
        with Trust Monitor.
        Example of use of this method is:
        Call basic-url/register_node without parameters and it
        return a list of all hosts register to Trust Monitor.

        Args:

        Return:
            - List of all node registered to Trust Monitor
        """
        logger.info('Call api register_node, to see all hosts')
        hosts = Host.objects.all()
        serializer = HostSerializer(hosts, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        """
        This method return a Response that can include an error or an ok status
        This is a post method which uses a json object to perform
        registration procedures.
        The json object is formed by four parameters, all these parameters are
        mandatory.
        The parameters of json object are: distribution, address, hostName and
        pcr0.
        Distribution define a definition of OS of host.
        hostName is the name of host and address is the IP address associated
        with the host, pcr0 is the value of first item of TPM of the host.
        Example: call basic-url/register_node post
        and include json with the previous values, the result indicates
        if the registration was successful or if there was an error.

        Args:
            json object {'hostName': '', 'address': '',
                         'distribution': '', 'pcr0': ''}
        Return:
            - The host created
            - Message Error
        """
        logger.info('Call post method of register_node to register new '
                    'node')
        serializer = HostSerializer(data=request.data)
        if serializer.is_valid():
            logger.debug('Serialization of host is valide, the new node '
                         'have all information')
            newHost = Host(hostName=request.data["hostName"],
                           address=request.data["address"],
                           pcr0=request.data["pcr0"],
                           distribution=request.data["distribution"])
            logger.info('The information of the node are:')
            logger.info('Name: ' + newHost.hostName)
            logger.info('Address: ' + newHost.address)
            logger.info('Pcr0: ' + newHost.pcr0)
            logger.info('Distribution: ' + newHost.distribution)
            logger.info('Call driver to manage new host')
            response = driver.registerNode(newHost)
            logger.debug('Return from the driver:')
            if (response.status_code == 200):
                logger.debug('Response return a status_code = 200, host '
                             'is created')
                serializer.save()
                logger.info('Save node in the database of Django')
                return Response(serializer.data,
                                status=status.HTTP_201_CREATED)
            elif (response.status_code == 400):
                logger.error('Response return a status_code = 400, this '
                             'means that we received an error in the '
                             'attestation framework')
                logger.error(json.loads(response.text))
                return Response(json.loads(response.text),
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                logger.error('Response has status_code = '
                             + str(response.status_code)
                             + ' with message: ' + str(response.data))
                return Response(response.data,
                                status=response.status_code)
        else:
            logger.error('Serializaton generated an error ' +
                         str(serializer.errors))
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class AttestNode(APIView):
    """
    List of all Result AttestNode or execution of a new attestation if
    the node is previously registered to Trust Monitor.
    """

    def post(self, request, format=None):
        """
        Used to request execution of the attestation process for a node.
        Example:
        Call basic-url/attest_node with post method and define
        json object.
        The json object is formed by a list of node with a respective
        containers.

        Args:
            json object:
                {"node_list": [{"node": "example1", "vnfs": ["cont1"]},
                               {"node": "example2"}]}
            where: node define the name of the host and for each node is
            possible define a list of vnfs which represents the list of
            containers
        Return:
            - Possible error during the Attestation
            - The result of the attestation.
        """
        logger.info('Call post method of attest_node to attest '
                    'one or mode node')
        if hasattr(request, 'data'):
            value_data = request.data
        else:
            value_data = request
        serializer = NodeListSerializer(data=value_data)
        if serializer.is_valid():
            node_list = value_data["node_list"]
            logger.debug('Serializaton of information passed of post '
                         'method are valide, the information are: '
                         + str(node_list))
            logger.debug('Call driver to manage the attest node')
            response = attest_node(node_list)
            if (type(response) != dict):
                logger.error('Get object type response')
                logger.error('Response status_code = '
                             + str(response.status_code))
                logger.error('Information: ' + str(response.data))
                dare_connector(response.data)
                return Response(response.data,
                                status=response.status_code)
            else:
                dare_connector(response)
                dashboard_connector(response)
                logger.info('Response status_code = 200')
                logger.info('Result: ' + str(response))
                return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error('Serialization generated an error ' +
                         str(serializer.errors))
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class StatusTrustMonitor(APIView):
    """
    Return status of trust Monitor used to verify if all component work.
    """

    def get(self, request, format=None):
        """
        This method checks if all the components used by Trust Monitor work.
        Example:
        Call basic-url/get_status_info

        Args:

        Return:
            - Return a json object that indicates if components in
              Trust Monitor work.
        """
        logger.info('Trust Monitor works')
        logger.info('Call driver to verify if it works')
        message = driver.getStatus()
        response = get_status_connectors(message)
        return Response(response.data, status=response.status_code)


class GetVerify(APIView):
    """
    Core of control verify module.
    """

    def post(self, request, format=None):
        """
        Post method that includes the verification logic, to see if the host is
        trusted or untrusted.
        Example:
        Call basic-url/get_verify post method.

        Args:
            Json object: {"distribution": "CentOS7", "report_url": "url",
                          "report_id", "30", "analysis": "type_analysis"}
        Return:
            - Error if the verification process fails
            - Result of the verification process trusted or untrusted
        """
        logger.info('API get_verify called by OAT.')
        serializer = VerificationValues(data=request.data)
        if serializer.is_valid():
            distro = request.data["distribution"]
            analysis = request.data["analysis"]
            report_url = request.data["report_url"]
            report_id = request.data["report_id"]
            logger.debug('Serializaton of information passed of post '
                         'method are valide, the information are: \n'
                         'Distro: %s, Analysis: %s, Report_url: %s, '
                         'Report_id: %s', distro, analysis, report_url,
                         report_id)
            logger.info('Call verifier method of RaVerifier')
            ra_verifier = RaVerifier()
            result = ra_verifier.verifier(distro=distro, analysis=analysis,
                                          report_id=report_id,
                                          report_url=report_url)
            logger.debug('Return of method and result is: %s', result)
            if result is True:
                result = 0
            elif result is False:
                result = 1
            return Response(int(result), status=status.HTTP_200_OK)
        else:
            res = 2
            logger.error('Serialization generated an error ' +
                         str(serializer.errors))
            return Response(res, status=status.HTTP_400_BAD_REQUEST)


class AttestAllNFVI(APIView):
    """
    Used to attest all nodes registered with Trust Monitor.
    """

    def get(self, request, format=None):
        """
        This method is used to attest all nodes register to Trust Monitor.
        Example:
            Call https://trust-monitor.it/get_nfvi_attestation_info get method.
        Args:

        Return:
            json object: {
                          "NFVI": "trusted/untrusted",
                          "vtime": "time of attestation"
                          [
                            {"node":"Node1",
                             "trust_lvl":"trusted/untrusted/timeout"
                             "analysis_status": "COMPLETED"}
                          ]
                         }
            where:
            All_NFVI is trusted if all node are trusted otherwise no.
            vtime is the time of attestation.
            And there are a list of node, that define in detail if node for
            example "Node1" is trusted or not.
        """
        logger.info('Call this method to attest all node register to Trust'
                    ' Monitor')
        logger.debug('Call driver to manage all nodes running in this time')
        result = manage_osm_vim_docker()
        if (type(result) != dict):
            logger.error('Get object type response')
            logger.error('Response status_code = '
                         + str(result.status_code))
            logger.error('Information: ' + str(result.data))
            dare_connector(result.data)
            return Response(result.data,
                            status=result.status_code)
        else:
            dare_connector(result)
            dashboard_connector(result)
            logger.debug('Get object type list')
            logger.info('Response status_code = 200')
            logger.info('Result: ' + str(result))
            return Response(result, status=status.HTTP_200_OK)


class AttestNFVI(APIView):
    """
    Used to attest one node registered with Trust Monitor.
    """
    def get(self, reques, format=None):
        """
        This method is used to attest one node which is registered with
        Trust Monitor.
        Example:
            Call basic-url/get_nfvi_pop_attestation_info get
            method with one parameter: node_id = 'name of node'
        Args:
            Name of node to attest.
        Return:
            json object: {
                            "node_id": "name of node",
                            "trust_lvl": "trusted/untrusted/timeout",
                            "vtime": "time of attestation",
                            "analysis_status": "COMPLETED/ERROR"
                         }
        """
        logger.info('Call this method to attest one node reigstered with '
                    'Trust Monitor.')
        param = reques.GET
        logger.debug('The parameter passed to get method are: %s', param)
        serializer = VerificationInputNFVI(data=param)
        if serializer.is_valid():
            logger.debug('Serialization of information are valide')
            node_id = serializer.data['node_id']
            logger.info('Is required the attestation of node %s', node_id)
            logger.debug('Call driver to attest that node')
            result = attest_single_node(node_id)
            if (type(result) != dict):
                logger.error('Get object type response')
                logger.error('Response status_code = '
                             + str(result.status_code))
                logger.error('Information: ' + str(result.data))
                dare_connector(result.data)
                return Response(result.data,
                                status=result.status_code)
            else:
                dare_connector(result)
                dashboard_connector(result)
                logger.debug('Get object type list')
                logger.info('Response status_code = 200')
                logger.info('Result: ' + str(result))
                return Response(result, status=status.HTTP_200_OK)
        else:
            logger.error('Serialization generate an error: %s',
                         str(serializer.errors))
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class Known_Digest(APIView):
    """
    List of all known digest used to complete the attestation process.
    Three methods: get method used to get the list of known digest
     post method used to add new known digest and delete method used to delete
     a digest on list of known digest.
    """

    def get(self, request, format=None):
        """
        This method return a list of all known digest.
        Example of use of this method is:
        Call basic-url/known_digests

        Args:

        Return:
            - List of all known digest
        """
        logger.info('Call api known_digests, to see all digest')
        list_digest = KnownDigest.objects.all()
        serializer = DigestSerializer(list_digest, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        """
        This method return a Response that can include an error or an ok status
        This is a post method which uses a json object to added digest in the
        list of known digest.
        The json object is formed by two parameters, these parameters are
        mandatory.
        The parameters of json object are: PathFile and Digest.
        PathFile is the the complete path of the file.
        Digest is the value sha1 associated with the PathFile.
        Example: call basic-url/known_digests post
        and include json with the previous values, the result indicates
        if the added was successful or if there was an error.

        Args:1
            json object {'pathFile': '/usr/bin/test',
                         'digest': 'sha1(/usr/bin/test)'}
        Return:
            - The known digest created
            - Message Error
        """
        logger.info('Call post method of KnownDigest to added new '
                    'digest')
        serializer = DigestSerializer(data=request.data)
        if serializer.is_valid():
            logger.debug('Serialization of digest is valide, '
                         'have all information')
            logger.info('See if the digest already exists in db')
            try:
                digest_found = KnownDigest.objects.get(
                    digest=request.data['digest'])
                logger.error('Digest already exists in the database')
                jsonMessage = {'Digest %s' % request.data['digest']:
                               'already exists'}
                return Response(jsonMessage, status=status.HTTP_403_FORBIDDEN)
            except ObjectDoesNotExist as objDoesNotExist:
                logger.info('Digest not found in database')
                logger.debug('The information are: PathFile %s and Digest %s',
                             request.data['pathFile'],
                             request.data['digest'])
                logger.info('Added digest at list of known_digests'
                            ' in structs.py file')
                structs.appendKnown_digest(request.data['digest'])
                serializer.save()
                logger.info('Save digest in the database of Django')
                return Response(serializer.data,
                                status=status.HTTP_201_CREATED)
        else:
            logger.error('Serializaton generated an error ' +
                         str(serializer.errors))
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, format=None):
        """
        This method return a Response that can include an error or an ok status
        This is a delete method which uses a json object to removed digest
        in the list of known digest.
        The json object is formed by one parameter, that parameter is
        mandatory.
        The parameter of json object is: Digest.
        Digest is the value sha1 associated with the PathFile.
        Example: call basic-url/known_digests delete and include
        json with the previous value, the result indicates if the removed was
        successful or if there was an error.

        Args:
            json object {'digest': 'sha1(/usr/bin/test)'}
        Return:
            - The known digest is deleted by the list of digest.
            - Message Error
        """
        logger.info('Call delete method of KnownDigest to removed a '
                    'digest')
        logger.info(request.data)
        serializer = DigestRemoved(data=request.data)
        if serializer.is_valid():
            logger.debug('Serialization of digest is valide, '
                         'have all information')
            logger.info('See if the digest already exists in db')
            try:
                digest_found = KnownDigest.objects.get(
                    digest=request.data['digest'])
                logger.info('Removed known digest %s %s',
                            digest_found.pathFile, digest_found.digest)
                structs.removedKnown_digest(digest_found.digest)
                digest_found.delete()
                logger.info("Digest %s removed from django db",
                            digest_found.digest)
                jsonMessage = {'Digest %s' % digest_found.digest: 'removed'}
                return Response(jsonMessage, status=status.HTTP_200_OK)
            except ObjectDoesNotExist as objDoesNotExist:
                logger.info('Digest not found in database')
                jsonMessage = {'Digest %s' % request.data['digest']:
                               'not found in db'}
                return Response(jsonMessage, status=status.HTTP_403_FORBIDDEN)
        else:
            logger.error('Serializaton generated an error ' +
                         str(serializer.errors))
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)
