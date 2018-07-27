from trust_monitor.serializer import *
from trust_monitor.models import Host, KnownDigest
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import json
import requests
import logging
from trust_monitor.verifier.instantiateDB import DigestListUpdater
from django.core.exceptions import ObjectDoesNotExist
from trust_monitor.engine import (
    attest_nodes,
    get_connectors_status,
    get_drivers_status,
    get_databases_status,
    register_node
)
from trust_monitor_driver.driverConstants import *
import urlparse


logger = logging.getLogger('django')

# Create your views here.


class RegisterNode(APIView):
    """
    API provides several REST methods to manage registered nodes.
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
                         'distribution': '', 'pcr0': '', 'driver': '',
                         'analysisType': ''}
        Return:
            - The host created
            - Message Error
        """
        try:
            logger.info('Call post method of register_node to register new '
                        'node')
            serializer = HostSerializer(data=request.data)
            if serializer.is_valid():
                logger.debug('Serialization of host is valid')
                newHost = Host(hostName=request.data["hostName"],
                               address=request.data["address"],
                               driver=request.data['driver'],
                               distribution=request.data['distribution'])

                register_node(newHost)
                serializer.save()
                return Response(serializer.data,
                                status=status.HTTP_201_CREATED)
            else:
                logger.error('Serializaton generated an error ' +
                             str(serializer.errors))
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error('Error occurred while registrering node: ' + str(ex))
            return Response(
                str(ex), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, format=None):
        """
        This method return a Response that can include an error or an ok status
        This is a delete method which uses a json object to remove a registered
        node from the TM database.
        The json object is formed by one parameter, that parameter is
        mandatory.
        The parameter of json object is: hostName.

        Example: call basic-url/register_node delete and include
        json with the previous value, the result indicates if the removed was
        successful or if there was an error.

        Args:
            json object {'hostName': 'nfvi-node'}
        Return:
            - The node is unregistered from the TM application
            - Message Error
        """
        logger.info('Call delete method of RegisterNode to remove a node')
        logger.info(request.data)
        serializer = VerificationDeleteRegisteredNode(data=request.data)
        if serializer.is_valid():
            logger.debug('Serialization of digest is valid')
            logger.info('See if the node exists in database')
            try:
                host = Host.objects.get(hostName=serializer.data['hostName'])
                host.delete()
                logger.info("Host %s removed from database",
                            host.hostName)
                jsonMessage = {'Host %s' % host.hostName: 'removed'}
                return Response(jsonMessage, status=status.HTTP_200_OK)
            except ObjectDoesNotExist as objDoesNotExist:
                logger.info('Host not found in database')
                jsonMessage = {'Host %s' % request.data['hostName']:
                               'not found in db'}
                return Response(jsonMessage, status=status.HTTP_403_FORBIDDEN)
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

        try:
            if hasattr(request, 'data'):
                value_data = request.data
            else:
                value_data = request
            serializer = NodeListSerializer(data=value_data)
            if serializer.is_valid():
                node_list = serializer.data["node_list"]
                logger.debug('Serializaton of information valid: '
                             + str(node_list))

                attest_status = attest_nodes(node_list)

                return Response(attest_status.json(), status=status.HTTP_200_OK)
            else:
                logger.error('Serialization generated an error ' +
                             str(serializer.errors))
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error('Error occurred while attesting node: ' + str(e))
            return Response(
                str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AttestNFVI(APIView):
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
        try:
            attest_result = attest_nodes(None)
            return Response(
                attest_status.json(), status=status.HTTP_200_OK)
        except Exception as e:
            logger.error('Error occurred while attesting whole NFVI: ' + str(e))
            return Response(
                str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AttestNFVIPoP(APIView):
    """
    Used to attest one node registered with Trust Monitor.
    """
    def get(self, request, format=None):
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
        try:
            param = request.GET
            logger.debug('The parameter passed to get method are: %s', param)
            serializer = VerificationInputNFVI(data=param)
            if serializer.is_valid():

                logger.debug('Serialization of information is valid')
                node_id = serializer.data['node_id']
                logger.info('Is required the attestation of node %s', node_id)
                logger.debug('Call driver to attest that node')

                attest_result = attest_nodes([node_id])

                return Response(
                    attest_status.json(), status=status.HTTP_200_OK)
            else:
                logger.error('Serialization generate an error: %s',
                             str(serializer.errors))
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error('Error occurred while attesting NFVI node: ' + str(e))
            return Response(
                str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
            logger.debug('Serialization of digest is valid')
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
                DigestListUpdater.append_known_digest(request.data['digest'])
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
            logger.debug('Serialization of digest is valid')
            logger.info('See if the digest already exists in db')
            try:
                digest_found = KnownDigest.objects.get(
                    digest=serializer.data['digest'])
                logger.info('Removed known digest %s %s',
                            digest_found.pathFile, digest_found.digest)
                DigestListUpdater.remove_known_digest(digest_found.digest)
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


class Status(APIView):
    """
    Return the status of TM components in JSON format
    """

    def get(self, request, format=None):
        """
        This method checks if all the components used by Trust Monitor work.
        Example:
        Call basic-url/status

        Args:

        Return:
            - Return a json object that indicates if components in
              Trust Monitor work.
        """
        logger.info('Trust Monitor works')
        logger.info('Call driver to verify if it works')
        message = []
        message.append({'drivers': get_drivers_status()})
        message.append({'connectors': get_connectors_status()})
        message.append({'databases': get_databases_status()})
        return Response(message, status=status.HTTP_200_OK)


class VerifyCallback(APIView):
    """
    Core of control verify module.
    """

    def post(self, request, format=None):
        """
        Post method that includes the verification logic, to see if the host is
        trusted or untrusted (specific for OAT)
        Example:
        Call basic-url/verify_callback post method.

        Args:
            Json object: {"distribution": "CentOS7", "report_url": "url",
                          "report_id", "30", "analysis": "type_analysis"}
        Return:
            - Error if the verification process fails
            - Result of the verification process trusted or untrusted
        """
        logger.info('API verify_callback called by OAT.')
        serializer = VerificationValues(data=request.data)
        if serializer.is_valid():
            distro = serializer.data["distribution"]
            analysis = serializer.data["analysis"]
            report_url = serializer.data["report_url"]
            report_id = serializer.data["report_id"]

            return DriverOAT().verify_callback(
                distro, analysis, report_url, report_id)
        else:
            logger.error('Serialization generated an error ' +
                         str(serializer.errors))
            return Response(2, status=status.HTTP_400_BAD_REQUEST)
        return Response(1, status.HTTP_200_OK)
