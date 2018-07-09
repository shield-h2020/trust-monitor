import logging
from driverHPESettings import *
import subprocess
import os
import json
from trust_monitor.models import Host
from rest_framework.response import Response
from rest_framework import status
import time

logger = logging.getLogger('django')


def runSwitchVerifier(node_address):
    """Wrap the SwitchVerifier binary.

    Configuration parameters of the switchVerifier binary are retrieved
    from the driverHPESettings class.
    """

    logger.debug("Running switchVerifier binary")
    # Run switchVerifier -c config.json -k pub.key -conf refconf -json [ip_addr]
    args = (SWITCH_VERIFIER_PATH,
            "-c",
            SWITCH_VER_CONFIG_PATH,
            "-k",
            SWITCH_PCR_PUB_KEY_PATH,
            "-conf",
            SWITCH_REF_CONFIG_PATH,
            "-json",
            node_address)

    logger.debug("SwitchVerifier run with args: " + str(args))
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    logger.debug("SwitchVerifier returned output: " + output)
    return output


class DriverHPE():
    """Class that enables SDN switch and controller verification in
    Trust Monitor.
    """

    def registerNode(self, host):
        """Registers the switch in the TM database

        The Driver is called each time a node is registered for "HPESwitch"
        attestation framework.
        """
        logger.info("Registering node for HPE driver")
        logger.warning('registerNode does not actually register a switch for HPE driver')
        pass

    def getStatus(self, message):
        """Retrieves the status of the HPE driver
        """
        logger.info('Getting status of HPE driver')

        # If configuration is missing, fail
        if not SWITCH_VERIFIER_PATH or not SWITCH_VER_CONFIG_PATH \
                or not SWITCH_PCR_PUB_KEY_PATH or not SWITCH_REF_CONFIG_PATH:
            message.append({'Driver HPE configured:':  False})
        # Else, config is ok
        else:
            message.append({'Driver HPE configured:': True})
            # Check if switchVerifier exists in local path
            if os.path.isfile(SWITCH_VERIFIER_PATH):
                message.append({'Driver HPE works:': True})
            # If it does not, fail
            else:
                message.append({'Driver HPE works:': False})

        return message

    def pollHost(self, node_list):
        """Attests the switch via the HPE driver and returns a JSON with
        global attestation result, timestamp and individual results for
        switchVerifier runs.

        As follows, an example of the parameter node_list value in case of
        multiple HPESwitch nodes
        {"node_list": [{"node": "switch_1"}, {"node": "switch_2"}]}
        """
        logger.info("Attesting node(s) with HPE driver")
        logger.debug("Node list is: " + str(node_list))

        attestationResults = []
        trust_level = "trusted"

        # In case of multiple nodes (switches), run the SwitchVerifier script
        # for each one of them
        for node_obj in node_list:
            try:
                # Retrieve address of each node
                host = Host.objects.get(hostName=node_obj['node'])
                logger.debug("Node IP address is " + host.address)
                result = runSwitchVerifier(host.address)

                # Load result as json and append it to list
                jsonResult = json.loads(result)
                trust_level = extractTrustLevelFromResult(jsonResult)
                attestationResults.append(jsonResult)

            except ValueError as not_json:
                logger.error("Attestation result is not a JSON")
                error = {'ValueError': not_json.message}
                return Response(error,
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as generic_exception:
                logger.error("Exception occurred while attesting node " + str(generic_exception))
                error = {'Exception': generic_exception.message}
                return Response(error,
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        jsonHosts = {
                    "NFVI": trust_level,
                    "vtime": getTime(),
                    "details": attestationResults
                    }

        logger.debug("Final HPE driver attestation result: " + str(jsonHosts))
        return jsonHosts


def extractTrustLevelFromResult(result):
    """Returns 'trusted' or 'untrusted' string depending on the result of the
        JSON parameters in the switchVerifier output

        The result is trusted if both Firmware and OS are correct and up
        to data, and both configuration and SDN Rules match in the switch

    """
    if result["FirmwareLevel"] == 0 and result["OSLevel"] == 0 \
        and result["ConfigurationMatch"] == True and result["SDNRulesMatch"] == True:
        return "trusted"
    else:
        return "untrusted"

def getTime():
    """Returns current time as integer
    """
    return int(round(time.time()*1000))
