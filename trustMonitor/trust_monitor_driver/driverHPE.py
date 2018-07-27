import logging
from driverHPESettings import *
import subprocess
import os
import json
from trust_monitor.models import Host
from rest_framework import status
from trust_monitor.attestation_data import SDNAttestation
from trust_monitor_driver.driverConstants import *


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
        logger.warning(
            'registerNode does not actually register a switch for HPE driver')
        pass

    def getStatus(self):
        """Retrieves the status of the HPE driver
        """
        logger.info('Getting status of HPE driver')
        configured = False
        active = False
        # If configuration is missing, fail
        if not SWITCH_VERIFIER_PATH or not SWITCH_VER_CONFIG_PATH \
                or not SWITCH_PCR_PUB_KEY_PATH or not SWITCH_REF_CONFIG_PATH:
            configured = False
        # Else, config is ok
        else:
            configured = True
            # Check if switchVerifier exists in local path
            if os.path.isfile(SWITCH_VERIFIER_PATH):
                active = True

        return {HPE_DRIVER: {'configuration': configured, 'active': active}}

    def pollHost(self, node):
        """Attests the switch via the HPE driver and returns a JSON with
        attestation result, timestamp and individual results for
        switchVerifier runs.
        """
        logger.info("Attesting node with HPE driver")

        try:
            # Retrieve address of switch
            host = Host.objects.get(hostName=node['node'])
            logger.debug("Node IP address is " + host.address)
            result = runSwitchVerifier(host.address)
            # Load result as json
            jsonResult = json.loads(result)

            attestation_result = SDNAttestation(
                host.hostName,
                extractTrustLevelFromResult(jsonResult),
                jsonResult,
                HPE_DRIVER
            )
            return attestation_result

        except Exception as e:
            logger.error(
                "Exception occurred while attesting node " +
                str(generic_exception))
            return None


def extractTrustLevelFromResult(result):
    """Returns True or Folse depending on the result of the
        JSON parameters in the switchVerifier output

        The result is trusted if both Firmware and OS are correct and up
        to data, and both configuration and SDN Rules match in the switch

    """
    if result["FirmwareLevel"] == 0 \
            and result["OSLevel"] == 0 \
            and result["ConfigurationMatch"] is True \
            and result["SDNRulesMatch"] is True:
        return True
    else:
        return False
