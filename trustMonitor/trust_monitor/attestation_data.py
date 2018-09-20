from datetime import datetime
import logging

logger = logging.getLogger('django')


class AttestationStatus():
    def __init__(self):
        self.vtime = self.get_current_time()
        self.trust = True
        self.list_host_attestation = []
        self.list_sdn_attestation = []

    def get_current_time(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f %Z")

    def getTime(self):
        return self.vtime

    def isTrusted(self):
        return self.trust

    def update(self, attestation):
        if isinstance(attestation, HostAttestation):
            logger.debug("Update global attestation status with Host info")
            if not attestation.trust:
                logger.debug("Trust status changed to False")
                self.trust = False
            self.list_host_attestation.append(attestation)
        elif isinstance(attestation, SDNAttestation):
            logger.debug("Update global attestation status with SDN info")
            if not attestation.trust:
                logger.debug("Trust status changed to False")
                self.trust = False
            self.list_sdn_attestation.append(attestation)
        else:
            logger.error(
                "Impossible to update attestation status (unknown)")
            self.trust = False
        self.vtime = self.get_current_time()

    def json(self):
        # Create list of JSON HostAttestation objects
        list_json_hosts_attest = []
        for host_attest_data in self.list_host_attestation:
            if isinstance(host_attest_data, HostAttestation):
                list_json_hosts_attest.append(host_attest_data.json())
        list_json_sdn_attest = []
        for sdn_attest_data in self.list_sdn_attestation:
            if isinstance(sdn_attest_data, SDNAttestation):
                list_json_sdn_attest.append(sdn_attest_data.json())

        return {
            "trust": self.trust,
            "vtime": self.vtime,
            "hosts": list_json_hosts_attest,
            "sdn": list_json_sdn_attest
        }


class SDNAttestation():
    def __init__(
            self,
            node='',
            trust=True,
            analysis_extra_info=None,
            driver=''):

        self.node = node
        self.trust = trust
        self.analysis_extra_info = analysis_extra_info
        self.driver = driver

    def json(self):
        return {
            'node': self.node,
            'trust': self.trust,
            'extra_info': self.analysis_extra_info,
            'driver': self.driver}


class HostAttestation():
    def __init__(
            self,
            node='',
            trust=True,
            analysis_status=0,
            analysis_extra_info=None,
            analysis_containers=None,
            driver=''):
        self.node = node
        self.trust = trust
        self.analysis_status = analysis_status
        self.analysis_extra_info = analysis_extra_info
        self.analysis_containers = analysis_containers
        self.driver = driver
        self.time = self.get_current_time()

    def get_current_time(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f %Z")

    def json(self):

        # Create list of JSON ContainerAttestation objects
        list_json_vnsfs_attest = []
        for cont_attest_data in self.analysis_containers:
            if isinstance(cont_attest_data, ContainerAttestation):
                list_json_vnsfs_attest.append(cont_attest_data.json())

        # Convert HostAttestationExtraInfo object in JSON
        json_extra_info = {}
        if isinstance(self.analysis_extra_info, HostAttestationExtraInfo):
            json_extra_info = self.analysis_extra_info.json()

        return {
            'node': self.node,
            'trust': self.trust,
            'time': self.time,
            'status': self.analysis_status,
            'extra_info': json_extra_info,
            'vnsfs': list_json_vnsfs_attest,
            'driver': self.driver}


class HostAttestationExtraInfo():
    def __init__(
            self,
            n_digests_ok=0,
            n_digests_not_found=0,
            n_digests_fake_lib=0,
            digest_list_not_found=None,
            digest_list_fake_lib=None,
            n_packages_ok=0,
            n_packages_security=0,
            n_packages_unknown=0,
            n_packages_not_security=0):
        self.n_digests_ok = n_digests_ok
        self.n_digests_not_found = n_digests_not_found
        self.n_digests_fake_lib = n_digests_fake_lib
        self.digest_list_not_found = digest_list_not_found
        self.digest_list_fake_lib = digest_list_fake_lib
        self.n_packages_ok = n_packages_ok
        self.n_packages_security = n_packages_security
        self.n_packages_unknown = n_packages_unknown
        self.n_packages_not_security = n_packages_not_security

    def json(self):
        return {
            'n_digests_valid': self.n_digests_ok,
            'n_digests_not_found': self.n_digests_not_found,
            'n_digests_fake_lib': self.n_digests_fake_lib,
            'list_digests_not_found': self.digest_list_not_found,
            'list_digests_fake_lib': self.digest_list_fake_lib,
            'n_packages_valid': self.n_packages_ok,
            'n_packages_security': self.n_packages_security,
            'n_packages_unknown': self.n_packages_unknown,
            'n_packages_not_security':
            self.n_packages_not_security
        }


class ContainerAttestation():
    def __init__(self, container='', trust=True, vnf_id='', vnf_name=''):
        self.container = container
        self.trust = trust
        self.vnf_id = vnf_id
        self.vnf_name = vnf_name

    def json(self):
        return {
            'vnf_id': self.vnf_id,
            'vnf_name': self.vnf_name,
            'container': self.container,
            'trust': self.trust
        }
