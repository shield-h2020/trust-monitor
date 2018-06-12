import logging

logger = logging.getLogger('django')


class InformationDigest():
    def __init__(self):
        self.list_not_found = []
        self.list_fake_lib = []
        self.n_digests_ok = 0
        self.n_digests_not_found = 0
        self.n_digests_fake_lib = 0
        self.list_containers = ""
        self.list_prop_not_found = []
        # packages stats
        self.host = ""
        self.n_packages_ok = 0
        self.n_packages_security = 0
        self.n_packages_not_security = 0
        self.n_packages_unknown = 0

    def __del__(self):
        logger.debug('Delete information Digest object')
        self.list_not_found = []
        self.list_fake_lib = []
        self.list_containers = ""
        self.host = ""
        self.list_prop_not_found = []
        self.n_digests_not_found = 0
        self.n_digests_ok = 0
        self.n_digests_fake_lib = 0
        self.n_packages_ok = 0
        self.n_packages_security = 0
        self.n_packages_not_security = 0
        self.n_packages_unknown = 0


class MapDigest():
    mapDigest = {}
