###############################################################################
# Configuration file for the HPE switch attestation driver
###############################################################################

# Path of the switchVerifier binary on the system
SWITCH_VERIFIER_PATH = '/switchVerifier/TM_network_verifier'
# Path of the switchVerifier config.json configuration file
SWITCH_VER_CONFIG_PATH = '/switchVerifier/config.json'
# Path of the switchVerifier public key for PCR signature verififcation
SWITCH_PCR_PUB_KEY_PATH = '/switchVerifier/key.pub'
# Path of the switch reference configuration
SWITCH_REF_CONFIG_PATH = '/switchVerifier/swConf'
# Hostname of Switch Verifier machine
SWITCHVER_HOSTNAME = "127.0.0.1"
# SSH port of Switch Verifier machine
SWITCHVER_SSH_PORT = 22
# SSH username of Switch Verifier machine
SWITCHVER_SSH_USER = "root"
# SSH password of Switch Verifier machine
SWITCHVER_SSH_PWD = "toor"
