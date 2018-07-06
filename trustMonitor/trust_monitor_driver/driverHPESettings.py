###############################################################################
# Configuration file for the HPE switch attestation driver
# In case of (standard) Docker-based deployment of the TM, all the paths should
# match the mount point of the volume defined in the docker-compose.yml file
# (default is '/hpe' directory)
###############################################################################

# Path of the switchVerifier binary on the system
SWITCH_VERIFIER_PATH = '/hpe/switchVerifier'
# Path of the switchVerifier config.json configuration file
SWITCH_VER_CONFIG_PATH = '/hpe/config.json'
# Path of the switchVerifier public key for PCR signature verififcation
SWITCH_PCR_PUB_KEY_PATH = '/hpe/key.pub'
# Path of the switch reference configuration
SWITCH_REF_CONFIG_PATH = '/hpe/swConf'
