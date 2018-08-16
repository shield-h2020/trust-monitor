###############################################################################
# Configuration file for the TM periodic attestation scheduler
###############################################################################

# Periodic attestation interval (in seconds). Set to 0 or negative integer to
# disable
PA_SEC_INTERVAL = 0

# TM attestation URL (base URL should be `https://reverse_proxy/` in a Docker
# Compose environment)
PA_URL = "https://reverse_proxy/nfvi_attestation_info"

# Periodic attestation request timeout (in seconds)
PA_SEC_TIMEOUT = 3
