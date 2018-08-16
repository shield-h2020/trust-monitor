###############################################################################
# Configuration file for the TM periodic attestation scheduler
###############################################################################

# Periodic attestation interval (in seconds). Set to 0 or negative integer to
# disable
PA_SEC_INTERVAL = 60

# TM attestation URL (base URL should be `https://tm_django_app/` in a Docker
# Compose environment)
PA_URL = "https://tm_django_app/nfvi_attestation_info"

# Periodic attestation request timeout (in seconds)
PA_SEC_TIMEOUT = 3
