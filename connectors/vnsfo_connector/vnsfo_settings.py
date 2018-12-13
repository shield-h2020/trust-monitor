###############################################################################
# Configuration file for the vNSFO connector
###############################################################################

# Base URL of the vNSFO rest API
VNSFO_BASE_URL = 'https://10.101.10.100:8448'

# Max timeout of vNSFO API calls
VNSFO_TIMEOUT = 5

# OSM-release selector for certain VNSFO API commands
# Accepted values are '' for legacy API call,
# 'r2/' for explicit OSM r2,
# 'r4/' for explicit OSM r4
OSM_RELEASE = ''
