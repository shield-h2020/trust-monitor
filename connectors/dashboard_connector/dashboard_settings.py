###############################################################################
# Configuration file for the Dashboard connector, which implements a rabbitmq
# client
###############################################################################

# Hostname/IP address of the dashboard RabbitMQ server
DASHBOARD_HOSTNAME = '10.101.10.130'
# Port of the dashboard RabbitMQ server
DASHBOARD_PORT = '5672'
# Exchange of the dashboard Rabbit MQ server
DASHBOARD_EXCHANGE = 'shield-dashboard-exchange'
# Topic of the dashboard Rabbit MQ server
DASHBOARD_TOPIC = 'shield.notification.tm'
# Number of attempts to query the Rabbit MQ server
DASHBOARD_ATTEMPTS = 3
# Retry delay when re-querying the Rabbit MQ server
DASHBOARD_RETRY_DELAY = 5
