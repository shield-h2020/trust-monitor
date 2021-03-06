# Trust Monitor README

This repository contains the software required to instantiate the Trust
Monitor application. This application can be used together with a Reference
Database and one or more attestation run-times to provide load-time/run-time
attestation of compute platforms and SDN network equipment via TPM.

## Directory structure

```
trust-monitor
├── connectors
│   ├── dare_connector
│   ├── dashboard_connector
│   ├── database
│   ├── store_connector
│   ├── vimemu_connector
│   └── vnsfo_connector
├── digestsHelper
│   ├── digests.json
│   └── upload_known_digests.py
├── docker-compose.yml
├── LICENSE
├── logs
├── OAThelper
│   ├── setting.py
│   └── start_verify.py
├── README.md
├── reverseProxy
│   ├── conf
│   ├── Dockerfile
│   ├── html
│   └── ssl
├── scheduler
│   ├── docker
│   ├── Dockerfile
│   └── requirements.txt
└── trustMonitor
    ├── docker
    ├── Dockerfile
    ├── manage.py
    ├── requirements.txt
    ├── trust_monitor
    ├── trust_monitor_django
    └── trust_monitor_driver
```

The directory `trustMonitor` includes the application specific
files of the Django app, comprising:
* `trust_monitor`: the base app software
* `trust_monitor_django`: the django execution files of the app
* `trust_monitor_driver`: the files required to integrate attestation drivers

The director `connectors` includes the sources of all the connectors to other
SHIELD components (DARE, Dashboard, VIM, vNSFO, white-list database).

The directory `reverseProxy` includes the sources of a Docker image
that instantiates a reverse proxy for the TM app.

The directory `OAThelper` includes additional data for the integration of
OAT attestation drivers.

The directory `scheduler` includes an optional Docker module to run periodic
attestation.

The directory `digestsHelper` includes an helper script for including additional
digests in the whitelist database.

**N.B:** The Trust Monitor application requires several other components to work
properly, as its attestation workflow is integrated within the SHIELD platform.
Moreover, the TM app requires a running instance of Apache Cassandra database
hosting the whitelist measurements for code in a specific schema.

## Docker Compose automated installation

The TM can be deployed in a Docker environment as a multi-container application.

### Install Docker Engine and Compose

1.  Install Docker engine (see [Install using the repository] on Docker pages)

```
sudo apt-get remove docker docker-engine docker.io
sudo apt-get update
sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install docker-ce
```

2.  Install Docker compose (see [Install Compose] on Docker pages)

```
sudo curl -L https://github.com/docker/compose/releases/download/1.18.0/docker-compose-Linux-x86_64 -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

[Install using the repository]: https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#install-using-the-repository
[Install Compose]: https://docs.docker.com/compose/install/#install-compose

### Configure the TM Django application

In the `reverseProxy` application, note that you need to provide a key and
certificate chain under `ssl` before executing the Docker Compose script
(e.g. via `make-ssl-cert` tool on Ubuntu). The name of the chain and private key
depends on the virtual host configured under
`reverseProxy/conf/conf.d/test.ra.trust.monitor.vhost.conf`,
which default to:

* `ssl/private/test.ra.trust.monitor.key`
* `ssl/certs/test.ra.trust.monitor.chain`

In the `TrustMonitor` application, edit the `trust_monitor_django/settings.py`
file to your needs. At minimum, you need to configure:

```
CASSANDRA_LOCATION = $WHITELIST_DB_IP
CASSANDRA_PORT = '9160'
```

where Apache Cassandra IP address refers to the instance running the white-list
database and the default port is `9160`.

### Run the Trust Monitor Docker environment

The environment can be deployed via Docker Compose by issuing the command

```
# docker-compose up --build
```

from the root directory of the project. Check the logs at startup to ensure that
all containers are started properly. At the end of the process, run the following
command from a different shall (still from the root directory):

```
# docker-compose ps
```

The output should be similar to the following:

```
Name                               Command                State                      Ports                  
-----------------------------------------------------------------------------------------------------------------------------
trust-monitor_reverse_proxy_1            nginx -g daemon off;             Up         0.0.0.0:443->443/tcp, 0.0.0.0:80->80/tcp
trust-monitor_tm_dare_connector_1        python dare.py                   Up         5000/tcp                                
trust-monitor_tm_dashboard_connector_1   python dashboard.py              Up         5000/tcp                                
trust-monitor_tm_database_redis_1        docker-entrypoint.sh redis ...   Up         6379/tcp                                
trust-monitor_tm_django_app_1            docker/entrypoint.sh             Up         8000/tcp                                
trust-monitor_tm_scheduler_1             python ./docker/scheduler.py     Up                                          
trust-monitor_tm_static_serve_1          docker/entrypoint.sh             Up         8000/tcp                                
trust-monitor_tm_store_connector_1       python store.py                  Up         5000/tcp                                
trust-monitor_tm_vimemu_connector_1      python vimemu.py                 Up         5000/tcp                                
trust-monitor_tm_vnsfo_connector_1       python vnsfo.py                  Up         5000/tcp                                
```

## Create your attestation driver

If you want to create your own attestation driver, you need to create a file
called for example `testDriver.py` to insert in the path
`trustMonitor/trust_monitor_driver`.
The `testDriver.py` file must have a class containing at least three methods inside it:
- `registerNode` used to register the node at the attestation framework to which the driver refers;
- `getStatus` used to verify whether the attestation framework is active or not;
- `pollHost`used to start the RA process with the attestation framework.

It is recommended to specify the identifier of the driver in the
`trustMonitor/trust_monitor_driver/driverConstants.py` file.

It may also be necessary to create within the path
`trustMonitor/trust_monitor/verifier` a file called for example `parsingTest.py`
used to parse the measurements coming from the attestation framework, in case
you want to leverage the white-list-based verification for compute nodes.

The various measures must have mandatory information to be treated as objects of
the IMARecord class in order to be included in the list of digest that are
analyzed during the integrity verification procedure.
For example:

```
pcr = "10" # the pcr register that contain this measure
template_digest = "null" # the information of template
template_name = "ima-ng" # the kind of template used by IMA
template_desc = "ima-ng" # the kind of template used by IMA
event_digest = "data" # the value of measure
event_name = measure['Path'] # the path of measure
id_docker = "host" # the owner of the measure, for example host or container
template_data = ("sha1:" + event_digest + " " + event_name +
                 " " + id_docker)
# the object that includes parts of the previous information
file_line = (pcr + " " + template_digest + " " +
             template_name + " " + template_data)
# the complessive line that is passed to IMARecord class
IMARecord(file_line)
```

When the IMARecord class is called the list of Digest that is considered during
the attestation process is expanded.
In the `engine.py` file you have to properly configure the attestation
callback to query the driver.
In the `views.py` file you have to properly configure the registration option
for your new driver.

## Log messages

Each developed docker container contains a file that takes care of capturing all
log message from the application, this file is accessible from the container within the path ``/logs/``.

Example below:

```bash
tm_store_connector:
  ...
  volumes:
   - './logs/store_connector:/logs'
```

## Connect the TM to an OAT attestation framework

In order to interact with OAT, both the Trust Monitor application and the OAT
Verifier need to be configured properly.

### Configuration on the OAT Verifier

The `OAThelper` folder contains others files used for different operations.

The `start_verify.py` file, contained within this folder is used by the
attestation driver to contact the TM in order to begin the attestation process.
You need to give `start_verify.py` the execution permissions.

The `setting.py` file is used to set the base URL of the TM (for callback).

These files must be added to the host where OAT is running in a proper directory,
hereby named `OAT_TM_DIR`.

### Configuration on the TM app

It is essential to add the certificate that identifies the OAT Verifier within
the directory `trustMonitor/docker/ssl/certs`. To do so, you can either download
the certificate from the web application via browser or run the following command:

```
# openssl s_client -showcerts -connect $OAT_VERIFIER_IP:8443 </dev/null 2>/dev/null|openssl x509 -outform PEM > trustMonitor/docker/ssl/certs/ra-oat-verifier.pem
```

which will save the X.509 certificate in PEM format in the `ra-oat-verifier.pem`
file.

Then, you have to update the `docker-compose.yml` file by adding the following
lines:

```
tm_django_app:
  image: ra/trust_monitor/tm_django_app
  build: ./trustMonitor
  environment:
    - RUN_DJANGO_APP=1
  depends_on:
    - tm_static_serve
```


Moreover, you need to update the `OAT_LOCATION` variable in the
`trustMonitor/trust_monitor_driver/driverOATSettings.py` file by adding the IP address
of the OAT Verifier and the remote path of the OAT Verifier callback as follows:

```python
PATH_CALLBACK = '/$OAT_TM_DIR/start_verify.py'
OAT_LOCATION = "192.168.1.10"
```

## Connect the TM to an Open CIT attestation framework

You need to configure the following variables in the
`trustMonitor/trust_monitor_driver/driverCITSettings.py`
file by adding the IP address of the CIT Attestation Server and the credentials
to access its REST API.

```
# IP address of the CIT attestation server
CIT_LOCATION = ''
# Username for authenticating to the REST API of the CIT attestation server
CIT_API_LOGIN = 'admin'
# Password for the user allowed to contact the REST API of the CIT attestation server
CIT_API_PASSWORD = ''
```

In order to register an Open CIT host, you need to retrieve the `uuid_host`
parameter from the Open CIT Attestation Server. In order to do so, access the
Attestation Server database by issuing:

```
# psql mw_as
```

Then, run the following command to retrieve the `uuid_host` parameter:

```
mw_as=# select uuid_hex from mw_hosts;
```

The `uuid_host` parameter must be set as `hostName` of the CIT host when
registering it.

## Connect the TM to the HPE switch attestation framework

The HPE switch verifier must be not run behind a NAT, as it leverages SNMP.
Because of this, the preferred way of running the HPE attestation driver is
via a direct SSH connection to the switch verifier host.

In order to run it, the following parameters must be added in the
`trustMonitor/trust_monitor_driver/driverHPESettings.py`
file, as follows:

```
SWITCH_VERIFIER_PATH = '/remote/path/to/<final name of switchVerifier binary>'
SWITCH_VER_CONFIG_PATH = '/remote/path/to/<name of configuration file (default config.json)>'
SWITCH_PCR_PUB_KEY_PATH = '/remote/path/to/<name of pub key for PCR sig. verification>'
SWITCH_REF_CONFIG_PATH = '/remote/path/to/<name of switch reference configuration>'
SWITCHVER_HOSTNAME = "<hostname of switch verifier host>"
SWITCHVER_SSH_PORT = "<port of switch verifier host>"
SWITCHVER_SSH_USER = "<username of switch verifier host>"
SWITCHVER_SSH_PWD = "<password of switch verifier host>"
```

## Test the Trust Monitor API

This section briefly states how to interact with the Trust Monitor APIs.

### Status information

The Trust Monitor Django application allows for a graphical testing of its APIs.
In order to retrieve status information on the application, just navigate to the
following URL in a browser:
```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/status/
```
This page should display in human readable form the status of different
services related to the TM and the attestation frameworks as well.

### Registration of a node

In order to perform registration of a node, just access the following page:
```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/register_node/
```

From the page, click the `GET` button to retrieve the list of currently registered
nodes (the TM app uses a volume for SQLite database, so it should persist among
restarts of the Docker environment).
In order to register an host, add the following content in the `POST` body:

```
{"distribution": "<distro (e.g. CentOS7/HPE)>", "hostName": "<host name>",
"driver":"OAT/OpenCIT/HPESwitch", "address": "xxx.xxx.xxx.xxx"}
```

In order to delete a registered node, you can access the same API with a `DELETE`
request (e.g. via `curl`):

```
curl -k -X "DELETE" --header "Content-Type: application/json" --data '{"hostName": "<node-to-unregister>"}' https://<TRUST_MONITOR_BASE_URL_OR_IP>/register_node/
```

### Attestation of a node

In order to perform attestation of a node, just access the following page:
```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/attest_node/
```

In order to attest a previously registered node, add the following content in
the `POST` body:

```
{"node_list" : [{"node" : "<host name>"}]}
```

Other attestation APIs (with `GET` request only) are:

* `https://<TRUST_MONITOR_BASE_URL_OR_IP>/nfvi_pop_attestation_info?node_id=<id>`
* `https://<TRUST_MONITOR_BASE_URL_OR_IP>/nfvi_attestation_info/`

While the first allows to attest a single node of the NFVI, given its name,
the second returns the trust status of the whole infrastructure. The second API
requires a working vNSFO connector to retrieve the list of running nodes.

### Update the list of known digests

The Trust Monitor includes an additional whitelist for known digests, in
addition to the whitelist database for a specific distribution. In order to show
the list of added digests, access the following `GET` API:

```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/known_digests/
```

In order to add a new digest, add the following content in the `POST` body:

```
{'pathFile': '/usr/bin/test', 'digest': 'sha1(/usr/bin/test)'}
```

In order to remove a digest, use the following content in the `DELETE` body:

```
{'digest': 'sha1(/usr/bin/test)'}
```

## Setup periodic attestation

The `scheduler` folder includes a Docker-based module that runs periodically
the call to attest the whole NFVI infrastructure, which in turns triggers
notifications to the other components (i.e. the DARE and dashboard). In order to
enable periodic attestation, you just need to edit the
`scheduler/docker/scheduler_config.py` file as follows:

```
PA_SEC_INTERVAL = ... # set an integer greater than 0 to enable periodic
                      # attestation

PA_URL = "https://reverse_proxy/nfvi_attestation_info" # should not be changed

PA_SEC_TIMEOUT = 30 # can be modified to set a maximum timeout for each
                   # attestation request
```

## Audit information

The Trust Monitor embeds an audit logic which allows to store and retrieve
past attestations for a specific node. Data is stored on HDFS for availability
and resiliency, with configuration available under `connectors/dare_connector/dare_settings.py`.
The audit API is accessible as follows;

```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/audit/
```

In order to retrieve the last audit log for a node, just run a `POST` request
with the following JSON body:

```
{"node_id":"<registered_node_name>"}
```

In case you want to retrieve all the logs in a specific time-frame, just access
the same API with the following POST body:

```
{"node_id":"<registered_node_name>", "from_date": "<date in YYYY-MM-DD format>", "to_date": "<date in YYYY-MM-DD format>"}
```

For example, in case you want to retrieve all the logs for a particular day
you may specify the date of such day as both `from_date` and `to_date` parameters.

Multiple audit logs are retrieved ordered from the newest to the oldest.
