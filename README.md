# Trust Monitor README

This repository contains the software required to instantiate the Trust
Monitor application. This application can be used together with a Reference
Database and one or more attestation runtimes to provide load-time/run-time
attestation of compute platforms and SDN network equipment via TPM.

## Directory structure

```
trust-monitor
├── docker-compose.yml
├── OAThelper
│   ├── setting.py
│   └── start_verify.py
├── LICENSE
├── README.md
├── reverseProxy
│   ├── conf
│   ├── Dockerfile
│   ├── html
│   └── ssl
├── connectors
|   ├── dare_connector
|   ├── dashboard_connector
|   |   └── server-rabbitmq
|   ├── store_connector
|   └── vNSFO_connector
└── trustMonitor
    ├── docker
    |   └── ssl
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

The directory `reverseProxy` includes the sources of a Docker image
that instantiates a reverse proxy for the TM app.

The directory `OAThelper` includes additional data for the integration of
OAT attestation drivers.

**N.B:** The Trust Monitor application requires several other components to work
properly, as its behaviour is not standalone. First of all, the TM app
requires a running instance of Apache Cassandra database hosting the
whitelist measurements for code in a specific schema. Moreover, the Trust Monitor
application interacts with other components (such as Open Source MANO) via APIs,
so these components should be in place (and properly configured in the app
settings) to be reachable by the TM app.

## (Suggested) Docker Compose automated installation

The TM can be deployed in a Docker environment as three three containers:
- an **nginx** SSL-aware reverse proxy  that exposes its ports (80,443) on the
host
- a Django app with the Trust Monitor app on `localhost`
- a Python `SimpleHTTPServer` to serve the application static files on
    `localhost`

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

### Configure the applications

In the `reverseProxy` application, note that you need to provide a key and certificate chain under
`ssl` before executing the Docker Compose script (e.g. via `make-ssl-cert` tool on Ubuntu). The name of the chain and private key depends on the virtual host configured under `reverseProxy/conf/conf.d/test.ra.trust.monitor.vhost.conf`,
which default to:

* `ssl/private/test.ra.trust.monitor.key`
* `ssl/certs/test.ra.trust.monitor.chain`

In the `TrustMonitor` application, edit the `trust_monitor_django/settings.py` file to your
needs. At minimum, you need to configure:

```
CASSANDRA_LOCATION = $WHITELIST_DB_IP
CASSANDRA_PORT = '9160'
```

where Apache Cassandra IP address refers to the instance running the whitelist
database and the default port is `9160`.

Then, you also need to configure the `OAT_LOCATION` if you are using the OAT
attestation framework (more in following sections).

Finally, before running the Docker Compose build script you need to export
the following environment variables in the same shell:

```
# export OSM_IP=<ip of Open Source MANO instance>
```

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
Name                                Command               State                    Ports                  
----------------------------------------------------------------------------------------------------------------------------
ratrustmonitor_reverse_proxy_1             nginx -g daemon off;             Up      0.0.0.0:443->443/tcp, 0.0.0.0:80->80/tcp
ratrustmonitor_tm_dare_connector_1         python dare.py                   Up      5000/tcp                                
ratrustmonitor_tm_dashboard_connector_1    python dashboard.py              Up      5000/tcp                                
ratrustmonitor_tm_database_redis_1         docker-entrypoint.sh redis ...   Up      6379/tcp                                
ratrustmonitor_tm_django_app_1             docker/entrypoint.sh             Up      8000/tcp                                
ratrustmonitor_tm_manage_osm_connector_1   python manage_osm.py             Up      5000/tcp                                
ratrustmonitor_tm_rabbitmq_server_1        docker-entrypoint.sh rabbi ...   Up      25672/tcp, 4369/tcp, 5671/tcp, 5672/tcp
ratrustmonitor_tm_static_serve_1           docker/entrypoint.sh             Up      8000/tcp                                
ratrustmonitor_tm_store_connector_1        python store.py                  Up      5000/tcp   
```

## (Alternative) manual installation

In alternative to Docker Compose, you can install the Trust Monitor app as a
standard Django application.

### Software requirements

The application can be installed on a Ubuntu 16.04.3 LTS host (other distros
have not been tested, but the installation process may be adapted).

The application requirements can be installed by issuing the following
commands:

```bash
sudo apt install python-pip graphviz-dev
sudo pip install -r trustMonitor/requirements.txt
```

### Installation steps

1. Create `local_setting.py` file under the `trustMonitor/trust_monitor_django`
directory to specify configuration parameters.
For example:

```python
LOCAL_SETTINGS = True
from settings import *
ALLOWED_HOSTS += ['ip_address_tm']
CASSANDRA_LOCATION = 'ip_address_cassandra_db'
CASSANDRA_PORT = '9160'
```

**N.B:** You can modify the SQLite database path in the `DATABASES`
variable as well.

2. Create the database used by the TM to register a new node or insert a
known digest.

```bash
cd trustMonitor/
python manage.py makemigrations trust_monitor
python manage.py migrate
```

To check if the compilation was successful, you can test everything by
running:

```bash
python manage.py runserver
```

This command runs the trust-monitor on localhost. If the output is similar
to:

```bash
Performing system checks...

System check identified no issues (0 silenced).
February 21, 2018 - 12:04:00
Django version 1.11.10, using settings 'trust_monitor.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

The creation was successful.

## Create your attestation driver

If you want to create your own attestation driver, you need to create a file called for example `testDriver.py` to insert in the path `trustMonitor/trust_monitor_driver`.
The `testDriver.py` file must have a class containing at least three methods inside it:
- `registerNode` used to register the node at the attestation framework to which the driver refers;
- `getStatus` used to verify whether the attestation framework is active or not;
- `pollHost`used to start the RA process with the attestation framework.

It is also necessary to create within the path `trustMonitor/trust_monitor/verifier` a file called for example `parsingTest.py` used to parsify the measurements coming from the attestation framework.
The various measures must have mandatory information to be treated as objects of the IMARecord class in ordert to be included in the list of digest that are analyzed during the integrity verification procedure.
For example:
```python
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

When the IMARecord class is called the list of Digest that is considered during the attestation process is expanded.
Inside the `views.py` file you have to insert the import from the driver file and you need to instantiate an object from the `testDriver` class, for example in this way:
```python
from trust_monitor_driver.testDriver import TestDriver

testDriver = TestDriver()
```
To allow you to record and attest a node, you must specify an if in the class that handles these methods, because when you are asked to insert a new node in the Trust Monitor you must also specify the driver to which we refer. So we can divide the procedures according to the chosen driver.
For example:

```python
class RegisterNode(APIView):

def post(self, request, format=None):
  ...
  if newHost.driver == 'OAT':
      ....
  elif newHost.driver == 'TestDriver':
      # register your node with the attestation framework and the Trust Monitor
```
Analogous content for the attestation API ``..../attest_node``.


## Log messages

Each developed docker container contains a file that takes care of capturing all log message from the application, this file is accessible from the container within the path ``/logs/``.
It is possible to export the volume containing the logs going to specify in the `docker-compose.yml` file for the desired container the volumes fiels specifying where to seve the information.

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
attestation driver to contact the TM in order to begin the attestation process. You need to give `start_verify.py` the execution permissions.

The `setting.py` file is used to set the base URL of the TM (for callback).

These files must be added to the host where OAT is running in a proper directory,
hereby named `OAT_TM_DIR`.

### Configuration on the TM app

It is essential to add the certificate that identifies the OAT Verifier within the directory `trustMonitor/docker/ssl/certs`. To do so, you can either download the certificate
from the web application via browser or run the following command:

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
  extra_hosts:
    - "$OAT_VERIFIER_CN":$OAT_VERIFIER_IP"
```

where `OAT_VERIFIER_CN` is the name included in the OAT Verifier certificate
and `OAT_VERIFIER_IP` is its IP address.

Moreover, you need to update the `OAT_LOCATION` variable in the `trustMonitor/trust_monitor_django/settings.py` file by adding the IP address
of the OAT Verifier.

Finally, you need to configure the remote path relative to `start_verify.py` used by OAT in the file
`trust_monitor_driver/driverOATSettings.py`

```python
PATH_DRIVER = '/$OAT_TM_DIR/start_verify.py'
```

## Connect the TM to an Open CIT attestation framework

You need to configure the following variables in the `trustMonitor/trust_monitor_driver/driverCITSettings.py`
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

## Connect the TM to the HPE switch attestation framework

*N.B:* This section refers to the Docker-based deployment.

You need to place the HPE switchVerifier binary and configuration file in the
`hpe` directory. Then, you need to configure the name of these configuration
files and binary in the `trustMonitor/trust_monitor_driver/driverHPESettings.py`
file, as follows:
```
SWITCH_VERIFIER_PATH = '/hpe/<final name of switchVerifier binary>'
SWITCH_VER_CONFIG_PATH = '/hpe/<name of configuration file (default config.json)>'
SWITCH_PCR_PUB_KEY_PATH = '/hpe/<name of pub key for PCR sig. verification>'
SWITCH_REF_CONFIG_PATH = '/hpe/<name of switch reference configuration>'
```

Finally, ensure that the following volume is enabled in the `docker-compose.yml`
file:

```
tm_django_app:
  image: ra/trust_monitor/tm_django_app
  [...]
  volumes:
    [...]
    - './hpe:/hpe'
```

In case you want to edit the `hpe` directory path in the host system, edit the
first part of the volume definition (the second is the path inside of the container).

## Test the Trust Monitor API

The Trust Monitor Django application allows for a graphical testing of its APIs.
In order to retrieve status information on the application, just navigate to the
following URL in a browser:
```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/get_status_info/
```
This page should display in human readable form the status of different
services related to the TM and the attestation frameworks as well.

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

In order to perform attestation of a node, just access the following page:
```
https://<TRUST_MONITOR_BASE_URL_OR_IP>/attest_node/
```

In order to attest a previously registered node, add the following content in
the `POST` body:

```
{"node_list" : [{"node" : "<host name>"}]}
```
