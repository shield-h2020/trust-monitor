# Trust Monitor README

This repository contains the software required to instantiate the Trust
Monitor application. This application can be used together with a Reference
Database and an attestation runtime to provide load-time/run-time attestation
of CentOS-based platforms equipped with a TPM.

## Directory structure

```
trust-monitor
├── docker-compose.yml
├── helper
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

The directory `helper` includes additional data for the integration of
attestation drivers.

## Software requirements

The application can be installed on a Ubuntu 16.04.3 LTS host (other distros
have not been tested, but the installation process may be adapted).

The application requirements can be installed by issuing the following
commands:

```bash
sudo apt install python-pip graphviz-dev
sudo pip install -r trustMonitor/requirements.txt
```

**N.B:** The Trust Monitor application requires several other components to work
properly, as its behaviour is not standalone. First of all, the TM app
requires a running instance of Apache Cassandra database hosting the
whitelist measurements for code in a specific schema. Moreover, the Trust Monitor
application interacts with other components (such as Open Source MANO) via APIs,
so these components should be in place (and properly configured in the app
settings) to be reachable by the TM app.

## Manual installation

1. Create `local_setting.py` file under the `trustMonitor/trust_monitor_django`
directory to specify configuration parameters.
For example:

```python
LOCAL_SETTINGS = True
from settings import *
ALLOWED_HOSTS += ['ip_address_tm']
CASSANDRA_LOCATION = 'ip_address_cassandra_db'
CASSANDRA_PORT = 'port_cassandra_db'
OAT_LOCATION = 'ip_address_oat'
```

It is also possible to increase the list of `ALLOWED_HOSTS` or the
Whitelist Database IP address.

**N.B:** You need to specify the SQLite database path in the `DATABASES`
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

3. In case of **OpenAttestation** (OAT) driver, indicate the path relative to
`start_verify.py` used by OAT in the file
`trust_monitor_driver/driver_setting.py`

```python
PATH_DRIVER = '/define_your_path/start_verify.py'
```

## Docker Compose automated installation

The TM can be deployed in a Docker environment as three three containers:
- an **nginx** SSL-aware reverse proxy  that exposes its ports (80,443) on the
host
    - Please note that you need to provide a key and certificate chain under
    `reverseProxy/ssl` before executing the Docker Compose script (e.g. via
    `make-ssl-cert` tool on Ubuntu)
- a Django app with the Trust Monitor app on `localhost`
    - Edit the `trustMonitor/trust_monitor_django/settings.py` file to your
    needs
- a Python `SimpleHTTPServer` to serve the application static files on
    `localhost`
    - No additional configuration is needed

In the `docker-compose.yml` file you must specify information for the container tm_manage_osm_connector and for the container tm_django_app.
- In the `tm_manage_osm_connector` in extra_hosts you must indicate the IP address of where Open Source Mano (OSM) is located, this IP address is defined by osm-r3.

```bash
extra_hosts:
  - "osm-r3:ip_address_osm"
```

- In the `tm_django_app` you need to specify the ip address in extra-hosts where the OAT framework is located, it must be defined as ra-oat-verifier.
```bash
extra_hosts:
  - "ra-oat-verifier:ip_address_oat"
```

After making these changes it is necessary to modify the Dockerfile of `manage_osm_connector` in which we must specify the IP address of OSM, example of extract of the `connectors/manage_osm_connector/Dockerfile` file:

```python
ENV OSM_HOSTNAME=ip_address_osm

ENV OSM_RO_HOSTNAME=ip_address_osm
```

The environment can be deployed via Docker Compose by issuing the command

```
docker-compose up --build
```

from the root directory of the project.

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

## Helper scripts

The `helper` folder contains others files used for different operations.

The `start_verify.py` file, contained within this folder is used by the
attestation driver to contact the TM in order to begin the attestation process. You need to give `start_verify.py` the execution permissions.

The `setting.py file`, is used to set the base URL of the TM (for callback).

These files must be added to the host where OAT is running.

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

## Extra Information on OAT

It is essential to add the certificate that identifies the OAT framework within the directory `trustMonitor/docker/ssl/certs`.
