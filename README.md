# Trust Monitor README

This repository contains the software required to instantiate the Trust
Monitor application.

This application can be used together with a Reference
Database and an attestation runtime to provide load-time/run-time attestation
of CentOS-based platforms equipped with a TPM.
Moreover, this application can be integrated with SDN-oriented attestation
for switches and controller.

## Software requirements

The application can be installed on a Ubuntu 16.04.3 LTS host (other distros
have not been tested, but the installation process may be adapted).

The application requirements can be installed by issuing the following
commands:

```bash
sudo apt install python-pip graphviz-dev
sudo pip install -r trustMonitor/requirements.txt
```

## Manual installation

1. Create `local_setting.py` file under the `trustMonitor/trust_monitor_django`
directory to specify configuration parameters.
For example, specify the attestation framework as follows:

	```python
	ATTESTATION_FRAMEWKORK = 'OAT'
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
