import schedule
import time
from scheduler_config import *
import logging
import requests
import sys

logging.basicConfig(
    filename='/logs/scheduler.log',
    level=logging.DEBUG
    format=' %(levelname)s [%(asctime)s] %(module)s - %(message)s')


def get_nfvi_attestation_url():
    if not PA_URL:
        logging.warning("No periodic attestation URL specified")
    return PA_URL


def get_pa_timeout():
    if not PA_SEC_TIMEOUT:
        logging.warning("No periodic attestation timeout specified" +
                        " (default is 60)")
        PA_SEC_TIMEOUT = 60
    return PA_SEC_TIMEOUT


def periodic_nfvi_attestation():
    logging.info("Running periodic NFVI attestation task")
    try:

        r = requests.get(get_nfvi_attestation_url(), timeout=get_pa_timeout())
        logging.info("Periodic NFVI attestation task returned " +
                     "with status code: " + r.status_code)
        r.raise_for_status()
        logging.debug("Periodic NFVI attestation response: " + r.text)
    except request.exceptions.HTTPError as resp_error:
        logging.error("NFVI attestation task response fail: " str(resp_error))
    except requests.exceptions.ConnectionError as conn_err:
        logging.error("Connection error occurred: " + str(conn_err))
    except requests.exceptions.Timeout as timeout:
        logging.error("Timeout occurred: " + str(timeout))
    except requests.exceptions.RequestException as err:
        logging.error("Generic request exception occurred: " + str(err))


if __name__ == '__main__':

    logging.info("Scheduler is starting.")

    try:
        interval = int(PA_SEC_INTERVAL)

        if interval <= 0:
            logging.info("Periodic attestation interval is invalid. " +
                         "Stopping scheduler.")
            sys.exit(-1)

        schedule.every(interval).seconds.do(periodic_nfvi_attestation)

        while True:
            schedule.run_pending()
            time.sleep(1)

    except ValueError as e:
        logging.error("Scheduler configuration error: " + str(e))
    except Exception as e1:
        logging.error("Generic error: " + str(e))

    logging.info("Scheduler is terminated.")
