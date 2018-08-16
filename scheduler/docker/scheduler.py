import schedule
import time
import logging
import requests
import sys

logging.basicConfig(
    filename='/logs/scheduler.log',
    level=logging.DEBUG,
    format=' %(levelname)s [%(asctime)s] %(module)s - %(message)s')


def get_nfvi_attestation_url():
    from scheduler_config import PA_URL
    if not PA_URL:
        logging.warning("No periodic attestation URL specified")
    return PA_URL


def get_pa_timeout():
    from scheduler_config import PA_SEC_TIMEOUT
    if not PA_SEC_TIMEOUT:
        logging.warning("No periodic attestation timeout specified" +
                        " (default is 5)")
        PA_SEC_TIMEOUT = 5
    return int(PA_SEC_TIMEOUT)


def periodic_nfvi_attestation():
    logging.info("Running periodic NFVI attestation task")
    try:

        r = requests.get(
            get_nfvi_attestation_url(),
            timeout=get_pa_timeout(),
            verify=False)
        logging.info("Periodic NFVI attestation task returned " +
                     "with status code: " + str(r.status_code))
        r.raise_for_status()
        logging.debug("Periodic NFVI attestation response: " + r.text)
    except requests.exceptions.HTTPError as resp_error:
        logging.error("NFVI attestation task response fail: " + str(resp_error))
    except requests.exceptions.ConnectionError as conn_err:
        logging.error("Connection error occurred: " + str(conn_err))
    except requests.exceptions.Timeout as timeout:
        logging.error("Timeout occurred: " + str(timeout))
    except requests.exceptions.RequestException as err:
        logging.error("Generic request exception occurred: " + str(err))


if __name__ == '__main__':

    logging.info("Scheduler is starting.")

    try:
        from scheduler_config import PA_SEC_INTERVAL
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
        logging.error("Generic error: " + str(e1))

    logging.info("Scheduler is terminated.")
