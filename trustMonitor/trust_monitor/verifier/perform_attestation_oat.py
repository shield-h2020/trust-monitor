from sys import argv
import logging
from structs import *
from suds.client import Client
from parser import IRParser, IMAMeasureHandler
from parser import ContainerCheckAnalysis
import gc
import argparse
from informationDigest import InformationDigest
from ra_verifier import RaVerifier
from parsingOAT import *
import sys


def main():
    parsingOAT = ParsingOAT()
    CLI = argparse.ArgumentParser()
    CLI.add_argument("--listdigest", nargs="*",)
    CLI.add_argument("--analysis", nargs=1,)
    CLI.add_argument("--report_url", nargs=1,)
    CLI.add_argument("--report_id", nargs=1,)
    CLI.add_argument("--distro", nargs=1,)
    CLI.add_argument("--portCassandra", nargs=1,)
    CLI.add_argument("--ipCassandra", nargs=1,)
    args = CLI.parse_args()
    known_digests = args.listdigest
    analysis = args.analysis[0]
    report_url = args.report_url[0]
    report_id = int(args.report_id[0])
    distro = args.distro[0]
    port_cassandra = str(args.portCassandra[0])
    ip_cassandra = args.ipCassandra[0]
    info_digest = InformationDigest()
    checked_containers = ""
    res = parsingOAT.parsing(analysis, checked_containers, report_url,
                             report_id, info_digest)
    if res == 2:
        print 2
        sys.exit(0)
    ra_verifier = RaVerifier()
    logger.info('Call verifier method of RaVerifier')
    result = ra_verifier.verifier(distro=distro, analysis=analysis,
                                  infoDigest=info_digest,
                                  checked_containers=checked_containers,
                                  report_id=report_id,
                                  known_digests=known_digests,
                                  port=port_cassandra,
                                  ip=ip_cassandra)
    logger.debug('Return of method and result is %s', result)
    if result[0] is True:
        print 0
    elif result[0] is False:
        print 1
    else:
        print 2
        sys.exit(0)
    print info_digest.list_not_found
    print info_digest.list_fake_lib
    print info_digest.n_digests_ok
    print info_digest.n_digests_not_found
    print info_digest.n_digests_fake_lib
    print info_digest.list_containers
    print info_digest.list_prop_not_found
    print info_digest.n_packages_ok
    print info_digest.n_packages_security
    print info_digest.n_packages_not_security
    print info_digest.n_packages_unknown
    print info_digest.host
    sys.exit(0)


if __name__ == "__main__":
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/verifier/ra_verifier_oat.log")
    fileHandler.setFormatter(formatter)
    logger = logging.getLogger('perform_attestation')
    logger.setLevel(level=logging.DEBUG)
    logger.addHandler(fileHandler)
    main()
