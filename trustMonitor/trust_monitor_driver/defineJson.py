import json


class JsonSingleHost():
    """
    Define Json for each single node.
    This json contains:
        {"node": "name_of_node",
         "trust_lvl": "trusted/untrusted",
         "analysis_status": "COMPLETED/ERROR",
         "analysis_extra_info": [],
         "analysis_containers": ['list_of_container']}
    """
    def defineSingleHost(self, host, list_not_found, list_fake_lib,
                         n_digests_ok, n_digests_not_found, n_digests_fake_lib,
                         n_packages_ok, n_packages_security,
                         n_packages_unknown, n_packages_not_security,
                         list_containers, list_prop_not_found):
        """
        Input response of the framework of attestation
        """
        listNotFound = (
            '' if len(list_not_found) == 0 else list_not_found)
        listFakeLib = (
            '' if len(list_fake_lib) == 0 else list_fake_lib)
        list_cont = []
        if not list_containers:
            list_cont = 'No analysis for containers'
        else:
            for container in list_containers.split('+'):
                    if (container in list_prop_not_found):
                        trust_cont = 'untrusted'
                    else:
                        trust_cont = 'trusted'
                    jsonCont = {'container': container,
                                'trust_lvl': trust_cont}
                    list_cont.append(jsonCont)
        jsonExtraDetails = {'Digest ok': n_digests_ok,
                            'Digest not found': n_digests_not_found,
                            'Digest fake lib': n_digests_fake_lib,
                            'List Digest not found': listNotFound,
                            'List Digest Fake Lib': listFakeLib,
                            'Packages ok': n_packages_ok,
                            'Packages security': n_packages_security,
                            'Packages unknown': n_packages_unknown,
                            'Packages not security':
                            n_packages_not_security}
        jsonHost = json.loads(host.text)['hosts']
        for jsonElem in jsonHost:
            host_name = jsonElem['host_name']
            host_trust = jsonElem['trust_lvl']
            if host_trust == 'unknown':
                analysis_status = 'PROBLEM_IN_OAT'
            elif host_trust != 'timeout':
                analysis_status = (
                      jsonElem['analysis_details']['status'])
            else:
                analysis_status = 'HOST_NOT_CONNECTED'
            if 'host' in list_prop_not_found:
                host_trust = 'untrusted'
            else:
                host_trust = 'trusted'
            jsonHost = {'node': host_name, 'trust_lvl': host_trust,
                        'analysis_status': analysis_status,
                        'analysis_containers': list_cont,
                        'analysis_extra_info': jsonExtraDetails}
        return jsonHost


class JsonListHost():
    """
    Added in JsonSingleHost an header
    {"NFVI": "trusted/untrusted",
     "vtime": "time_of_attestation",
     "details": ["list of JsonSingleHost"]}
    """
    def defineListHosts(self, listHost, vtime, trust_lvl):
        jsonHosts = {"NFVI": trust_lvl, "vtime": vtime, "details":
                     listHost}
        return jsonHosts
