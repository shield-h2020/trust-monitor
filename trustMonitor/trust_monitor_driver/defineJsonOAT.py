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
    def defineSingleHost(self, respo, mapDigest, host):
        """
        Input response of the framework of attestation
        """
        info = mapDigest[host]
        listNotFound = (
            '' if len(info.list_not_found) == 0 else info.list_not_found)
        listFakeLib = (
            '' if len(info.list_fake_lib) == 0 else info.list_fake_lib)
        list_cont = []
        if not info.list_containers:
            list_cont = 'No analysis for containers'
        else:
            for container in info.list_containers.split('+'):
                    if (container in info.list_prop_not_found):
                        trust_cont = 'untrusted'
                    else:
                        trust_cont = 'trusted'
                    jsonCont = {'container': container,
                                'trust_lvl': trust_cont}
                    list_cont.append(jsonCont)
        jsonExtraDetails = {'Digest ok': info.n_digests_ok,
                            'Digest not found': info.n_digests_not_found,
                            'Digest fake lib': info.n_digests_fake_lib,
                            'List Digest not found': listNotFound,
                            'List Digest Fake Lib': listFakeLib,
                            'Packages ok': info.n_packages_ok,
                            'Packages security': info.n_packages_security,
                            'Packages unknown': info.n_packages_unknown,
                            'Packages not security':
                            info.n_packages_not_security}
        jsonHost = json.loads(respo.text)['hosts']
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
            if 'host' in info.list_prop_not_found:
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
