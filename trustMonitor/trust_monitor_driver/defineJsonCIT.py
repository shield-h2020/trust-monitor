class DefineJsonCIT():

    def createJson(self, host, trust_lvl, mapDigest):
        """
        Input response of the framework of attestation
        """
        try:
            info = mapDigest[host.hostName]
        except KeyError as ke:
            json_err = {'Error': 'No performed attestation of node '
                        + host.hostName}
            return json_err
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
        jsonHost = {'node': host.hostName, 'trust_lvl': trust_lvl,
                    'analysis_containers': list_cont,
                    'driver': host.driver,
                    'analysis_extra_info': jsonExtraDetails}
        return jsonHost


class JsonListHostCIT():
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
