
"""
Download all vulns from Tenable.io
Name: Mike Weiss
Email: blackdog.gianttree@gmail.com
"""

import os
import csv
import multiprocessing
import re
import requests

# Get key strings from OS environment
ACCESS_KEY = os.environ["ACCESS_KEY"]
SECRET_KEY = os.environ["SECRET_KEY"]

out_filename = 'out_file.csv'
base_url = "https://cloud.tenable.com"
min_risk = 4

class tenable_api_path(object):
    """ Not the ideal use of OO, just added to show versatility """

    def __init__(self):
        self.acc_key = ACCESS_KEY 
        self.sec_key = SECRET_KEY

    def get_url(self, path):
        self.path = path
        self.headers = {'Content-type': 'application/json', 'X-ApiKeys': 'accessKey='+self.acc_key+'; secretKey='+self.sec_key}
        req = requests.get(base_url+path, headers=self.headers)
        return req.json()

    def get_curr_vulns(self):
        """ Get all current vulns """
        currvulns_req = self.get_url('/workbenches/assets/vulnerabilities')
        return currvulns_req['assets']

    def get_vulns_asset(self,asset_id):
        """ Get all vulns for asset """
        vuln_req = self.get_url('/workbenches/assets/'+str(asset_id)+'/vulnerabilities')
        return vuln_req['vulnerabilities']

    def get_plug_info(self,plugin_id):
        """ Get plugin info """
        vulninfo_req = self.get_url('/workbenches/vulnerabilities/'+str(plugin_id)+'/info')
        return vulninfo_req['info']


    def get_plug_out(self,asset_id, plugin_id):
        """ Get plugin output for asset """
        vulnout_req = self.get_url('/workbenches/assets/'+str(asset_id)+'/vulnerabilities/'+str(plugin_id)+'/outputs')
        return vulnout_req['outputs'][0]


def get_value(source, string):
    """ Get value or make empty"""
    empty_msg = ''
    try:
        value = source[string]
    except:
        value = empty_msg
    if value is None:
        value = empty_msg
    return value


def utf8_value(value):
    """ Decode Unicode """
    return str(value).decode('utf8')


def run_subproc(vuln):
    """ Pooled subprocess function """
    plugin_id = vuln['plugin_id']

    # Get additional details regarding vuln; try cache first, return failure
    try:
        try:
            vuln_info = vulninfo_cache[plugin_id]
        except:
            vuln_info = t.get_plug_info(plugin_id)
        vuln_out = t.get_plug_out(asset_id, plugin_id)
    except:
        return [['GetDataError', 'Plugin: '+str(plugin_id)]]

    # Setup output from all data sources, regex CVEs; return
    risk = utf8_value(get_value(vuln, 'severity'))
    name = get_value(vuln, 'plugin_name')
    desc = get_value(vuln_info, 'description')
    solu = get_value(vuln_info, 'solution')
    port = utf8_value(get_value(vuln_out, 'states')[0]['results'][0]['port'])
    plou = get_value(vuln_out, 'plugin_output')

    rex = re.compile(r'(CVE-\d{4}-\d{4})')
    cves = utf8_value(",".join([x for x in rex.findall(desc)]))

    data = [risk, port, cves, name, desc, solu, plou]
    return [data, [plugin_id, vuln_info]]


if __name__ == '__main__':

    t = tenable_api_path()

    # Set up output file
    out_file = open(out_filename, mode='wb')
    out = csv.writer(out_file, delimiter='|')
    head = ["Risk", "Host", "Port", "CVE", "Name", "Description", "Solution", "Plugin Output"]
    out.writerow([s.encode("utf-8") for s in head])

    # Create vuln info cache
    vulninfo_cache = {}

    # Get assets with vulns above minimum risk; add asset to list
    asset_data = []
    for asset in t.get_curr_vulns():
        add = True
        for group in asset['severities']:
            if all([(int(group['level']) >= min_risk), (int(group['count']) > 0)]):
                add = 1
                continue
        if add == True:
            asset_data.append(asset)
        else:
            continue

    # Go through asset list, grab vulns, write to file
    for asset in asset_data:
        asset_id = asset['id']

        # Set host as FQDN or fallback to IP
        try:
            host = asset['fqdn'][0]
        except:
            host = asset['ipv4'][0]

        # Get asset vulns and ensure above minimum risk; add to list
        vulns_data = []
        for vuln in t.get_vulns_asset(asset_id):
            if all([(int(vuln['severity']) >= min_risk), (str(vuln['vulnerability_state']) != "Fixed")]):
                vulns_data.append(vuln)

        # Run subprocesses
        pool = multiprocessing.Pool(8)
        jobs = pool.map(run_subproc, vulns_data)

        for job in jobs:
            job[0].insert(1, host)

            # Encode UTF8, write row
            out.writerow([s.encode("utf-8") for s in job[0]])

            # Cache vuln info if not exist
            try:
                try:
                    vulninfo_cache[job[1][0]]
                except:
                    vulninfo_cache[job[1][0]] = job[1][1]
            except:
                continue

        pool.terminate()

    out_file.close()


