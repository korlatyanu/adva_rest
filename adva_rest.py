#!/usr/bin/env python3.6

"""Adva  tool (REST-API)
examples:

# query current nint QFactor from tow NEs
adva_rest.py -dd dwdm-m9-sas1-1-new dwdm-sas1-m9-1-new -t now -p qf

# check SW on all NEs
adva_rest.py -a -c sw

# generate Diag.tgz and copy it to remote server
adva_rest.py -d dwdm-adva-test -c diag

# load SW to device
adva_rest.py -d dwdm-adva-test -c sw_load -V 3.2.1

# delete SW from device
adva_rest.py -d dwdm-adva-test -c sw_del -V 3.2.1

# backup DB from all devices
adva_rest.py -a -c db_backup

"""

import asyncio
import argparse
import logging
import traceback
import re

from pprint import pprint, pformat
from time import sleep
from datetime import date
from collections import defaultdict

import colorama
import aiohttp

import common_lib as cl

ENCODING = "utf-8"
MULTITASK = False
WIDTH = 180
LOGIN = ""  # put login here
PASSWORD = ""
FTP_SERVER = "93.158.158.93"  # noc-sas
FTP_PATH = "adva/"
FTP_SW_PATH = FTP_PATH + "Soft/F8_"


# pylint: disable=global-statement, broad-except, too-many-branches, invalid-name, attribute-defined-outside-init, no-else-return
# pylint: disable=too-many-lines, too-many-instance-attributes, too-many-arguments, no-self-use, too-many-locals, too-many-public-methods

def read_args():
    """Arguments declaration"""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--device", dest="device", help="device name, defaults to dwdm-sas-1 if no argument given")
    parser.add_argument("-dd", "--devices", dest="devices", nargs='+', help="bunch of devices")
    parser.add_argument("-a", "--all", dest="all", action="store_true",
                        help="run on all devices (taken from RT with filter '{Adva F8} and not {в оффлайн}'")
    parser.add_argument("-i", "--interface", dest="iface", help="by default only check 'line' ifaces. 'all' for clients")
    parser.add_argument("-c", "--command", dest="cmd",
                        choices=("diag",
                                 "alarm",
                                 "sysinfo",
                                 "sw",
                                 "sw_load",
                                 "sw_del",
                                 "db_backup",
                                 "inventory",
                                 ),
                        help="optional, command to execute")
    parser.add_argument("-V", "--version", dest="version", help="Only valid for 'sw_load', 'sw_del', version of pkg")
    parser.add_argument("-p", "--pm", dest="pmtype", nargs="+", help="PM type to query (FEC/OSNR/power), case insensitive")
    parser.add_argument("--pmfamily", dest="pmfamily", nargs="+", help="PM type to query (QualityMod/NearEnd/Impairments)")
    parser.add_argument("-t", "--period", dest="pmperiod", help="PM period to query (1m/15m/1h/24h), case insensitive")
    parser.add_argument("--history", dest="hist_cur", action="store_true", help="history knob # not implemented")
    parser.add_argument("--step", dest="step", help="step for history (start-number-of-bin)")
    parser.add_argument("--stepdelta", dest="step_delta", default=0, help="step delta for history (end-number-of-bin)")

    parser.add_argument("-w", "--width", dest='width', default=180, help="pprint width when printing results")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="be more verbose")
    parser.add_argument("-vv", "--debug", dest="debug", action="store_true", help="be even more verbose")

    return parser.parse_args()


def inhibit_exception(func):
    """функйия-декоратор для подавления исключений.
    Если возникло исключение, мы должны завершить сессию в NE, иначе они могут накопиться, и новые сессии нельзябудет открыть.
    """
    def wrapped(*args, **kwargs):
        logging.debug("wrapped insdide inhibit_exception got func %s ", func.__name__)
        logging.debug("wrapped insdide inhibit_exception kwargs %s ", str(**kwargs))
        #for arg in args:
        #    pprint(dir(arg))
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error("Error %s while executing %s", e, func.__name__)
            traceback.print_exc()
            args[0].logout()  # в нулевом аргументе сам экземпляр класса.
            #self.logout()
    return wrapped


class AdvaGet():
    """Class AdvaGet. Asyncio REST client to gather info from Adva DWDM boxes"""
    if LOGIN and PASSWORD:
        login, password = LOGIN, PASSWORD
    else:
        login, password = cl.read_creds("adva8")  # read credentials from external system
    devices_inv = {}  # тут будем хранить для каждого устройства установленные в него карты.

    body = {
        "in": {
            "un": login,
            "pswd": password,
            }
    }
    #common_header = {'Accept': 'application/json;ext=nn', 'Content-Type': 'application/json;ext=nn', 'AOS-API-Version': '1.0'}
    #
    uri = {"login": "/auth?actn=lgin",
           "logout": "/auth?actn=lgout",
           "auth": "/auth",
           "keepalie": "/auth?actn=ka",
           "sysinfo": "/mit/me/1",
           "pms": "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/opt/pm/crnt",
           "pmsn": [
               "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/opt/pm/crnt",
               "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/ctp/{MOD}/och/pm/crnt",
               "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/ctp/{MOD}/otuc2pa/pm/crnt",
               ],
           "inventory": '/col/eqh?filter={"sl":{"$exists":true},"$ancestorsIn":["/mit/me/1/eqh/sh,1"]}',  # only shelf 1. Need to check when stacked NEs will appear
           "alarm": "/mit/me/1/alm",
           "diag": "/mit/me/1/sysdiag?actn=gendiag",
           "cpdiag": "/mit/me/1/sysdiag?actn=cpdiag",
           "sw": "/mit/me/1/eqh/shelf,1/eqh/slot,ecm-1/eq/card/card/sw/active/pkg",
           "sw_load": "/mit/me/1/swmg?actn=cppkg",
           "sw_ecm_staging": "/mit/me/1/eqh/shelf,1/eqh/slot,ecm-1/eq/card/card/sw/staging/pkg",
           "sw_req_pkgs": "/mit/me/1/swmg/relmf/relcard/",  # to get requited pkgs // doesn't work in 3.1.5, 3.2.1
           "sw_del": "/mit/me/1/swmg?actn=rmpkg",
           "db_backup": "/mit/me/1/mgt?actn=bkcrnt",
           "db_load": "/mit/me/1/mgt?actn=dbto",
           }  # probably better to keep URIs in class. TODO

    def __init__(self,
                 fqdn,
                 url,
                 cmd=None,
                 pmtype=("all",),
                 pmtype_exact="",
                 pmfamily="",
                 pmperiod="nint",
                 iface_filter=None,
                 hist_cur="current",  # history PMs not supported yet
                 step=0,
                 step_delta=0
                 ):
        self.fqdn = fqdn
        self.host = None
        self.url = url
        self.cmd = []
        self.cmd.append(cmd)
        #self.slots = self.derive_device_slots()
        self.pmtype = pmtype  # list of possible PMs. used as a filter to entries received from NE
        self.pmtype_exact = pmtype_exact  # exact PM
        self.pmperiod = pmperiod
        self.pmfamily = pmfamily
        self.iface = iface_filter
        self.hist_cur = hist_cur  # not used as of now
        self.step = step
        self.step_delta = step_delta
        self.res_out = ""
        self.dict_out = defaultdict()
        self.header = {'Accept': 'application/json;ext=nn', 'Content-Type': 'application/json;ext=nn', 'AOS-API-Version': '1.0'}
        self.cards = dict()
        #self.client_ports = defaultdict(list)
        logging.debug("Body is: %s", self.body)
        logging.debug("AdvaGet class values: %s", self.__dict__)

    @inhibit_exception
    async def get_inventory(self):
        """Function will query inventory info from device and fill the info about installed cards
            returnes the list from result
In [41]: for i in b["result"]:
    print(i["fnm"])
   ....:
node 1 shelf 1
node 1 slot 1/1
node 1 slot 1/2
node 1 slot 1/3
node 1 slot 1/4
node 1 slot 1/5
node 1 slot 1/6
node 1 slot 1/7
node 1 slot 1/cem
node 1 slot 1/ecm-1
node 1 slot 1/ecm-2
node 1 slot 1/ext-1
node 1 slot 1/ext-2
node 1 slot 1/fan-1
node 1 slot 1/fan-2
node 1 slot 1/psm-1
node 1 slot 1/psm-2
node 1 slot 1/psm-3
node 1 plug-slot 1/1/c1
node 1 plug-slot 1/1/c2"""
        #resp = self.session.get(self.url + self.uri["inventory"], headers=self.header, verify=False)
        _, tmp = await self.query_uri(self.uri["inventory"])
        # print("PRINT JSON" + pformat(resp.json()))
        return tmp["result"]  # this returns a list

    @inhibit_exception
    async def fill_inventory(self, inv_json):
        """"takes json data with inventory, creates inventory entries in object
        inv_json returned from device query consists of a list of cards
        """
        # shelf is index 0. Cards have the same number as in chassis even if some are not intsalled. THIS is not true
        logging.info("fill_inventory gets \n%s ", str(print_inv(inv_json)))
        for _, v in enumerate(inv_json):
            if "type" in v and v["type"] == "slot":
                if not "name" in v:
                    # there is always each slot listed even if empty, skip those without names
                    continue
                slot = v["dnm"]
                self.cards[slot] = v["name"]
        return None

    def get_port_slot(self, iface):
        """Parse iface name"""
        port_re = re.compile((r"""(?P<shelf>\d)/(?P<slot>[\d\w]+)/(?P<port>[\d\w]+)"""
                              r"""(/(?P<logic>[\w\d]+)(/(?P<sub_logic>[\w\d-]+))?)?"""))
        m = port_re.match(iface)
        if not m:
            logging.error("get_port_slot got improper iface!")
            return None, None, None
        logging.info("get_port_slot matches %s ", pformat(m))
        return m["shelf"], m["slot"], m["port"]

    async def __aenter__(self):
        """open session upon creating Class object with 'with'"""
        if await self.open_session():
            return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the connection"""
        await self.logout()

    async def open_session(self):
        """open https session to NE"""
        logging.info("open_session started")
        self.session = aiohttp.ClientSession()
        resp = await self.session.post(self.url + self.uri["login"], json=self.body, headers=self.header, verify_ssl=False)
        logging.info("sent %s to %s", self.url + self.uri["login"], self.fqdn)
        logging.info("sent %s", self.body)
        logging.info("got %s from %s", resp.status, self.fqdn)
        if resp.status != 200:
            logging.error("Failed to open session to %s, return code %s", self.fqdn, resp.status)
            return False
        else:
            logging.info("Opened session to %s, code %s, token %s", self.fqdn, resp.status, resp.headers['X-Auth-Token'])
            self.header["X-Auth-Token"] = resp.headers['X-Auth-Token']
            # logging.info("System info %s " % self.print_sysinfo())
            return True

    async def logout(self):
        """Logout from NE"""
        logging.info("Sending logout %s", self.header)
        lout = await self.session.post(self.url + self.uri["logout"], verify_ssl=False, headers=self.header)
        await self.session.close()
        logging.info("Logging out, status code %s", lout.status)
        logging.info("Logging out %s", lout.headers)

    @inhibit_exception
    async def get_sysinfo(self):
        """get NE sysinfo"""
        _, dict_out = await self.query_uri(self.uri["sysinfo"])
        return dict_out

    @inhibit_exception
    async def derive_modulation(self, slot, port):
        """this should guess the modulation type of the N port. Makes it dumbly trying to query config with ot200 first.
        If error, goes with ot100
        !!!Not ready for TF!!!
        """
        # slot is given as 'node 1 slot 1/2'
        # port is given as 'n1'
        slot = slot[-1]
        port = port[-1]
        uri = "/mit/me/1/eqh/shelf,1/eqh/slot," + slot + "/eq/card/ptp/nw," + port + "/ctp/"
        mods = ["ot200", "ot100"]
        for mod in mods:
            if await self.query_port_config(uri + mod) in [200, 204]:
                return mod
        return "unknown"

    @inhibit_exception
    async def query_port_config(self, uri):
        """this needs to be redone"""
        header = self.header
        logging.info("query_port_config sending %s ", self.url + uri)
        resp = await self.session.get(self.url + uri, headers=header)
        logging.debug("Raw data received from device: \n %s", pformat(resp.json()))
        return resp.status

    @inhibit_exception
    async def query_uri(self, uri):
        """General Get URI query"""
        header = self.header
        logging.info("query_uri sending %s %s", self.url + uri, pformat(header))
        resp = await self.session.get(self.url + uri, headers=header, verify_ssl=False)
        # pprint(resp.headers)
        if resp.status >= 200 and resp.status < 300:
            tmp = await resp.json()
        else:
            print(f"Failed to query uri '{uri}', status code {resp.status}")
            tmp = {}
        logging.debug("Code received from device: \n %s", pformat(resp.status))
        logging.debug("Raw data received from device: \n %s", pformat(tmp))
        return resp.status, tmp

    @inhibit_exception
    async def post_uri(self, uri, body):
        """General Post URI query"""
        header = self.header
        logging.info("sending %s %s", self.url + uri, pformat(header))
        resp = await self.session.post(self.url + uri, json=body, headers=header, verify_ssl=False)
        tmp = await resp.json()
        return resp.status, resp.headers, tmp

    @inhibit_exception
    def gather_pms_iface(self, iface):
        """"func needs to be redone with AIO!!!"""
        shelfnum, slotnum, portnum = self.get_port_slot(iface)
        portnum = portnum[-1]
        for uri in self.uri["pmsn"]:
            uri = uri.format(SHELFNUM=shelfnum, SLOTNUM=slotnum, PORTNUM=portnum, MOD="ot200")
            resp, data = self.query_uri(uri)
            if resp not in [200, 204]:
                return 1
            pms_data = self.pick_pms(data["result"])
            if iface not in self.dict_out:
                self.dict_out[iface] = pms_data
            else:
                self.dict_out[iface].update(pms_data)
        return 0

    @inhibit_exception
    async def query_col(self, uri, out_data):
        """recursively query PMs from NE"""
        _, data = await self.query_uri(uri)
        if not data:
            return out_data
        for item in data["result"]:
            logging.debug("query_col collected: \n %s", pformat(item["self"]))
            out_data[item["self"]] = item
        if "next" in data:
            logging.debug("query_col next uri: \n %s", pformat(data["next"]))
            uri = data["next"]
            await self.query_col(uri, out_data)
        return out_data

    @inhibit_exception
    def parse_col(self, data):
        """walk through data received from 'col' request. Write to result dict"""
        #dict_out = defaultdict(defaultdict(dict).copy)  # iface: {logical_iface: pmtype: [pmperiods]}
        dict_out = {}  # iface: {logical_iface: pmtype: [pmperiods]}
        # {'bintv': 'm15',
        #  'ctyp': '/cim/mm/moc/pm,cur',
        #  'dnm': 'm15-Power',
        #  'elpsd': 16,
        #  'name': 'Power',
        #  'pmdata': {'oprh': 5.8,
        #             'oprl': 5.8,
        #             'oprm': 5.8,
        #             'opth': 6.7,
        #             'optl': 6.7,
        #             'optm': 6.7},
        #  'self': '/mit/me/1/eqh/shelf,1/eqh/slot,4/eq/card/ptp/cl,1/optm/pm/crnt/m15,Power',
        #  'sts': 'prtl'},
        keys_of_interest = (
            #"bintv",
            "pmdata",
            #"self",
            #"dnm",
            )
        not_interesting_keys = (
            "Receiver",
            "RxQFnw100g",
            "RxQFnw200g"
        )
        merge_pmtype = {  # some PMtypess use different naming for different PMperiods
            "Impairments": ["Impairments", "ImpQFnw200g", "ImpQFnw100g"],
            "Power": ["IFQFnw", "Power", "IFAM20nw", "IF112gSR4", "IFunknown"],
        }
        not_interesting_ports = (
            "psm-",
            "fan-",
            "cem",
            "ecm-",
        )
        logging.debug("parse_col issued with PMtype %s, PMperiod %s: \n ", self.pmtype, self.pmperiod)
        for key, data_ in data.items():
            port, port_logical, pmperiod, pmtype = convert_entity(key)
            if self.pmperiod and not self.pmperiod in key and "all" not in self.pmperiod:
                logging.debug("dropped %s due pmperiod", port)
                continue
            if self.pmtype and not any(pm in key for pm in self.pmtype) and "all" not in self.pmtype:
                logging.debug("dropped %s %s due pmtype", port, key)
                continue
            if self.iface and not self.iface in port:
                logging.debug("dropped %s %s due iface", port, key)
                continue
            if not port or any(not_interesting_port in port for not_interesting_port in not_interesting_ports):
                # в общем /col данные по всем шелфам-картам-портам, нам не все интересно
                logging.debug("dropped %s %s due port not interesting", port, key)
                continue
            if pmtype in not_interesting_keys:
                logging.debug("dropped %s %s due key not interersting", port, key)
                continue
            if self.pmfamily and not any(pm in key for pm in self.pmfamily):
                logging.debug("dropped %s due pmfamily", port)
                continue
            logging.debug("left %s %s for further processing", port, key)
            for data_key, data_value in data_.items():
                if data_key not in keys_of_interest:
                    continue
                #dict_out[port][port_logical][pmtype].update(data_value)
                for merge_pm, merge_pms in merge_pmtype.items():
                    if pmtype in merge_pms:
                        pmtype = merge_pm
                for end_pmtype, end_value in data_value.items():
                    #print(self.pmtype_exact, end_pmtype)
                    if self.pmtype_exact and end_pmtype not in self.pmtype_exact:
                        logging.info("dropped %s %s due exact PM not match", end_pmtype, end_value)
                        continue
                    if port not in dict_out:
                        dict_out[port] = {}
                    if port_logical not in dict_out[port].keys():
                        dict_out[port][port_logical] = {}
                    if pmtype not in dict_out[port][port_logical].keys():
                        dict_out[port][port_logical][pmtype] = {}
                    if pmperiod not in dict_out[port][port_logical][pmtype].keys():
                        dict_out[port][port_logical][pmtype][pmperiod] = {}
                    if end_pmtype not in dict_out[port][port_logical][pmtype][pmperiod].keys():
                        dict_out[port][port_logical][pmtype][pmperiod][end_pmtype] = {}
                    # dict_out[port][port_logical][pmtype][pmperiod].update({data_key: data_value})
                    dict_out[port][port_logical][pmtype][pmperiod][end_pmtype] = end_value  # we basically keep only pmdata
        return dict_out

    @inhibit_exception
    async def sw_staging(self):
        """Func to return current pkgs in staging"""
        _, tmp = await self.query_uri(self.uri["sw_ecm_staging"])
        tmp2 = trim_dict(tmp, ["name"])
        if "result" not in tmp2:
            return ""
        pkg_present = [pkg["name"] for pkg in tmp2["result"]]
        self.print("Currently ECM staging contains:")
        print(pkg_present)
        return pkg_present

    async def sw_load(self, version):
        """func to upload the SW image to ECM staging"""
        pkg_present = await self.sw_staging()
        # по-хорошему нужно удалить старые имаджи
        # закачивать нужно пэкэджи для конкретных карт, нужно знать, какие карты есть в шасси.
        # _, tmp = await self.query_uri(self.uri["sw_req_pkgs"])  # тут он выдает список для всех карт, даже которых нет в NE
        # pprint(tmp)
        # pkgs_required = {}
        # for item in tmp["result"]:
        #     pkgs_required[item["dnm"]] = [it["name"] for it in item["relpkg"]]
        # pprint(pkgs_required)
        await self.fill_inventory(await self.get_inventory())
        self.print("\nDevice has cards:")
        pprint(self.cards)
        pkgs = (
            # F8
            f"f8-am-s20h-2-base-{version}-arm7-32bit.bz2.pak",
            f"f8-am-s23h-base-{version}-arm7-32bit.bz2.pak",
            f"f8-am-s23l-base-{version}-arm7-32bit.bz2.pak",

            f"f8-cc-3-{version}-hi-arm7-32bit.tar.gz.pak",
            f"f8-cem-2-{version}-hi-arm7-32bit.tar.pak",
            f"f8-cem-4-{version}-hi-arm7-32bit.tar.pak",
            f"f8-ecm-3-{version}-hi-ppc-64bit.tar.gz.pak",
            f"f8-ecm-2-{version}-hi-ppc-64bit.tar.gz.pak",
            f"f8-mp-2b4ct-base-{version}-arm7-32bit.bz2.pak",
            # TF
            f"f8-cc-3-{version}-hi-arm7-32bit.tar.gz.pak",
            f"f8-t-mp-2d12ct-base-{version}-arm7-32bit.bz2.pak",
            f"f8-tecm-{version}-hi-ppc-64bit.tar.gz.pak",
            f"f8-cem-2-{version}-hi-arm7-32bit.tar.pak",
        )
        pkgs_needed = [pkg for pkg in pkgs if any(card.lower().split("/")[-1] in pkg for card in self.cards.values())]
        # not all pkgs are named fine, some need be added manually
        if any("T-ECM" in card for card in self.cards.values()):
            pkgs_needed.append(f"f8-tecm-{version}-hi-ppc-64bit.tar.gz.pak")
        if any("T-CEM-2" in card for card in self.cards.values()):
            pkgs_needed.append(f"f8-cem-2-{version}-hi-arm7-32bit.tar.pak")
        pkgs_needed.append(f"f8-cc-3-{version}-hi-arm7-32bit.tar.gz.pak")  # all need CC
        self.print("\nPackages needed:")
        pprint(pkgs_needed)
        for pkg in pkgs_needed:
            if pkg in pkg_present:
                self.print("skipping %s, as present already at device %s" % (pkg, self.fqdn))
                continue
            self.print("now copying %s" % pkg)
            await self.sw_load_pkg(version, pkg)

    @inhibit_exception
    async def sw_load_pkg(self, version, pkg):
        """"download the pkg file"""
        path = FTP_SW_PATH + f"{version}/"
        body = {
            "in": {
                "name": path + pkg,
                "ftpinfo": {
                    "prot": "ftp",
                    "srvtype": "ipAddress",
                    "srvipaddr": FTP_SERVER,
                    "srvuid": "anonymous",
                    "srvpasswd": "blah"
                }
            }
        }
        code, headers, resp = await self.post_uri(self.uri["sw_load"], body)
        logging.info("returned %s:\n%s\n\n%s", code, pformat(headers), pformat(resp))
        if code != 202:
            self.print("Failed to copy %s cause %s", pkg, code, msg_type="error")
            return 1
        job = headers["Location"] + "/ajob"
        await self.poll_ajob(job, "copy %s" % pkg)

    @inhibit_exception
    async def poll_ajob(self, ajob, name):
        """wait in cycle for async job to finish"""
        while True:
            _, tmp = await self.query_uri(ajob)
            self.print(tmp["descr"])
            self.print((tmp["st"], "waiting..."))
            if tmp["st"] == "fin":
                self.print("finished %s at %s" % (name, self.fqdn), msg_type="finished")
                return True
            if tmp["st"] == "fail":
                self.print("failed to perform %s at %s" % (name, self.fqdn), msg_type="error")
                return False
            sleep(10)

    @inhibit_exception
    async def sw_del(self, version):
        """delete given version pkgs from staging"""
        pkgs_present = await self.sw_staging()
        pkgs_del = []
        for pkg in pkgs_present:
            if version in pkg:
                self.print(f"will delete pkg {pkg}")
                pkgs_del.append(pkg)
        body = {
            "in": {
                "name": pkgs_del
            }
        }
        code, headers, resp = await self.post_uri(self.uri["sw_del"], body)
        logging.info("returned %s:\n%s\n\n%s", code, pformat(headers), pformat(resp))
        if code != 200:
            self.print("Failed to delete cause %s", code, msg_type="error")
        else:
            self.print("succesfully deleted pkgs", msg_type="finished")

    @inhibit_exception
    async def gen_diag(self):
        """generate diag file"""
        body = {"in": {}}
        code, headers, _ = await self.post_uri(self.uri["diag"], body)
        if code != 202:
            self.print("Failed to generate diag for %s %s" % (self.fqdn, code), msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        return bool(await self.poll_ajob(job, "generate diag"))

    @inhibit_exception
    async def copy_diag(self,
                        prot="ftp",
                        srvtype="ipAddress",
                        srvipaddr=FTP_SERVER,
                        srvuid="anonymous",
                        srvpasswd="blah"):
        """copy diag data to server, noc-sas by default"""
        today = date.today()
        file = FTP_PATH + f"{self.fqdn}_{today.strftime('%Y%m%d')}_Diag.tgz"
        body = {
            "in": {
                "rfile": file,
                "toinfo": {
                    "prot": prot,
                    "srvtype": srvtype,
                    "srvipaddr": srvipaddr,
                    "srvuid": srvuid,
                    "srvpasswd": srvpasswd,
                }
            }
        }
        code, headers, _ = await self.post_uri(self.uri["cpdiag"], body)
        if code != 202:
            self.print("Failed to copy diag for %s %s" % (self.fqdn, code), msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        if await self.poll_ajob(job, "copy diag to remote"):
            self.print("Diag file saved to %s %s" % (srvipaddr, "/tftpboot/" + file), msg_type="finished")
        else:
            return False

    @inhibit_exception
    async def db_backup(self):
        """backup the DB"""
        body = {"in": {"fmt": "binary"}}
        code, headers, _ = await self.post_uri(self.uri["db_backup"], body)
        if code != 202:
            self.print("Failed to backup DB %s" % code, msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        return bool(await self.poll_ajob(job, "backup DB"))

    @inhibit_exception
    async def db_load(
            self,
            prot="ftp",
            srvtype="ipAddress",
            srvipaddr=FTP_SERVER,
            srvuid="anonymous",
            srvpasswd="blah"
        ):
        """copy DB data to server, noc-sas by default"""
        today = date.today()
        file = FTP_PATH + "sw_backup/f8/"+ f"{self.fqdn}_{today.strftime('%Y%m%d')}.db"
        body = {
            "in": {
                "name": file,
                "toinfo": {
                    "prot": prot,
                    "srvtype": srvtype,
                    "srvipaddr": srvipaddr,
                    "srvuid": srvuid,
                    "srvpasswd": srvpasswd,
                }
            }
        }
        code, headers, _ = await self.post_uri(self.uri["db_load"], body)
        if code != 202:
            self.print("Failed to upload DB for %s %s", self.fqdn, code, msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        if await self.poll_ajob(job, "copy DB to remote"):
            self.print("DB file saved to %s %s" % (srvipaddr, "/tftpboot/" + file), msg_type="finished")

    def pick_pms(self, data):
        """
         {'result': [{'bintv': 'nint',
             'ct': {'rev': '1'},
             'ctyp': '/cim/mm/moc/pm,cur',
             'dnm': 'nint-IFQFnw',
             'elpsd': 38310616,
             'fnm': 'node 1 interface 1/4/n1 opt-phy pm',
             'name': 'IFQFnw',
             'pmdata': {'lbc': 100, 'lsrtmp': 32.2, 'opr': -9, 'opt': 0},
             'self': '/mit/me/1/eqh/shelf,1/eqh/slot,4/eq/card/ptp/nw,1/opt/pm/crnt/nint,IFQFnw',
             'sts': 'tod'},]}
        """
        dict_out = {}
        pms_of_interest = [
            "opr",
            "opt",
            "snr",
            "correrr",
            "fecberm",
            "fecucb",
            "bbe",
            "ses",
            "uas",
            "es",
        ]
        for entry in data:
            if entry["bintv"] == self.pmperiod:
                for pm, pmv in entry["pmdata"].items():
                    logging.debug("pick_pms is cycling %s ", pm)
                    if any(pm.startswith(pm_of_interest) for pm_of_interest in pms_of_interest):
                        dict_out[pm] = pmv
        return dict_out

    def print(self, *argv, msg_type="regular"):
        """"print with device name"""
        if isinstance(*argv, str):
            string = argv[0].strip()
        else:
            string = " ".join(*argv)
        if msg_type == "error":
            color = colorama.Fore.RED
        elif msg_type == "finished":
            color = colorama.Fore.GREEN
        else:
            color = colorama.Fore.WHITE
        print(color, end="")
        print(f"{self.fqdn}: " + string)
        print(colorama.Style.RESET_ALL, end="")


def print_inv(_list):
    """prints inventory"""
    out = ""
    for i, v in enumerate(_list):
        out += "%s -> %s" % (i, v["fnm"])
        if "name" in v:
            out += " name: " + v["name"]
        out += "\n"
    return out


def trim_dict(_dict, keys_of_interest=None, skip_keys=()):
    """"This function should leave only specified keys in given dict"""
    if not keys_of_interest:
        return _dict
    dict_out = {}
    rubbish_keys = [
        "result",
    ]
    if not skip_keys:
        skip_keys = ("ct")
    keys_of_interest += rubbish_keys
    logging.debug("trim_dict is issued")
    for k, v in _dict.items():
        if k in skip_keys:
            continue
        logging.debug("trim_dict Iterating over %s", k)
        if isinstance(v, dict):
            logging.debug("trim_dict Iterating over %s", k)
            tmp = trim_dict(v, keys_of_interest, skip_keys)
            if tmp:
                dict_out[k] = tmp
        if v.__class__ in (list, tuple, set):
            if not v:
                continue
            dict_out[k] = list()
            for item in v:
                if item.__class__ == dict:
                    dict_out[k].append(trim_dict(item, keys_of_interest, skip_keys))
            # continue
        if k in keys_of_interest:
            if k in rubbish_keys:
                continue
            if k not in dict_out:
                dict_out[k] = v
            else:
                if isinstance(dict_out[k], dict):
                    dict_out[k].update(v)
                else:
                    dict_out[k].append(v)
    return dict_out


def url_construct(device):
    """"repare URL from hostname"""
    return f"https://{device}.yndx.net"


def prepare_device(device):
    """prepare device name (append 'dwdm-' if needed)"""
    if device is None:
        device = "dwdm-adva-test"
    if "dwdm" not in device:
        device = f"dwdm-{device}"
    return device


def prepare_devices(devices):
    """devices can be given as src/dst dcs
    aka VLA M9 or SAS STD
    or as devices list
    """
    rg = re.compile(r".*\d.*")
    if rg.match(devices[0]) or any("dwdm" in dev for dev in devices):
        # есть цифры в списке, значит задан список устройств
        return [prepare_device(device) for device in devices]
    else:
        # вероятно тут список локаций
        assert len(devices) == 2
        devices_out = []
        rt_devices = cl.get_devices_from_rt("{ADVA F8} and not {в оффлайне}")
        logging.info("Got devices from RT: %s", pformat(rt_devices))
        for rt_device in rt_devices:
            if devices[0].lower() in rt_device:
                if devices[1].lower() in rt_device:
                    devices_out.append(rt_device)
        return devices_out


def convert_entity(str_):
    """given entyty from Adva NE convert it to meaninngfull data"""
    port = ""
    port_logic = "phy"
    # example_data: r"""/mit/me/1/eqh/shelf,1/eqh/slot,5/eq/card/ptp/cl,1/ctp/et100/mac/pm/crnt/m15,MacNIrx"""
    # m = re.search((r"^.+/shelf,(?P<shelf>\d+).*/"
    #                r"slot,(?P<slot>\d+)/.*(?P<port_type>cl|nw),"
    #                r"(?P<port>\d+)(?:/.*(?P<port_logic>ot200|ot100|et100))?.*?"
    #                r"(?P<layer>odu4-1|odu4-2|odu4|otu4|otuc2pa|och|opt|optm|mac|ety6)"
    #                r"(?:(/(?P<sublayer>optl))?(?:/(?P<lane>\d+)?))?.*"
    #                r"(?P<pmperiod>nint|m15|day),(?P<pmtype>.+)$"
    #                ), str_)

    m = re.search((r"^.+/shelf,(?P<shelf>\d+)/.*"
                   r"slot,(?P<slot>\d+)/.*(?P<port_type>cl|nw),"
                   r"(?P<port>\d+)(?:/.*(?P<port_logic>ot\d00|et100))?.*?"
                   r"(?P<layer>odu4-\d|odu4|otu4|otsia|otuc\dpa|och|optm|opt|mac|ety6)"
                   r"(?:(/(?P<sublayer>optl))?(?:/(?P<lane>\d+)?))?.*"
                   r"(?P<pmperiod>nint|m15|day),(?P<pmtype>.+)$"
                   ), str_)  # https://regex101.com/r/FdWqmN/1/
    if not m:
        # currently only ifaces PMs are gathered. Meybe need to gather CPU from ECM as well.
        logging.debug("%s hasn't match", str_)
        return "", "", "", ""
    shelf, slot, port_type, port_num, logic = m.group("shelf"), m.group("slot"), m.group("port_type"), m.group("port"), m.group("port_logic")
    layer, sublayer, lane = m.group("layer"), m.group("sublayer"), m.group("lane")
    pmperiod, pmtype = m.group("pmperiod"), m.group("pmtype")
    port = f"{shelf}/{slot}/{port_type[0]}{port_num}"
    logic = "" if not logic else logic
    port_logic = f"{logic}/{layer}"
    if sublayer:
        port_logic += f"/{sublayer}{lane}"
    return port, port_logic, pmperiod, pmtype


def prepare_pms_arg(pmtype, pmperiod, hist_cur):
    """prepare PM type, period in a way readable by AdvaGet"""
    logging.debug("pmargs: %s %s", pmtype, pmperiod)
    pmt = []   # should be fixed (FEC, PCSrx, ...)
    pmt_exact = []  # can be anything
    pmfamily = []
    pmp = ""
    hc = "current" if not hist_cur else "history"
    if not pmtype:
        pmt = ("all",)
    elif any(p.lower() in ["fec", "ber-fec"] for p in pmtype):
        pmt = ["fec", "FEC"]
    elif any(p.lower() in ["snr", "osnr"] for p in pmtype):
        pmt = ["OSNR", "snr", "Impairments", "ImpQFnw200g", "ImpQFnw100g", "QualityMod", "QualityTF600g32h64Q"]
    elif any(p.lower() in ["opr", "power"] for p in pmtype):
        # pmt = ["opr", "Power", "IFunknown", ]
        pmt = ["opr", "IFQFnw", "IFTFnw", "Power", "IFAM20nw", "IFAM23Lnw", "IFAM23Lcl", "IF112gSR4", "IF112gLR4", "IFunknown"]
    elif any(p.lower() in ["err", "errors"] for p in pmtype):
        pmt = ["err", "NearEnd", "PCSrx", "PCStx", "MacNIrx", "MacNItx"]
    elif any(p.lower() in ["qf", "quality", "qfq"] for p in pmtype):
        pmt = ["qf", "RxQuality", "RxQFnw200g", "RxQFnw100g"]
    else:
        pmt = ("all",)
        if any(pm.islower() for pm in pmtype):
            # end pms are currently (3.1.5 and lower) in lowercase
            pmt_exact = pmtype
        else:
            pmfamily = pmtype
    if not pmperiod:
        pmp = "nint"
    elif pmperiod == "all":
        pmp = "all"
    elif pmperiod.lower() in ["nint", "now"]:
        pmp = "nint"
    elif pmperiod.lower() in ["15m", "15min", "m15"]:
        pmp = "m15"
    elif pmperiod.lower() in ["24h", "24hour", "1d", "1day", "day"]:
        pmp = "day"
    logging.info("prepare_pms_arg returns type: %s; exact_type: %s; period: %s; hist/cur: %s", pmt, pmt_exact, pmp, hc)
    return pmt, pmt_exact, pmfamily, pmp, hc


async def get_data(device, args):
    """AdvaGet entry point"""
    res_data = {}
    url = url_construct(device)
    pmtype, pmtype_exact, pmfamily, pmperiod, hist_cur = prepare_pms_arg(args.pmtype, args.pmperiod, args.hist_cur)
    if not pmfamily:
        pmfamily = args.pmfamily
    async with AdvaGet(
            device,
            url,
            args.cmd,
            pmtype=pmtype,
            pmtype_exact=pmtype_exact,
            pmperiod=pmperiod,
            pmfamily=pmfamily,
            hist_cur=hist_cur, step=args.step, step_delta=args.step_delta,
            iface_filter=args.iface,
    ) as adva_dev:
        # adva_dev = AdvaGet(device,
        #                    url,
        #                    args.cmd,
        #                    pmtype=pmtype,
        #                    pmtype_exact=pmtype_exact,
        #                    pmperiod=pmperiod,
        #                    pmfamily=pmfamily,
        #                    hist_cur=hist_cur, step=args.step, step_delta=args.step_delta,
        #                    iface_filter=args.iface,
        #                    )
        # if not await adva_dev.open_session():
        #     logging.error("Could not open session to %s " % adva_dev.fqdn)
        #     return 1
        # if args.iface:
        #     adva_dev.gather_pms_iface(args.iface)
        #     pprint(adva_dev.dict_out)
        #     return 1
        # inv_data = adva_dev.get_inventory()
        # adva_dev.fill_inventory(inv_data)
        if not adva_dev:
            return None
        if not args.cmd:
            # not cmd given, will query PMs
            uri = "/mit/me/1/eqh/shelf,1/eqh"
            uri = adva_dev.uri["pms"].format(SHELFNUM=1, SLOTNUM=4, PORTNUM=1)
            uri = '/col/cur?filter={"$ancestorsIn":["/mit/me/1/eqh/shelf,1/eqh/slot,4/"]}'
            uri = '/col/cur'
            data = await adva_dev.query_col(uri, dict())  # here we get dict with all the PMs for all cards and ifaces
            res_data = adva_dev.parse_col(data)
        else:
            # here do the cmd
            if any(c in args.cmd for c in ("show_alarm", "alarm")):
                _, tmp = await adva_dev.query_uri(adva_dev.uri["alarm"])
                res_data = trim_dict(tmp, ["condescr", "ednm", "repttim"])
            elif args.cmd == "sw":
                _, tmp = await adva_dev.query_uri(adva_dev.uri["sw"])
                res_data = trim_dict(tmp, ["version"])
            elif any(c in args.cmd for c in ("diag", "gen_diag")):
                if await adva_dev.gen_diag():
                    await adva_dev.copy_diag()
            elif any(c in args.cmd for c in ("sysinfo", "show_sysinfo")):
                res_data = await adva_dev.get_sysinfo()
            elif args.cmd == "sw_load":
                sw = "3.2.1" if not args.version else args.version
                await adva_dev.sw_load(sw)
            elif args.cmd == "sw_del":
                sw = "2.1.2" if not args.version else args.version
                await adva_dev.sw_del(sw)
            elif args.cmd == "db_backup":
                if await adva_dev.db_backup():
                    await adva_dev.db_load()
            elif args.cmd == "inventory":
                _, tmp = await adva_dev.query_uri(adva_dev.uri["inventory"])
                res_data = trim_dict(tmp,
                                     ["fnm", "hwrev", "itemnum", "manfid", "name", "serial"],
                                     ("snmpeqp", "sm", "sl", "plgh", "displ", "sh")
                                     )
    # await adva_dev.logout()
    return res_data

    #for item in sorted(data.keys()):
        #print(item)
    #    print(convert_entity(item))
    # pprint(data)
    # try:
    #     Adva_dev.gather_pms()
    # except BaseException as err:
    #     logging.error("Exception has occured %s " % err)
    #     traceback.print_tb(err.__traceback__)



def main():
    """script entry point"""
    args = read_args()
    global MULTITASK
    global WIDTH
    WIDTH = int(args.width)
    frmt = u"[LINE:%(lineno)d]%(filename)s - %(funcName)s() - %(levelname)-8s [%(asctime)s]  %(message)s"
    # frmt = u"%(asctime)s %(name)s - %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(dev)s %(message)s"
    results = dict()
    if args.debug:
        logging.basicConfig(format=frmt, level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(format=frmt, level=logging.INFO)
    else:
        logging.basicConfig(format=frmt, level=logging.ERROR)
    if args.device:
        device = prepare_device(args.device)
        data = asyncio.get_event_loop().run_until_complete(get_data(device, args))
        results[device] = data
    elif args.devices:
        devices = prepare_devices(args.devices)
        pprint(devices)
        MULTITASK = True
    elif args.all:
        devices = cl.get_devices_from_rt("({ADVA F8} or {Adva TF})and not {в оффлайне}")  # get needed devices from inventory system
        pprint(devices)
        MULTITASK = True
    if not results:
        logging.info("Will gather data from devices: %s", pformat(devices))
        tasks = []
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for device in devices:
            tasks.append(loop.create_task(get_data(device, args)))
        try:
            res = loop.run_until_complete(asyncio.gather(*tasks))
        except Exception as e:
            logging.error(e)
        results = dict(zip(devices, res))
        loop.close()
    for device, res in results.items():
        if not res:
            logging.info("Device %s returns None", device)
            continue
        print(f"*** {device} ***")
        pprint(res, width=WIDTH)
        print("\n")


if __name__ == '__main__':
    main()
