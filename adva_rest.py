#!/usr/bin/env python3.6

r"""Adva  tool (REST-API)
examples:

# query current nint QFactor from tow NEs
adva_rest.py -dd dwdm-m9-sas1-1-new dwdm-sas1-m9-1-new -t now -p qf

# check SW on all NEs
adva_rest.py -a -c sw
adva_rest.py -a -c sw | perl -pe "s/\*\n/\* /g" | grep 2.2.1

# generate Diag.tgz and copy it to remote server
adva_rest.py -d dwdm-adva-test -c diag

# load SW to device
adva_rest.py -d dwdm-adva-test -c sw_load -V 3.2.1

# upgrade SW (sw_load -> sw_install -> sw_activate)
# use at your own risk!!!
adva_rest.py -d dwdm-adva-test -c sw_upgrade

# delete SW from device
adva_rest.py -d dwdm-adva-test -c sw_del -V 3.2.1

# backup DB from all devices
adva_rest.py -a -c db_backup

# check alarms, rm some noisy lines
adva_rest.py -a -c alarm | grep -v "interface\|plug\|License expires"

"""

import asyncio
import argparse
import logging
import re
import os
import json

from pprint import pprint, pformat
from time import sleep
from datetime import date
from collections import defaultdict
from tabulate import tabulate

import colorama
import aiohttp

try:
    import common_lib as cl  # local lib. not accessible from public sources.
except ImportError:
    pass

ENCODING = "utf-8"
TIMEOUT = 5  # aiohttp session timeout
MULTITASK = False
WIDTH = 180
LOGIN = "admin"  # put login here
PASSWORD = ""  # put password here. Can be put in environments, 'DWDM_PASSW'
FTP_SERVER = ""  # FTP to take SW from and to load DB and Diag to. ip addr.
FTP_PATH = "adva/"
FTP_SW_PATH = FTP_PATH + "Soft/F8_"
VERSION = "3.2.1"  # default SW for upgrade


# pylint: disable=global-statement, broad-except, too-many-branches, invalid-name, attribute-defined-outside-init, no-else-return
# pylint: disable=too-many-lines, too-many-instance-attributes, too-many-arguments, no-self-use, too-many-locals, too-many-public-methods
# pylint: disable=no-value-for-parameter, too-many-statements


if not FTP_SERVER:
    if "cl" in locals():
        FTP_SERVER = cl.FTP_SERVER


# URI value can be type  str or list
# if type list, format:
# uri name; keys_of_interest (list); skip_keys (list)
URI = {
    "login": "/auth?actn=lgin",
    "logout": "/auth?actn=lgout",
    "auth": "/auth",
    "keepalive": "/auth?actn=ka",
    # "pmsn": [  # not used in reality. It's difficult to use, as need to know all the layers of entity.
    #     "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/opt/pm/crnt",
    #     "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/ctp/{MOD}/och/pm/crnt",
    #     "/mit/me/1/eqh/shelf,{SHELFNUM}/eqh/slot,{SLOTNUM}/eq/card/ptp/nw,{PORTNUM}/ctp/{MOD}/otuc2pa/pm/crnt",
    # ],

    "cpdiag": "/mit/me/1/sysdiag?actn=cpdiag",
    "sw_req_pkgs": "/mit/me/1/swmg/relmf/relcard/",  # to get requited pkgs // doesn't work in 3.1.5, 3.2.1
    "db_load": "/mit/me/1/mgt?actn=dbto",
}

URI_CMD = {  # Maybe need to make a class out of it
    # here are URIs that can be called via '-c' arg
    "protect": ["/mit/me/1/eqh/shelf,1/eqh/slot,1/eq/card/prtgrp/traffic%2F1/prtunit", ["fnm", "type", "state"]],
    "inventory": [
        '/col/eqh?filter={"sl":{"$exists":true},"$ancestorsIn":["/mit/me/1/eqh/sh,1"]}',
        ["fnm", "hwrev", "itemnum", "manfid", "name", "serial"],
        ["snmpeqp", "sm", "sl", "plgh", "displ", "sh"],
    ],
    # only shelf 1. Need to check when stacked NEs will appear
    "alarm": ["/mit/me/1/alm", ["condescr", "ednm", "repttim"]],
    "log": [
        "/mit/me/1/systlog/log/{TYPE}/nelogent",
        [
            # "condescr",
            # "condtyp",
            # "detectm",
            "ednm",
            "evttm",
            "descr",
            "host",
            "mgmtp",
        ],
        ["almi", ]
    ],
    "diag": "/mit/me/1/sysdiag?actn=gendiag",
    "sysinfo": "/mit/me/1",
    "sw": ["/mit/me/1/eqh/shelf,1/eqh/slot,ecm-1/eq/card/card/sw/active/pkg", ["version"]],
    "sw_load": "/mit/me/1/swmg?actn=cppkg",
    "sw_del": "/mit/me/1/swmg?actn=rmpkg",
    "sw_ecm_staging": ["/mit/me/1/eqh/shelf,1/eqh/slot,ecm-1/eq/card/card/sw/staging/pkg", ["name"]],
    "sw_install": "/mit/me/1/swmg?actn=instl",
    "sw_activate": "/mit/me/1/swmg?actn=actv",
    "db_backup": "/mit/me/1/mgt?actn=bkcrnt",
    "time": "/mit/me/1/datm/tim",
    "license": ["/mit/me/1/lmsys/lm", ["avail", "name", "grntd", "used"], ["fmprfid"]],
    "shelf": "/mit/me/1/eqh/shelf,1",
    # "pm": ["/mit/me/1/eqh/shelf,{SHELF}/eqh/slot,{SLOT}/eq/card/ptp/nw,{PORT}/opt/pm/crnt"],  # do not use it
}

URI.update(URI_CMD)


def read_args():
    """Arguments declaration"""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--device", dest="device", help="device name, defaults to dwdm-sas-1 if no argument given")
    parser.add_argument("-dd", "--devices", dest="devices", nargs='+', help="bunch of devices")
    parser.add_argument("-a", "--all", dest="all", action="store_true",
                        help="run on all devices (taken from RT with filter '{Adva F8} and not {в оффлайн}'")
    parser.add_argument("-r", "--read", dest="devices_file", help="read devices from file")
    parser.add_argument("-i", "--interface", dest="iface", help="by default only check 'line' ifaces. 'all' for clients")
    parser.add_argument("-c", "--command", dest="cmd",
                        choices=(*URI_CMD.keys(), "sw_upgrade", "lldp"),
                        help="optional, command to execute")
    parser.add_argument("-V", "--version", dest="version", default=VERSION, help="Only valid for 'sw_load', 'sw_del', version of pkg")
    parser.add_argument("-p", "--pm", dest="pmtype", nargs="+", help="PM type to query (FEC/OSNR/power), case insensitive")
    parser.add_argument("--pmfamily", dest="pmfamily", nargs="+", help="PM type to query (QualityMod/NearEnd/Impairments)")
    parser.add_argument("-t", "--period", dest="pmperiod", help="PM period to query (1m/15m/1h/24h), case insensitive")
    parser.add_argument("-l", "--log", dest="log_type",
                        choices=("evt", "alm", "aud", "sec"),
                        default="alm",
                        help="Type of log to query."
                        )
    parser.add_argument("--uri", dest="uri", help="URI to query (only get URIs supported)")
    parser.add_argument("--history", dest="hist_cur", action="store_true", help="history knob")
    parser.add_argument("--step", dest="step", help="step for history. How many bins back needed")
    parser.add_argument("--stepdelta", dest="step_delta", default=0, help="step delta for history // not implemented. not needed even")
    parser.add_argument("-w", "--width", dest="width", default=180, help="pprint width when printing results")
    parser.add_argument("--raw", dest="raw", action="store_true", help="don't filter the output dict")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="be more verbose")
    parser.add_argument("-vv", "--debug", dest="debug", action="store_true", help="be even more verbose")
    args_ = parser.parse_args()
    if args_.version.startswith("4."):
        args_.version += "-1"  # they've encoded another capability to sw name. "-1" means not service impact.
    return args_


class AdvaGet():
    """Class AdvaGet. Asyncio REST client to gather info from Adva DWDM boxes"""
    if LOGIN and PASSWORD:
        login, password = LOGIN, PASSWORD
    else:
        try:
            login, password = cl.read_creds("adva8")  # read credentials from external system
        except NameError:
            login = LOGIN
            password = os.environ.get("DWDM_PASSW")
    devices_inv = {}  # тут будем хранить для каждого устройства установленные в него карты.

    body = {
        "in": {
            "un": login,
            "pswd": password,
            }
    }
    #common_header = {'Accept': 'application/json;ext=nn', 'Content-Type': 'application/json;ext=nn', 'AOS-API-Version': '1.0'}
    #

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
        #resp = self.session.get(self.url + URI["inventory"], headers=self.header, verify=False)
        uri, _, _ = uri_transform(URI["inventory"])
        _, tmp = await self.query_uri(uri)
        return tmp["result"]  # this returns a list

    async def fill_inventory(self, inv_json):
        """"takes json data with inventory, creates inventory entries in object
        inv_json returned from device query consists of a list of cards
        """
        # shelf is index 0. Cards have the same number as in chassis even if some are not intsalled. THIS is not true
        logging.info("fill_inventory gets \n%s ", pformat(inv_json))

        for _, v in enumerate(inv_json):
            if "type" in v and v["type"] == "slot":
                if not "name" in v:
                    # there is always each slot listed even if empty, skip those without names
                    continue
                slot = v["dnm"]
                self.cards[slot] = v["name"]
        return None

    async def __aenter__(self):
        """open session upon creating Class object with 'with'"""
        if await self.open_session():
            return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the connection"""
        await self.logout()

    async def open_session(self):
        """open https session to NE"""
        logging.info("%s: open_session started", self.fqdn)
        try:
            timeout = aiohttp.ClientTimeout(connect=TIMEOUT)
            # if some host is unreachable, it'll take tiiime before showing results for reachable nodes. So timeout.
            self.session = aiohttp.ClientSession(timeout=timeout)
            resp = await self.session.post(self.url + URI["login"], json=self.body, headers=self.header, verify_ssl=False, )
        except Exception as e:
            logging.error("%s: %s", self.fqdn, e)
            return False
        logging.info("sent %s to %s", self.url + URI["login"], self.fqdn)
        logging.info("%s: auth with username %s", self.fqdn, self.body["in"]["un"])
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
        if "X-Auth-Token" not in self.header:
            logging.info("%s seems we're not logged in, so will not logout, just close the session", self.fqdn)
            await self.session.close()
            return None
        logging.info("%s: sending logout %s", self.fqdn, self.header)
        # lout = await self.session.post(self.url + URI["logout"], verify_ssl=False, headers=self.header)
        code = await self.general_post_uri(URI["logout"], body={})
        await self.session.close()
        logging.info("%s logging out, status code %s", self.fqdn, code)

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

    async def query_port_config(self, uri):
        """this needs to be redone"""
        header = self.header
        logging.info("query_port_config sending %s ", self.url + uri)
        resp = await self.session.get(self.url + uri, headers=header)
        logging.debug("Raw data received from device: \n %s", pformat(resp.json()))
        return resp.status

    async def query_uri_terminal(self, uri):
        """Terminal URI query. Probably not what you need"""
        header = self.header
        tmp = {}
        logging.info("sending %s %s", self.url + uri, pformat(header))
        resp = await self.session.get(self.url + uri, headers=header, verify_ssl=False)
        if 200 <= resp.status < 300:
            try:
                tmp = await resp.json()
            except json.decoder.JSONDecodeError:
                logging.error("JSONDecodeError happened")
                # Error happens for string like this: '"fecberm": -1e-18.0' due float after e
                txt = await resp.text()
                txt = re.sub(r"(e-\d+)\.0+", r"\1", txt)
                tmp = json.loads(txt)
        else:
            logging.error("%s: Failed to query uri '%s', status code %s", self.fqdn, uri, resp.status)
        logging.debug("Code received from %s: \n %s", self.fqdn, pformat(resp.status))
        logging.debug("Raw data received from %s: \n %s", self.fqdn, pformat(tmp))
        if "next" in tmp:
            logging.warning("%s 'next' key is present in json data for uri %s", self.fqdn, uri)
        return resp.status, tmp

    async def query_uri(self, uri, out_data=None):
        """General URI query. If output is big, there will be few chunks, 'next' points to URI with next chunk."""
        status, data = await self.query_uri_terminal(uri)
        if not out_data:
            out_data = dict()
            out_data["result"] = list()
        if not data:
            return status, out_data
        if "result" not in data:
            # if there will be data without 'result' but with 'next', we will miss further chunks here
            return status, data
        out_data["result"] += data["result"]
        if "next" in data:
            logging.warning("next uri: \n %s", pformat(data["next"]))
            uri = data["next"]
            await self.query_uri(uri, out_data=out_data)
        return status, out_data

    async def post_uri(self, uri, body):
        """General Post URI query"""
        header = self.header
        logging.info("sending %s\n%s,\nbody: %s", self.url + uri, pformat(header), pformat(body))
        try:
            resp = await self.session.post(self.url + uri, json=body, headers=header, verify_ssl=False)
            tmp = await resp.json()
            return resp.status, resp.headers, tmp
        except Exception as e:
            logging.error("%s: %s", self.fqdn, e)
            return 0, {}, {}

    async def general_post_uri(self, uri, body):
        """general POST URI func"""
        code, headers, _ = await self.post_uri(uri, body)
        if 200 < code > 300:
            self.print("Failed to POST URI %s" % code, msg_type="error")
            return False
        job = headers.get("Location", "")  # sw_activate will not have it
        if not job:
            # here it's probably sw_activate
            return True
        job += "/ajob"
        if await self.poll_ajob(job, uri):
            self.print("Job finished %s" % uri, msg_type="finished")
            return True

    def derive_uri(self, data):
        """Generate set of URIs. we get the data from '/col' URI, it contains all the resource addresses in '/mit' hierarchy"""
        uri = set()
        if "result" not in data:
            logging.error("%s no result in data")
            return uri
        for mit in data["result"]:
            self_ = mit.get("self", "")
            port, port_logical, _, _ = convert_entity(self_)
            if not port:
                logging.debug("%s: entry skipped due not port, %s, '%s'", self.fqdn, port, self_)
                continue
            port += "/" + port_logical
            if self.iface and not re.findall(self.iface, port):
                logging.debug("%s: skipped uri due port %s not match from args %s: %s", self.fqdn, port, self.iface, self_)
                continue
            if "/pm" not in self_:
                continue
            uri.add(self_.split("/pm/")[0] + "/pm/")
        logging.debug("URIs chosen for further query:\n%s", pformat(uri))
        return uri


    def parse_col(self, data):
        """walk through data received from 'col' request. Write to result dict"""
        #dict_out = defaultdict(defaultdict(dict).copy)  # iface: {logical_iface: pmtype: [pmperiods]}
        dict_out = {}  # iface: {logical_iface: pmtype: [pmperiods]}
        # example data:
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
            "stime",
            "idx",  # number of bin for hsistory PM
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
            "Impairments": ["Impairments", "ImpQFnw200g", "ImpQFnw100g",],
            "Power": ["IFQFnw",
                      "Power",
                      "IFAM20nw",
                      "IF112gSR4",
                      "IFunknown",
                      "PwrNwOPPM",
                      "PwrClOPPM",
                      "IFAM23Lnw",
                      "IFAM23Hnw",
                      "IFAM23Hcl",
                      ],
        }
        not_interesting_ports = (
            "psm-",
            "fan-",
            "cem",
            "ecm-",
        )
        logging.debug("%s parse_col issued with PMtype %s, PMperiod %s: \n ", self.fqdn, self.pmtype, self.pmperiod)
        # sometimes it's usefull to check what device gives in REST:
        # adva_rest.py -d dwdm-man-kiv-e -vv 2>&1 | i "'self': '/mit/me/"
        for item in data["result"]:
            key = item["self"]
            data_ = item
            port, port_logical, pmperiod, pmtype = convert_entity(key)
            logging.debug("%s: processing item '%s', port: '%s', port_logical: %s, pmperiod: %s, pmtype: %s",
                          self.fqdn,
                          item,
                          port,
                          pmperiod,
                          pmperiod,
                          pmtype,
                          )
            if self.pmperiod and not self.pmperiod in key and "all" not in self.pmperiod:
                logging.debug("%s: dropped %s due pmperiod '%s' vs '%s'", self.fqdn, port, pmperiod, self.pmperiod)
                continue
            if self.pmtype and not any(pm in key for pm in self.pmtype) and "all" not in self.pmtype:
                logging.debug("%s: dropped %s %s due pmtype '%s' vs '%s'", self.fqdn, port, key, pmtype, self.pmtype)
                continue
            if self.iface and not re.findall(self.iface, port + "/" + port_logical):
                logging.debug("%s: dropped %s %s due iface '%s' vs '%s'", self.fqdn, port, key, port + "/" + port_logical, self.iface)
                continue
            if not port or any(not_interesting_port in port for not_interesting_port in not_interesting_ports):
                # в общем /col данные по всем шелфам-картам-портам, нам не все интересно
                logging.debug("%s: dropped %s %s due port not interesting", self.fqdn, port, key)
                continue
            if pmtype in not_interesting_keys:
                logging.debug("%s: dropped %s %s due key not interersting", self.fqdn, port, key)
                continue
            if self.pmfamily and not any(pm in key for pm in self.pmfamily):
                logging.debug("%s: dropped %s due pmfamily '%s' vs ''%s", self.fqdn, port, key, pformat(self.pmfamily))
                continue
            logging.debug("%s: left %s %s for further processing", self.fqdn, port, key)
            add_data = {}
            for key_of_interest in keys_of_interest:
                if key_of_interest == "idx":
                    tmp = data_.get(key_of_interest, None)
                    if self.step:
                        if int(tmp) > int(self.step) - 1:
                            # go to next item
                            break
                    continue
                tmp = data_.get(key_of_interest, None)
                if not tmp:
                    continue
                if isinstance(tmp, str):
                    # not pmdata here
                    add_data[key_of_interest] = tmp
                    continue
                for merge_pm, merge_pms in merge_pmtype.items():
                    if pmtype in merge_pms:
                        pmtype = merge_pm
                for end_pmtype, end_value in tmp.items():  # iterate over pmdata
                    #print(self.pmtype_exact, end_pmtype)
                    if self.pmtype_exact and end_pmtype not in self.pmtype_exact:
                        logging.info("%s: dropped %s %s due exact PM not match '%s'", self.fqdn, end_pmtype, end_value, self.pmtype_exact)
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
                    if add_data:
                        dict_out[port][port_logical][pmtype].update(add_data)
        return dict_out

    async def sw_staging(self):
        """Func to return current pkgs in staging"""
        _, tmp = await self.query_uri(URI["sw_ecm_staging"][0])
        if "result" not in tmp:
            return ""
        pkg_present = [pkg["name"] for pkg in tmp["result"]]
        self.print("Currently ECM staging contains:")
        print(pkg_present)
        return pkg_present

    async def sw_load(self, version):
        """func to upload the SW image to ECM staging"""
        pkg_present = await self.sw_staging()
        # по-хорошему нужно удалить старые имаджи
        # закачивать нужно пэкэджи для конкретных карт, нужно знать, какие карты есть в шасси.
        # _, tmp = await self.query_uri(URI["sw_req_pkgs"])  # тут он выдает список для всех карт, даже которых нет в NE
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
            f"f8-os-oppm-f-base-{version}-arm7-32bit.bz2.pak",  # supported since 3.2.1
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
        pkgs_needed.append(f"f8-os-oppm-f-base-{version}-arm7-32bit.bz2.pak")  # TMP to launch FIN TODO remove
        self.print("\nPackages needed:")
        pprint(pkgs_needed)
        for pkg in pkgs_needed:
            if pkg in pkg_present:
                self.print("skipping %s, as present already at device %s" % (pkg, self.fqdn))
                continue
            self.print("now copying %s" % pkg)
            await self.sw_load_pkg(version, pkg)
        pkg_present = await self.sw_staging()
        return all(pkg in pkg_present for pkg in pkgs_needed)

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
        code, headers, resp = await self.post_uri(URI["sw_load"], body)
        logging.info("returned %s:\n%s\n\n%s", code, pformat(headers), pformat(resp))
        if code != 202:
            self.print("Failed to copy %s cause %s" % (pkg, code), msg_type="error")
            return 1
        job = headers["Location"] + "/ajob"
        await self.poll_ajob(job, "copy %s" % pkg)

    async def sw_activate(self):
        """"download the pkg file"""
        body = {
            "in": {
                "actparam": {
                    "valtmren": False,
                    "now": True,
                    "valtmr": 30,
                }
            }
        }
        yes = input(f"{self.fqdn}: this will activate SW on device, access will be lost during reboot. Are you sure? Y/n: ")
        if re.findall(r"^[yY]+", yes):
            self.print("system will reboot")
            await self.general_post_uri(URI["sw_activate"], body)

    async def poll_ajob(self, ajob, name):
        """wait in cycle for async job to finish"""
        while True:
            _, tmp = await self.query_uri(ajob)
            self.print(tmp["descr"])
            self.print((tmp["st"], "waiting..."))
            descr = tmp.get("descr", "") + " " + name
            if tmp["st"] == "fin":
                self.print("finished %s" % descr, msg_type="finished")
                return True
            if tmp["st"] == "fail":
                self.print("failed to perform %s" % descr, msg_type="error")
                return False
            sleep(10)  # this is intentionnaly not asyncio

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
        code, headers, resp = await self.post_uri(URI["sw_del"], body)
        logging.info("returned %s:\n%s\n\n%s", code, pformat(headers), pformat(resp))
        if code != 200:
            self.print("Failed to delete cause %s" %code, msg_type="error")
        else:
            self.print("succesfully deleted pkgs", msg_type="finished")

    async def gen_diag(self):
        """generate diag file"""
        body = {"in": {}}
        code, headers, _ = await self.post_uri(URI["diag"], body)
        if code != 202:
            self.print("Failed to generate diag for %s %s" % (self.fqdn, code), msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        return bool(await self.poll_ajob(job, "generate diag"))

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
        code, headers, _ = await self.post_uri(URI["cpdiag"], body)
        if code != 202:
            self.print("Failed to copy diag for %s %s" % (self.fqdn, code), msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        if await self.poll_ajob(job, "copy diag to remote"):
            self.print("Diag file saved to %s %s" % (srvipaddr, "/tftpboot/" + file), msg_type="finished")
        else:
            return False

    async def db_backup(self):
        """backup the DB"""
        body = {"in": {"fmt": "binary"}}
        code, headers, _ = await self.post_uri(URI["db_backup"], body)
        if code != 202:
            self.print("Failed to backup DB %s" % code, msg_type="error")
            return False
        job = headers["Location"] + "/ajob"
        return bool(await self.poll_ajob(job, "backup DB"))

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
        # fixme use general_post_uri for all such funcs instead of bottom
        code, headers, _ = await self.post_uri(URI["db_load"], body)
        if code != 202:
            self.print("Failed to upload DB for %s %s" % (self.fqdn, code), msg_type="error")
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
        print(color, f"{self.fqdn}: " + string, colorama.Style.RESET_ALL)


def print_inv(_list):
    """prints inventory"""
    out = ""
    for i, v in enumerate(_list):
        out += "%s -> %s" % (i, v["fnm"])
        if "name" in v:
            out += " name: " + v["name"]
        out += "\n"
    return out


def uri_transform(uri):
    """sometimes URI is a string, sometimes it's a collection"""
    keys_of_interest = []
    skip_keys = []
    if isinstance(uri, list):
        if len(uri) == 3:
            skip_keys = uri[2]
        if len(uri) >= 2:
            keys_of_interest = uri[1]
        uri = uri[0]
    return uri, keys_of_interest, skip_keys


def parse_log(data):
    """given 'log' data, make it human-readable. Used for 'alarm' as well"""
    tab = []
    if "result" not in data:
        # if no alarms, device will return  {'result': []}
        # trim_dict will return {} in this case.
        return "nothing to show"
    for item in data["result"]:
        line = []
        descr = ""
        line.append(item.get("evttm", ""))  # 'evttm': '2018-01-05T02:50:21.1338Z'
        line.append(item.get("repttim", ""))  # alarm time for 'alarm'
        line.append(item["ednm"].replace("node 1 ", ""))  # 'node 1 interface 1/ecm-1/m/eth ety'
        descr = item.get("descr", "")  # 'descr': 'TCA unavailable seconds payload high'
        descr += item.get("condescr", "")  # 'descr': 'TCA unavailable seconds payload high'; for 'alarm'
        if "usri" in item:
            # this is for 'sec' log
            descr += "proto: " + item["usri"]["mgmtp"] + " from " + item["usri"]["host"]
        line.append(descr)
        tab.append(line)
    return tabulate(tab)


def parse_lldp(data):
    """pretty print for LLDP neighbors data"""
    tab = []
    for port, port_data in data.items():
        if not port_data:
            # some ports don't have lldp enabled or lldp neigbors
            continue
        line = []
        line.append(port)
        for item in port_data["result"]:
            lldp_entry = " ".join((item.get("snam", ""), item.get("pid", "")))
            line.append(lldp_entry)
        tab.append(line)
    return tabulate(tab)

def get_port_slot(iface):
    """Parse iface name. Not used as of now"""
    port_re = re.compile((r"""(?P<shelf>\d)/(?P<slot>[\d\w]+)/(?P<port>[\d\w]+)"""
                          r"""(/(?P<logic>[\w\d]+)(/(?P<sub_logic>[\w\d-]+))?)?"""))
    m = port_re.match(iface)
    if not m:
        logging.error("get_port_slot got improper iface!")
        return None, None, None
    logging.info("get_port_slot matches %s, shelf='%s', slot='%s', port='%s'", pformat(m), m["shelf"], m["slot"], m["port"])
    return m["shelf"], m["slot"], m["port"]


def trim_dict(_dict, keys_of_interest=None, skip_keys=None):
    """"This function should leave only specified keys in given dict"""
    if not keys_of_interest:
        return _dict
    dict_out = {}
    rubbish_keys = [
        "result",
    ]
    if not skip_keys:
        skip_keys = ["ct"]
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
    if rg.match(devices[0]) or any("dwdm" in dev for dev in devices) or "-" in devices[0]:
        # есть цифры в списке, значит задан список устройств
        return [prepare_device(device) for device in devices]
    else:
        # вероятно тут список локаций
        assert len(devices) == 2
        devices_out = []
        rt_devices = cl.get_devices_from_rt("({ADVA F8} or {Adva TF}) and not {в оффлайне}")
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
                   r"(?P<port>\d*[-,\w]*)(?:/.*(?P<port_logic>ot\d00|et100|ots|oms))?.*?"
                   r"(?P<layer>odu4-\d|odu4|otu4|otsia|otuc\dpa|och|optm|opt|mac|ety6|ots|oms|traffic)"
                   r"(?:(/(?P<sublayer>optl))?(?:/(?P<lane>\d+)?))?.*"
                   r"(?P<pmperiod>nint|m15|day),(?P<pmtype>.+)$"
                   ), str_)  # https://regex101.com/r/FdWqmN/1/
    if not m:
        # currently only ifaces PMs are gathered. Maybe need to gather CPU from ECM as well.
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
        pmt = ["OSNR",
               "snr",
               "Impairments",
               "ImpQFnw200g",
               "ImpQFnw100g",
               "QualityMod",
               "QualityTF600g32h64Q",
               "QualityTF200g16Q",
               "QualityTF400g16Q",
               ]
    elif any(p.lower() in ["opr", "power"] for p in pmtype):
        # items here might be not exact (IFAM instead of explicitly referencing each PM IFAM23Lnw, IFAM23Hnw)
        # FIXME use regexps
        # pmt = ["opr", "Power", "IFunknown", ]
        pmt = ["opr",
               "IFQFnw",
               "IFTFnw",
               "Power",
               "PwrNwOPPM",
               "PwrClOPPM",
               "IFAM20nw",
               "IFAM23Lnw",
               "IFAM23Lcl",
               "IFAM23Hcl",
               "IF112gSR4",
               "IF112gLR4",
               "IFunknown",
               "OSC",
               "IFAM23Hnw",
               "IFAM23Lvar1nw",
               ]
    elif any(p.lower() in ["err", "errors"] for p in pmtype):
        pmt = ["err", "NearEnd", "PCSrx", "PCStx", "MacNIrx", "MacNItx",]
    elif any(p.lower() in ["qf", "quality", "qfq"] for p in pmtype):
        pmt = ["qf",
               "RxQuality",
               "RxQFnw200g",
               "RxQFnw100g",
               "QualityTF",
               ]
    else:
        pmt = ("all",)
        if any(pm.islower() for pm in pmtype):
            # end pms are currently (3.1.5 and lower) in lowercase
            pmt_exact = pmtype
        else:
            pmfamily = pmtype
    if not pmperiod:
        if "err" in pmt or hist_cur:
            # err PMs are present only in m15, day period
            # history PMs need be m15 and day
            pmp = "all"
        else:
            # other PMs we probably want current value
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


def derive_lldp_uri(data):
    """we get PM uris from adva_dev.derive_uri, need to pick only C port mac resources and append the lldp URI tail"""
    uri = []
    for item in data:
        if "mac" not in item:
            continue

        uri.append(item.rstrip("/pm/") + "/lldpport/lldpbrid/nearest/rmtnode")
    return uri


def prepare_uri():
    """Func will prepare the parametrized URIs"""
    URI_CMD["log"][0] = URI_CMD["log"][0].format(TYPE=args.log_type)


def string_to_re(string):
    """convert given string to regex pattern"""
    string = re.sub(r"\*", ".*", string)  # swapp asterisk with re .*. If given string was already in re format, will duplitcate "."
    string = re.sub(r"\.+\*", ".*", string)  # eliminate previous
    string = ".*" + string + ".*"  # match anything in the begining and end of string
    return string


async def get_data(device):
    """AdvaGet entry point"""
    res_data = {}
    url = url_construct(device)
    pmtype, pmtype_exact, pmfamily, pmperiod, hist_cur = prepare_pms_arg(args.pmtype, args.pmperiod, args.hist_cur)
    if not pmfamily:
        pmfamily = args.pmfamily
    prepare_uri()
    iface_filter = None
    if args.iface:
        iface_filter = string_to_re(args.iface)
    async with AdvaGet(
            device,
            url,
            args.cmd,
            pmtype=pmtype,
            pmtype_exact=pmtype_exact,
            pmperiod=pmperiod,
            pmfamily=pmfamily,
            hist_cur=hist_cur, step=args.step, step_delta=args.step_delta,
            iface_filter=iface_filter,
    ) as adva_dev:
        if not adva_dev:
            return None
        if not args.cmd and not args.uri:
            # no cmd given, will query PMs
            uri = "/mit/me/1/eqh/shelf,1/eqh"
            # uri = URI["pms"].format(SHELFNUM=1, SLOTNUM=4, PORTNUM=1)  # humble tries
            uri = '/col/cur?filter={"$ancestorsIn":["/mit/me/1/eqh/shelf,1/eqh/slot,4/"]}'  # humble tries
            uri = "/col/cur"
            # uri = "/mit/me/1/eqh/shelf,1/eqh/slot,2/eq/card/ptp/nw,2/ctp/ot500/otsia/otsi/1/pm/hist"
            # uri = "/mit/me/1/eqh/shelf,1/eqh/slot,1/eq/card/ptp/nw,2/ctp/ot500/otuc5pa/pm/hist"
            _, data = await adva_dev.query_uri(uri)  # here we get dict with all the PMs for all cards and ifaces
            if args.hist_cur:
                # to query history PM we need to query specific resource (port, logical layer).
                # we can query current PMs all at once via '/col' URI. From there we can derive the resources (ports, etc) to later query
                # the hisroy PM for those resources.
                uri_resources = adva_dev.derive_uri(data)
                data = {}
                for uri in uri_resources:
                    _, tmp = await adva_dev.query_uri(uri + "hist")
                    if not data:
                        data = tmp
                    else:
                        data["result"] += tmp["result"]
            res_data = adva_dev.parse_col(data)
        elif args.uri:
            # we gave particular URI to query in script args.
            _, res_data = await adva_dev.query_uri(args.uri)
        else:
            # here do the cmd
            sw = VERSION if not args.version else args.version
            body = {'in': {}}
            if args.cmd == "lldp":
                # here we need to collect LLDP info from all C ports. We don't know what ports are there, we derive this from /col/cur
                # LLDP works in TF only
                _, data = await adva_dev.query_uri("/col/cur")
                lldp_uri_resources = derive_lldp_uri(adva_dev.derive_uri(data))
                for uri in lldp_uri_resources:
                    _, tmp = await adva_dev.query_uri(uri)
                    if "result" not in tmp and "self" not in tmp["result"]:
                        continue
                    port, _, _, _ = convert_entity(uri.split("lldp")[0] + "pm/crnt/day,FCK")  # stupid hack for convert entity to work
                    res_data[port] = (trim_dict(tmp, ["snam", "pid"]))
                return parse_lldp(res_data)
            elif args.cmd == "diag":
                if await adva_dev.gen_diag():
                    await adva_dev.copy_diag()
            elif args.cmd == "sw_load":
                await adva_dev.sw_load(sw)
            elif args.cmd == "sw_activate":
                # TODO make SW upgrade that will perform sw_load->sw_install->sw_activate
                # this will terminate the session, device will reboot (usually warm).
                await adva_dev.sw_activate()
            elif args.cmd == "sw_del":
                sw = "2.1.2" if not args.version else args.version
                await adva_dev.sw_del(sw)
            elif args.cmd == "sw_upgrade":
                if await adva_dev.sw_load(sw):
                    if await adva_dev.general_post_uri(URI["sw_install"], body):
                        await adva_dev.sw_activate()  # this will terminate the session
            elif args.cmd == "db_backup":
                if await adva_dev.db_backup():
                    await adva_dev.db_load()
            else:
                # here we call the uri
                uri, keys_of_interest, skip_keys = uri_transform(URI[args.cmd])
                if "actn" in uri:
                    # we have POST URI here
                    logging.info("%s: will process POST URI here", adva_dev.fqdn)
                    body = {'in': {}}  # TODO move it to URI
                    await adva_dev.general_post_uri(uri, body)
                    return None
                _, res_data = await adva_dev.query_uri(uri)
                if args.raw:
                    return res_data
                if not args.raw and (keys_of_interest or skip_keys):
                    res_data = trim_dict(res_data, keys_of_interest=keys_of_interest, skip_keys=skip_keys)
                if args.cmd == "log":
                    # we have dedicated parser for 'log'. TODO add parser to URI
                    res_data = parse_log(res_data)
                if args.cmd == "alarm":
                    res_data = parse_log(res_data)
    return res_data


def get_devices_from_file(_file):
    """read device list from file"""
    devices = []
    with open(_file) as file:
        for line in file:
            if not line.strip() or line.startswith("#"):
                continue
            devices.append(line.strip())
    return devices


def main():
    """script entry point"""
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
        data = asyncio.get_event_loop().run_until_complete(get_data(device))
        results[device] = data
    elif args.devices:
        devices = prepare_devices(args.devices)
        pprint(devices)
        MULTITASK = True
    elif args.devices_file:
        devices = get_devices_from_file(args.devices_file)
        pprint(devices)
        MULTITASK = True
    elif args.all:
        devices = cl.get_devices_from_rt("({ADVA F8} or {Adva TF}) and not {в оффлайне}")  # get needed devices from inventory system
        pprint(devices)
        MULTITASK = True
    if not results:
        logging.info("Will gather data from devices: %s", pformat(devices))
        tasks = []
        res = ""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for device in devices:
            tasks.append(loop.create_task(get_data(device)))
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
        if isinstance(res, str):
            print(res)
        else:
            pprint(res, width=WIDTH)
        print("\n")


if __name__ == '__main__':
    args = read_args()
    main()
