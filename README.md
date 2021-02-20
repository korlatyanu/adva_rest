# adva_rest

written by Anton Korlatyanu (korlatyanu@yandex.ru, korlatyanu@yandex-team.ru). Not a programer in anyway (not a true DWDM engineer as well =), so don't judge hard.

script is usefull for engineers working with Adva FSP3000C products (CloudConnect).

Asyncio, REST-API based; can work with bunch of nodes simulteniosely.

%%
18:23:32 [korlatyanu@kcarbon ~]$ adva_rest.py -h                                         
usage: adva_rest.py [-h] [-d DEVICE] [-dd DEVICES [DEVICES ...]] [-a]
                    [-i IFACE]
                    [-c {diag,alarm,sysinfo,sw,sw_load,sw_del,db_backup,inventory}]
                    [-V VERSION] [-p PMTYPE [PMTYPE ...]]
                    [--pmfamily PMFAMILY [PMFAMILY ...]] [-t PMPERIOD]
                    [--history] [--step STEP] [--stepdelta STEP_DELTA]
                    [-w WIDTH] [-v] [-vv]

Adva  tool (REST-API)
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

optional arguments:
  -h, --help            show this help message and exit
  -d DEVICE, --device DEVICE
                        device name, defaults to dwdm-sas-1 if no argument
                        given
  -dd DEVICES [DEVICES ...], --devices DEVICES [DEVICES ...]
                        bunch of devices
  -a, --all             run on all devices (taken from RT with filter '{Adva
                        F8} and not {в оффлайн}'
  -i IFACE, --interface IFACE
                        by default only check 'line' ifaces. 'all' for clients
  -c {diag,alarm,sysinfo,sw,sw_load,sw_del,db_backup,inventory}, --command {diag,alarm,sysinfo,sw,sw_load,sw_del,db_backup,inventory}
                        optional, command to execute
  -V VERSION, --version VERSION
                        Only valid for 'sw_load', 'sw_del', version of pkg
  -p PMTYPE [PMTYPE ...], --pm PMTYPE [PMTYPE ...]
                        PM type to query (FEC/OSNR/power), case insensitive
  --pmfamily PMFAMILY [PMFAMILY ...]
                        PM type to query (QualityMod/NearEnd/Impairments)
  -t PMPERIOD, --period PMPERIOD
                        PM period to query (1m/15m/1h/24h), case insensitive
  --history             history knob # not implemented
  --step STEP           step for history (start-number-of-bin)
  --stepdelta STEP_DELTA
                        step delta for history (end-number-of-bin)
  -w WIDTH, --width WIDTH
                        pprint width when printing results
  -v, --verbose         be more verbose
  -vv, --debug          be even more verbose
%%


18:22:29 [korlatyanu@kcarbon ~]$ adva_rest.py -dd dwdm-vla1-4 dwdm-sas-1 -i /n -p opr snr
['dwdm-vla1-4', 'dwdm-sas-1']
*** dwdm-vla1-4 ***
{'1/1/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 13, 'snr': 17.5}}}},
 '1/1/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 5, 'snr': 17.2}}}},
 '1/2/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 11, 'snr': 17.6}}}},
 '1/2/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 5, 'snr': 17.6}}}},
 '1/3/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 4, 'snr': 16.8}}}},
 '1/3/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 2, 'snr': 17.2}}}},
 '1/4/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 14, 'snr': 17.4}}}},
 '1/4/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 7, 'snr': 17.3}}}},
 '1/5/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 7, 'snr': 17.4}}}},
 '1/5/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 6, 'snr': 17.4}}}},
 '1/6/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 13, 'snr': 17.4}}}},
 '1/6/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 6, 'snr': 16.9}}}},
 '1/7/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 9, 'snr': 17.6}}}},
 '1/7/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 6, 'snr': 17}}}}}


*** dwdm-sas-1 ***
{'1/1/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 7, 'snr': 17.2}}}},
 '1/1/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 7, 'snr': 17.9}}}},
 '1/2/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 9, 'snr': 17.6}}}},
 '1/2/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 5, 'snr': 16.9}}}},
 '1/3/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 9, 'snr': 17}}}},
 '1/3/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 10, 'snr': 17.1}}}},
 '1/4/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 9, 'snr': 17.3}}}},
 '1/4/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 4, 'snr': 16.6}}}},
 '1/5/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 10, 'snr': 16.6}}}},
 '1/5/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 10, 'snr': 16.6}}}},
 '1/6/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 8, 'snr': 17.1}}}},
 '1/6/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 7, 'snr': 17.2}}}},
 '1/7/n1': {'ot200/och': {'Impairments': {'nint': {'dgd': 10, 'snr': 17.3}}}},
 '1/7/n2': {'ot200/och': {'Impairments': {'nint': {'dgd': 4, 'snr': 16.9}}}}}





