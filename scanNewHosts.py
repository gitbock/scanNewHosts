#!/usr/bin/python3
# ScanNewHosts.py scans networks for hosts. If host is found, query zabbix database if host already known.
# If host is known, try to update zabbix inventory with found MAC address. Only possible if scanned network is
# directly connected to scanner host, not routed.
# If not known, send email alert
#


# Requirements
# pip3 install pyzabbix python-nmap
# apt install nmap


import nmap
import smtplib
from email.message import EmailMessage
from pyzabbix import ZabbixAPI
from datetime import datetime
from lib.bsys_conf import *



def send_mail(subject, mail_body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = cfg['notify']['email']['from']
    msg['To'] = cfg['notify']['email']['to']
    msg.set_content(mail_body)
    try:
        s = smtplib.SMTP(cfg['notify']['email']['server'])
        print("Sending mail...")
        s.send_message(msg)
        s.quit()
    except Exception as ex:
        str_ex = str(ex)
        print("Error sending mail: {}".format(str_ex))


if __name__ == '__main__':
    global cfg
    cfg = read_config("./config.yaml")

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("{} Starting network scanner...".format(now))


    # Connect to Zabbix. If not possible -> useless as no option to compare found hosts to a database.
    print("Logging in to zabbix...")
    try:
        zapi = ZabbixAPI(cfg['zabbix']['url'])
        zapi.session.verify = cfg['tls']['verify-ca-cert-path']
        zapi.login(cfg['zabbix']['user'], cfg['zabbix']['pw'])
        print("Connected to Zabbix API Version %s" % zapi.api_version())
    except Exception as ex:
        str_ex = str(ex)
        print("Cannot login to zabbix. Exiting. {}".format(str_ex))
        send_mail("Error ScanNewHosts", "ScanNewHosts failed. Cannot login to zabbix: {}".format(str_ex))
        exit(-1)

    # Start Scanning
    nm = nmap.PortScanner()
    for n in cfg['scan']['networks']:
        print("------------Scanning network {}".format(n))
        nm.scan(hosts=n, arguments=cfg['scan']['nmap_para'])
        all_hosts = nm.all_hosts()  # get all hosts that were scanned
        for h in all_hosts:
            # extract infos from found hosts
            ip = nm[h]['addresses']['ipv4']

            # check if mac was found during scan
            mac = "unknown mac"
            vendor = "unknown vendor"
            if 'mac' in nm[h]['addresses']:
                mac = nm[h]['addresses']['mac']
                if nm[h]['vendor']:
                    vendor = nm[h]['vendor'][mac]
            print("Host {} - {} ({})".format(ip, mac, vendor))
            if ip in cfg['scan']['ignore']:
                print("Discovered Host {} ignored".format(h))
            else:
                print("Check if host in Zabbix...")
                zh = zapi.host.get(filter={"ip": ip}, output=["host"])
                if zh:
                    z_hostid = zh[0]["hostid"]
                    z_hostname = zh[0]["host"]
                    print("Found Host in Zabbix. Host Name: \"{}\" -> OK.".format(z_hostname))
                    # Try updating MAC
                    if mac != "unknown mac":
                        print("Updating {} with mac {} and vendor {}".format(ip, mac, vendor))
                        zh = zapi.host.update(hostid=z_hostid, inventory={"macaddress_a": mac})
                        zh = zapi.host.update(hostid=z_hostid, inventory={"vendor": vendor})

                else:
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print("ALERT!! New Host discovered: {}. Not in zabbix!!".format(ip))
                    mail_body = "Host {} {} ({}) discovered at {}".format(ip, mac, vendor, now)
                    send_mail("ALERT: new Host found", mail_body)

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("{} End Network Scanner".format(now))
