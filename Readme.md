# ScanNewHosts

### Summary

Python script to scan your networks using nmap. Found hosts are compared to zabbix database. If host is not already in database, alert email ist sent. Inventory of zabbix is also updated with MAC address of host if found.

### Requirements

python3

nmap: `apt install nmap`

python-libs: `pip3 install pyzabbix python-nmap`

### Installation

1. Clone or download files to your scanner host
2. `cp config.yaml.example config.yaml`
3. adapt config.yaml to your environment  

### Run once
`python3 scanNewHosts.py`


### Run regulary

You may add a crontab entry like this to scan every 4 hours

`0 */4 * * * cd /opt/scanNewHosts && python3 /opt/scanNewHosts/scanNewHosts.py >> /var/log/scanNewHosts.log 2>&1`

Watch out that:
- you use the proper directory
- the log file is created and accessible by the user you run the script
