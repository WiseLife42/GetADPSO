# Introduction
This Python script retrieves and displays fine-grained password policies (FGPPs) applied to users and groups in Active Directory. It also displays details of configured PSO, including attributes such as minimum password length, password complexity, lockout duration, etc.

The script performs the following actions:
* Displays groups with PSO applied.
* Displays users with PSO applied.
* Displays details of PSO configured in Active Directory.

# Installation
## Prerequisites
* Python3
* ldap3
* python-dateutil
    
```
pip install ldap3 python-dateutil
wget https://raw.githubusercontent.com/WiseLife42/GetADPSO/main/GetADPSO.py
```

# Usage
```
# python3 GetADPSO.py -h

usage: GetADPSO.py [-h] -u USERNAME -p PASSWORD -d DOMAIN --dc-ip DC_IP

Script to retrieve the msDS-ResultantPSO attribute for all users and groups in Active Directory who have this attribute defined, and show the details of the PSO policies.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for Active Directory
  -p PASSWORD, --password PASSWORD
                        Password for Active Directory
  -d DOMAIN, --domain DOMAIN
                        Domain for Active Directory
  --dc-ip DC_IP         Domain Controller IP address

```
## Running with a standard account
![image](https://github.com/WiseLife42/GetADPSO/assets/80531900/25a6732f-9870-4c75-a093-44ad1b54c54b)

## Running with an administrator account
![image](https://github.com/WiseLife42/GetADPSO/assets/80531900/8f7e732b-c19a-45c7-b1b8-2d45eeb34191)



