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
* pycryptodome
    
```
pip install ldap3 python-dateutil pycryptodome 
wget https://raw.githubusercontent.com/WiseLife42/GetADPSO/main/GetADPSO.py
```

# Usage
```
# python3 GetADPSO.py -h

usage: GetADPSO.py [-h] -u USERNAME -p PASSWORD -d DOMAIN [--dc-host DC_HOST] [--kerberos] [--ccache CCACHE] [-v]

Script to retrieve the msDS-ResultantPSO attribute for all users and groups in Active Directory, and show the details of PSO policies.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for Active Directory
  -p PASSWORD, --password PASSWORD
                        Password for Active Directory
  -d DOMAIN, --domain DOMAIN
                        Domain for Active Directory
  --dc-host DC_HOST     Domain Controller hostname or IP address
  --kerberos            Use Kerberos authentication
  --ccache CCACHE       Path to Kerberos ccache file
  -v, --debug           Enable debug logging for more details

```
## Running with a standard account
![image](https://github.com/user-attachments/assets/963d5c11-30fe-4152-93a8-7361a4fa2530)

## Running with a standard account (verbose)
![image](https://github.com/user-attachments/assets/2b2ed4ca-47e6-4c98-b1d0-be4af6c9963b)

## Running with an administrator account
![image](https://github.com/user-attachments/assets/532fe012-794d-4e11-a3b0-5b2db31279e9)

## Running with an administrator account (verbose)
![image](https://github.com/user-attachments/assets/9dc3f4f2-f4f7-4e80-8c78-8b9693d1d1c4)



