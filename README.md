# DefaultCredCheck
nmap http default credentials check

## Installation
replace /usr/share/nmap/nselib/data/http-default-accounts-fingerprints.lua with provided script

## Example
```shell
root@kali:~/Desktop# ./default_cred.py -t 192.168.2.0/24
[*] Valid target
[*] CMD: nmap --open -n --script http-default-accounts.nse -T4 192.168.2.0/24
[+] Found login on 192.168.2.126:80/axis2/axis2-admin/ with cred admin:axis2
[+] Found login on 192.168.2.126:443/axis2/axis2-admin/ with cred admin:axis2
```
