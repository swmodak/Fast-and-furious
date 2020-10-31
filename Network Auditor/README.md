# Auditor tool

Tool to audit network devices for security configuration


# How to Run

 create a input file "devices" with router IP addresses.

Execute folling cli from same directory where auditor.py file is located.
```
$ python auditor.py devices
```


# Expected Output

Audit file 'audit_result.txt' is genrated.
output file contents as below -

#### Audit Result for Cisco Devices ####

##############
Device_127.0.0.1
##############
service password-encryption = PASS
enable secret = PASS
logging = PASS
ntp = FAIL
ip http server = PASS

 Total Fail count: 1/5

##############
Device_127.0.0.2
##############
service password-encryption = FAIL
enable secret = FAIL
logging = PASS
ntp = FAIL
ip http server = PASS

 Total Fail count: 3/5



# Future Enhancement

1) API to access the services to be added.
2) The Auditing service to be enhanced to add multi-vendor routers e.g, auding Juniper Router
2) the application nned to be ruuning as a microservices.
3) Call back to Cisco SecureX to be added.
