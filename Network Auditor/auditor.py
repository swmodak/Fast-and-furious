#!/usr/bin/env python3

import paramiko
import time
import datetime
from ciscoconfparse import CiscoConfParse

TNOW = datetime.datetime.now().replace(microsecond=0)

username = 'admin'
password = 'admin'

import sys
inFile = sys.argv[1]
outFile = "audit_result"


with open(inFile,'r') as i:
    ips = i.readlines()



def open_sshconn(ip, auditFile):
    print('\n #### Connecting to the device ' + ip + '####\n')

    SESSION = paramiko.SSHClient()
    SESSION.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SESSION.connect(ip, port=22,
                    username=username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False)

    DEVICE_ACCESS = SESSION.invoke_shell()
    DEVICE_ACCESS.send(b'terminal len 0\n')
    DEVICE_ACCESS.send(b'show run\n')
    time.sleep(10)
    output = DEVICE_ACCESS.recv(65000)

    SAVE_FILE = open('ROUTER_' + ip + str(TNOW), 'w')
    SAVE_FILE.write(output.decode('ascii'))
    SAVE_FILE.close
    SESSION.close


    configFile = open(SAVE_FILE, "r")
    parse = CiscoConfParse(configFile)

    auditFile.write("\n##############\n")
    auditFile.write('Device_' + ip)
    auditFile.write("##############\n")
    cnt = 0; violation=0

    # service password-encryption
    print("Auditing encrypted password")
    cnt += 1
    if parse.find_lines('^service\spassword-encryption'):
        auditFile.write("service password-encryption = PASS \n")
    else:
        violation += 1
        auditFile.write("service password-encryption = FAIL \n")

    # enable secret
    print("auditing enable secret")
    cnt += 1
    if parse.find_lines('^enable\ssecret'):
        auditFile.write("enable secret = PASS \n")
    else:
        violation += 1
        auditFile.write("enable secret = FAIL \n")

    # logging
    print("auditing logging")
    cnt += 1
    if parse.find_lines('^logging\s\d') or parse.find_lines('^logging\shost\s\d'):
        auditFile.write("logging = PASS \n")
    else:
        violation += 1
        auditFile.write("logging = FAIL \n")

    # ntp
    print("auditing ntp server")
    cnt += 1
    if parse.find_lines('^ntp\sserver\s\d'):
        auditFile.write("ntp = PASS \n")
    else:
        violation += 1
        auditFile.write("ntp = FAIL \n")

    # ip http server
    print("auditing http server")
    cnt += 1
    if not parse.find_lines('^ip\shttp\sserver'):
        auditFile.write("no ip http server = PASS \n")
    else:
        violation += 1
        auditFile.write("ip http server = FAIL \n")

    auditFile.write("\n Total Fail count: {}/{} \n".format(violation, cnt))



def main():
    auditFile = open(outFile, "w")
    auditFile.seek(0)
    auditFile.write("#### Audit Result for Cisco Devices ####\n")
    for ip in ips:
        open_sshconn(ip, auditFile)
        print('\nDone for Device %s' % ip)
    auditFile.close



if __name__ == "__main__":
    main()