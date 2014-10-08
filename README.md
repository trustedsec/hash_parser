Quick Hash Parser / Comparer 

Written by: David Kennedy (ReL1K) @HackingDave from https://www.trustedsec.com

This is a hash parser that will export a rc file compatible with Metasploit. This is useful when compromising a seperate domain and want to see if any of the credentials work on another domain or other systems.

The first input is the filename that contains the hashes ex: Admin:500:LM:NTLM.
The second input is the remote IP address you want to use smb_logins on to validate if the creds work.
The third is the domain to attempt this on, leave this blank for workgroup

Usage: python hash_parser.py <hash_file.txt> <remote_ipaddr> <domain>
