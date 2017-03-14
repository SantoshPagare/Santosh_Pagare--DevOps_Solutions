#!/bin/bash

python grant_revoke_ssh.py --action=grant --user=justin --servers=52.91.170.232,54.144.52.117

#python grant_revoke_ssh.py --action=revoke --user=david --servers=54.144.52.117

: <<'END'
Usage:
$ python grant_revoke_ssh.py --help
usage: grant_revoke_ssh.py [-h] [-a {revoke,grant}] [-s SERVERS] [-u USER]

Script to grant/revoke SSH access to a group of servers/instances to a new
developer.

optional arguments:
  -h, --help            show this help message and exit
  -a {revoke,grant}, --action {revoke,grant}
                        grant/revoke
  -s SERVERS, --servers SERVERS
                        comma-separated list of IP addresses of servers
  -u USER, --user USER  username whose SSH access is to be granted or revoked
END


#Approach:
#We ssh to each server in the group of servers and execute the grant_revoke_ssh.py script remotely. We
#have ssh access for a particular user to the remote servers, which will help us in granting/revoking
#ssh access to new users.
#
#NB:
#Note that since we are granting SSH access to a user by adding the user to AllowUsers list,
#we should make sure that the user(s) that had SSH access previously also should be added to this list.
#(This has not been taken care by the script).
#AllowUsers restricts ssh access to only those in the list. There might be a possibility that we grant
#access to new developer 'dev1' using 'admin' user by adding 'dev1' to AllowUsers list and don't add or 
#forget to add 'admin' himself. Since 'admin' isn't in the AllowUsers list, he won't be able to ssh.
