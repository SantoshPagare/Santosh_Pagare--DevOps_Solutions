#!/usr/bin/python

import argparse
import subprocess
import fileinput
import re


parser = argparse.ArgumentParser(description="Script to \
    grant/revoke SSH access to a group of servers/instances to \
    a new developer.")
parser.add_argument('-a', '--action', dest='action', action='store',
                    choices={'grant', 'revoke'}, help='grant/revoke')
parser.add_argument('-s', '--servers', dest='servers', action='store',
                    help='comma-separated list of IP addresses of servers')
parser.add_argument('-u', '--user', dest='user', action='store',
                    help='username whose SSH access is to be granted or revoked')

args = parser.parse_args()

print "Action = %s" % args.action
print "Servers = %s" % args.servers
print "User = %s" % args.user

user = args.user

restart_service = """
print "Restarting sshd service"
proc = subprocess.Popen('systemctl restart sshd',
                        shell=True,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        )
stdout_value, stderr_value = proc.communicate('through stdin to stdout')
"""

grant_scriptlet = """ 
import re
import fileinput
import os
import crypt
import pwd
import subprocess

def remove_user_from_deny_list(username, line):
    fileToSearch = "/etc/ssh/sshd_config"
    textToSearch = line.rstrip('\\n')

    for line in fileinput.input(fileToSearch, inplace=True, backup='.bak'):
            if textToSearch in line:
                print line.replace(username, "").rstrip('\\n')
            else:
                print line.rstrip('\\n') 


def add_user_to_allow_list(username, line):
    fileToSearch = "/etc/ssh/sshd_config"
    textToSearch = line.rstrip('\\n')
    textToReplace = line.rstrip('\\n') + " " + username 

    for line in fileinput.input(fileToSearch, inplace=True, backup='.bak'):
            if textToSearch in line:
                print line.replace(textToSearch, textToReplace).rstrip('\\n')
            else:
                print line.rstrip('\\n')    

def grant_ssh_access(username):
    try:
          pwd.getpwnam(username)
          print "User %s already exists" % username
    except KeyError:
          print "User %s does not exist." % username
          password = username
          encPass = crypt.crypt(password,"22")   
          print "Creating user %s" % username
          os.system("useradd -p "+encPass+ " -s "+ "/bin/bash "+ "-d "+ "/home/" + username+ " -m "+ " -c \\""+ username+"\\" " + username)

    f = open('/etc/ssh/sshd_config', 'rt')
    flag = 0
    for line in f:
        if re.search(r"DenyUsers(.*)(?=\\b%s\\b)" % username, line):
            print "The user %s is present in DenyUsers list. Removing it..." % username
            remove_user_from_deny_list(username, line)
        if re.search("#\s*AllowUsers", line):  # If AllowUsers entry is present, but commented out
            print "AllowUsers entry present but commented out: %s" % line
        elif re.search(r"AllowUsers(.*)(?=\\b%s\\b)" % username, line):
            print "%s present : %s" % (username, line)
            flag = 1
        elif re.search(r"AllowUsers(.*)(?!\\b%s\\b)" % username, line):
            print "%s not present : %s" % (username, line)
            print "Adding user %s to the allowed list..." % username
            add_user_to_allow_list(username, line.rstrip('\\n'))
            flag = 1
    f.close()        
    if not flag:
        print "AllowUsers entry not present at all. Adding it..."
        with open("/etc/ssh/sshd_config", "a") as myfile:
            myfile.write("\\nAllowUsers %s\\n" % username)
            
"""
grant_scriptlet = grant_scriptlet + "\ngrant_ssh_access(\"%s\")" % user
grant_scriptlet = grant_scriptlet + "\n" + restart_service

revoke_scriptlet = """
import re
import fileinput
import os
import crypt
import subprocess

def add_user_to_deny_list(username, line):
    fileToSearch = "/etc/ssh/sshd_config"
    textToSearch = line.rstrip('\\n')
    textToReplace = line.rstrip('\\n') + " " + username

    for line in fileinput.input(fileToSearch, inplace=True, backup='.bak'):
            if textToSearch in line:
                print line.replace(textToSearch, textToReplace).rstrip('\\n')
            else:
                print line.rstrip('\\n')

def deny_ssh_access(username):
    f = open('/etc/ssh/sshd_config', 'rt')
    flag = 0  # entry not present
    for line in f:
        if re.search("#\s*DenyUsers", line):  # If DenyUsers entry is present, but commented out
            print "DenyUsers entry present but commented out: %s" % line
        elif re.search(r"DenyUsers(.*)(?=\\b%s\\b)" % username, line):
            print "%s present : %s" % (username, line)
            flag = 1
        elif re.search(r"DenyUsers(.*)(?!\\b%s\\b)" % username, line):
            print "%s not present : %s" % (username, line)
            print "Adding user %s to the denied list..." % username
            add_user_to_deny_list(username, line.rstrip('\\n'))
            flag = 1
            break
    f.close()
    if not flag:
        print "DenyUsers entry not present at all. Adding it..."
        with open("/etc/ssh/sshd_config", "a") as myfile:
            myfile.write("\\nDenyUsers %s\\n" % username)

"""
revoke_scriptlet = revoke_scriptlet + "\ndeny_ssh_access(\"%s\")" % user
revoke_scriptlet = revoke_scriptlet + "\n" + restart_service

if args.action == 'grant':
    scriptlet = grant_scriptlet
elif args.action == 'revoke':
    scriptlet = revoke_scriptlet


with open("ssh_access.py", "w") as text_file:
    text_file.write("%s" % scriptlet)


for ip in args.servers.split(","):
    print "Working on %s..." % ip
    # Note that since we are granting SSH access to a user by adding the user to AllowUsers list,
    # make sure that the user(s) that had SSH access previously also should be added to this list.
    proc = subprocess.Popen('ssh -o StrictHostKeyChecking=no santosh@%s sudo python < ./ssh_access.py' % ip,
                            shell=True,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            )
    stdout_value, stderr_value = proc.communicate('through stdin to stdout')
    for i in stdout_value.split('\n'):
        print i.rstrip('\n')
    if stderr_value:
        print 'stderr      :', repr(stderr_value)
