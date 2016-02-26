#!/usr/bin/env python

'''
edit /usr/share/nmap/nselib/data/http-default-accounts-fingerprints.lua

update TomcatManager creds:

{username = "tomcat", password = "tomcat"},
{username = "tomcat", password = "manager"},
{username = "tomcat", password = "password"},
{username = "tomcat", password = "admin"},
{username = "admin", password = "admin"},
{username = "admin", password = "tomcat"},
{username = "admin", password = "password"},
{username = "admin", password = "manager"},
{username = "manager", password = "manager"},
{username = "manager", password = "tomcat"},
{username = "manager", password = "password"},
{username = "manager", password = "admin"},


add also Jboss checks:


table.insert(fingerprints, {
  name = "Jboss",
  category = "web",
  paths = {
    {path = "/jmx-console/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "JMXConsole"
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "jboss"},
    {username = "jboss", password = "admin"},
    {username = "jboss", password = "jboss"},
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Jboss unauthenticated",
  category = "web",
  paths = {
    {path = "/jmx-console/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return http.get(host, port, path).status == 200
  end
})

'''

import re, sys, commands
from termcolor import colored
from optparse import *


def log(IP, CRED, PATH, PORT):
	if options.f_out is not None:
		out_file.write("[+] Found login on "+IP+":"+PORT+PATH+" with cred "+CRED+"\r\n")
	print colored("[+] ","green")+"Found login on "+colored(IP+":"+PORT+PATH,"green")+" with cred "+colored(CRED,"green")


def f_read(filename):
	try:	
		in_file	= open(filename,"r")
		content = in_file.read()
		in_file.close()
		return content.split("\n\n")
	except:
		print colored("[-] ","red")+"File not found\n"
		sys.exit()


def ValidTarget():
	pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:$|\/\d{1,2}$)") 
	if pattern.match(options.target.strip()):
		print colored("[*] ","blue")+"Valid target"
		return 1
	else:
		print colored("[-] ","red")+"Invalid target"
		return 0


def work(list):
	for i in range(0,len(list)):
		if "found" in list[i]:
			struct = list[i].split("\n")
			for j in range(0,len(struct)):
				if "report for" in struct[j]:		
					IP = re.sub(".*for ","",struct[j])
				if "found" in struct[j]:	
					loot = re.sub(".*-> ","",struct[j])
					CRED = loot.split(" Path:")[0]
					PATH = loot.split(" Path:")[1]
					PORT = re.sub("/.*","",struct[j-1])
					log(IP, CRED, PATH, PORT)
				


############################################
#		MAIN     		   #
############################################

parser = OptionParser(usage='%prog [options]', description='Check for http default credentials')
parser.add_option('-f', '--file', type='string', dest="f_in", help='read from nmap output file')
parser.add_option('-t', '--target', type='string', dest="target", help='target to scan')
parser.add_option('-p', '--port', type='string', dest="port", help='target\'s port to scan')
parser.add_option('-w', '--write', type="string", dest="f_out", help='write log to file')

(options, args) = parser.parse_args()

if options.f_in is None and options.target is None:
	print "\n"+colored("[-] ","red")+"--file or --target option required\n"
	parser.print_help()
	print "\n"
        sys.exit()
if options.f_in is not None and options.target is not None:
	print "\n"+colored("[-] ","red")+"--file and --target option cannot be used together\n"
	parser.print_help()
	print "\n"
        sys.exit()
if options.f_in is not None:
	print colored("[*] ","blue")+"Reading file "+options.f_in
	list = f_read(options.f_in)
if options.target is not None:
	if not ValidTarget():
		sys.exit()
	if options.port is not None:
		print colored("[*] ","blue")+"CMD: nmap --open -n --script http-default-accounts.nse -T4 -p %s %s"%(options.port,options.target)
		output = commands.getoutput("nmap --open -n --script http-default-accounts.nse -T4 -p %s %s"%(options.port,options.target))
	else:
		print colored("[*] ","blue")+"CMD: nmap --open -n --script http-default-accounts.nse -T4 %s"%options.target
		output = commands.getoutput("nmap --open -n --script http-default-accounts.nse -T4 %s"%options.target)
	list = output.split("\n\n")
if options.f_out is not None:
	print colored("[*] ","blue")+"Log file is '%s'"%options.f_out
	out_file = open(options.f_out,"w")	

work(list)
sys.exit()
	
