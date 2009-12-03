#!/usr/bin/env python
"""
Copyright (c) 2008-2009, Anthony FOIGNANT. All rights reserved.

A simple tool which make the configuration's backup of your SAN switches simple and easy. 
It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. 
You don't need to install or configure a SSH or a FTP server on your computer.

Contact Info:
  http://code.google.com/p/save-simply-your-san/
  antispameu-san@yahoo.fr
"""
#Import definitions
try:
    import SaveSimplyyourSAN
except ImportError:
    raise ImportError, 'This program requires the SaveSimplyyourSAN extension for Python. See http://code.google.com/p/save-simply-your-san/'

import sys
import threading
import Queue
import time
import socket
import os

from optparse import OptionParser

################################################################
## SaveSimplyyourSan-CLI() Function
## 
################################################################

def SaveSimplyyourSAN_CLI():
	#Main function, deals with arguments and launch the program
	if not sys.argv[1:]:
	    sys.stdout.write("Save Simply your SAN: version 0.95. You must specify more arguments. More help avalaible with -h or --help option")
            sys.exit(1)
	usage = "usage: %prog [options] arg"
	# Definitions of the options
	parser = OptionParser(usage)
	parser.add_option("-i", "--ip", help="IP of the switch (MANDATORY).", type="string", action="store", dest="ip")
	parser.add_option("-s", "--switch", help="Type of the switch. Possible values are : cisco (default) or brocade or mcdata or others", type="string", action="store", dest="switch", default="cisco")
	parser.add_option("-u", "--user", help="User on the switch (MANDATORY).", type="string", action="store", dest="user")
	parser.add_option("-p", "--password", help="Password of the user on the switch (MANDATORY).", type="string", action="store", dest="password")
	parser.add_option("-t", "--transfert", help="Type of transfert. Possible values are : scp (by default) or ftp", type="string", action="store", dest="transfert", default="scp")
	parser.add_option("-e", "--execute", help="Execute the given command or a comma separated list of commands onto the equipment ", type="string", action="store", dest="command")
	parser.add_option("-c", "--client", help="Type of client. Possible values are : ssh or telnet (SSH by default)", type="string", action="store", dest="client", default="ssh")
	parser.add_option("-g", "--generate", help="Generate a 1024 bits key for the SSH server. Possible values are : RSA or DSS. The key will be stored in the file new_server_type.key.", type="string", action="store", dest="generate", default="no")
	parser.add_option("-l", "--interface", help="The local IP interface on which the server will be attached", type="string", action="store", dest="interface")
	parser.add_option("-n", "--nat", help="The NAT IP address on which the server will be recheable", type="string", action="store", dest="nat")
	parser.add_option("--timeout", help="The timeout value for SSH or Telnet commands. 4.0 seconds by default", type="float", action="store", dest="timeout", default="10.0")
	parser.add_option("-d", "--debug", help="The debug level. Values are : yes or no (default).", action="store", dest="debug", default="no")
	parser.add_option("--dir", help="store the files in the directory specified. If non value is provided, the files are stored in a directory with the switch's name. If you provide the value 'byday', the files are stored in a directory named with the date. Values are : 'yourdirectory' or 'byday'.", type="string", action="store", dest="dir", default="no")
	#not implemented yet !
	#parser.add_option("-k", "--host-key", help="the Switch's SSH private key used for SSH authentication.", type="string", action="store", dest="key")
	parser.add_option("--known_hosts", help="The known_hosts file. Specify the known_host file you want to use. By default, it doesn't use any file and accept all connection to any host", type="string", action="store", dest="known_hosts", default="no")
	parser.add_option("--server_key", help="The server_key file used for the SSH server.", type="string", action="store", dest="server_key", default="server_rsa.key")
	parser.add_option("--server_key_type", help="The type of SSH key used for in the server_key file. Possible values are RSA or DSS", type="string", action="store", dest="server_key_type", default="RSA")
	parser.add_option("-z", "--zip", help="Zip the output's files. Possible values are yes or no (default)", type="string", action="store", dest="zip", default="no")
	(options, args) = parser.parse_args()

	# Generation of the SSH Server's key
	if options.generate == "RSA" or options.generate == "DSS" :
	    SaveSimplyyourSAN.GenerateServerKey(options.generate)
            print "A 1024 bits key has been generated successfuly in the file new_server_type.key. The public key is stored in the file new_server_type.pub"
            sys.exit(0)
        elif options.generate != "no":
	    print "*** Error : invalid argument ! Possibles values are RSA or DSS !"
	    sys.exit(1)

        # verifying mandatory arguments
	if not options.ip:
	    print '*** You must provide an IP address of a switch with -i !'
	    sys.exit(1)
	#if not options.user and not options.key:
	if not options.user:
	    print '*** You must provide a user with -u !'
	    sys.exit(1)
	#if not options.password and not options.key:
	if not options.password:
	    print '*** You must provide a password with -p !'
	    sys.exit(1)

        # A flag for debug
	if options.debug == 'yes':
	    options.debug = True
	else:
	    options.debug = False
	#initialising switch object
	switch = SaveSimplyyourSAN.Switch(options.ip, options.user, options.password, options.switch, options.client, options.transfert, float(options.timeout), options.interface, options.nat, options.dir, debug=options.debug, known_hosts=options.known_hosts, server_key=options.server_key, server_key_type=options.server_key_type, zipped=options.zip)
	if not switch.Connect(): 
	    print "*** Problem during Connection to the swith "
	    sys.exit(2)
	else: #switch connection successful
	    # we try to get the prompt and the to guess the switch's type
            if not switch.GetPromptAndType():
		print "*** Error : impossible to guess the equipment's type !"
		sys.exit(2)
            # we test the switch's type
            if not switch.TestType():
		print "*** Error with the type of switch !"
		sys.exit(2)	
	
	    #if a command is provided we grab the output of the command and store it
	    if options.command:
		commands = options.command.split(',')
		currentdir = os.getcwd()
		for command in commands:
		    output = switch.GetCommand(command)
	            filename = switch.name + '__' + command + '__' + time.strftime('%Y%m%d__%H%M',time.localtime())+ '__' + switch.type + '.txt'
		    os.chdir(currentdir)
		    if not switch.SaveFileInDirectory(output, filename, switch.name):
			print "*** Problem with the file backup !"
			switch.client.close()
		        sys.exit(2)
	        switch.client.close()
	        sys.exit(0)

	    # Calling the function for getting the configuration from a Mcdata switch
	    if switch.type == "mcdata":
		if switch.GetMcdataConfig():
		    sys.exit(0)
	    elif (switch.type == "brocade") or (switch.type == "cisco"):
		if not switch.interface:
		    print 'The server will bind on this IP address : '+ str(socket.gethostbyname(socket.gethostname())) + " for the switch's IP :" + str(switch.address)
		else:
		    print 'The server will bind on this IP address : '+ str(switch.interface) + " for the switch's IP : " + str(switch.address)
		if switch.nat:
		    print 'The NAT IP address of the server is : '+ str(switch.nat)
		ssh_server_timeout = 30 # SSH Server will be closed after this timeout value
	        ftp_server_timeout = 30	# FTP Server will be closed after this timeout value
		# Creating a queue for getting messages between client and server threads
		server_queue = Queue.Queue()
		# Starting FTP or SSH servers
		if switch.transfert_type == 'scp':
		    print 'Starting an SSH server...'
		    server_thread = threading.Thread(None, SaveSimplyyourSAN.SSHserver_launch, None, (switch, server_queue, ssh_server_timeout))
		elif switch.transfert_type == 'ftp':
		    print 'Starting an FTP server...'
		    server_thread = SaveSimplyyourSAN.FTPServer(switch, server_queue, ftp_server_timeout)
		else:
		    print '*** Not a good type of transfert ! Possible values are scp or ftp'
	            switch.client.close()
		    sys.exit(1)
                # Launching SSH or Telnet client for sending uploads command
		if switch.connection_type == "ssh":
	            if switch.SSHSave(server_queue, server_thread):
			sys.exit(0)
                elif switch.connection_type == "telnet":
		    if switch.TelnetSave(server_queue, server_thread):
			sys.exit(0)
		else:
		    print "*** Not a good type of client ! Possible values are ssh or telnet"
	            switch.client.close()
		    sys.exit(1)
	    else:
		print '*** Invalid type of switch ! Possible values are : cisco or brocade or mcdata or others'
		sys.exit(1)
############################################
if __name__ == '__main__':
    SaveSimplyyourSAN_CLI()
