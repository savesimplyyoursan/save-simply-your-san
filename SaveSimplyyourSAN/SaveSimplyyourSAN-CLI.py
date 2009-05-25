#!/usr/bin/env python
"""
Copyright (c) 2008-2009, Anthony FOIGNANT. All rights reserved.

A simple tool which make the configuration's backup of your SAN switches simple and easy. It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. You don't need to install or configure a SSH or a FTP server on your computer.

Contact Info:
  http://code.google.com/p/save-simply-your-san/
  antispameu-san@yahoo.fr
"""
#Import definitions
try:
    import SaveSimplyyourSAN
except ImportError:
    raise ImportError, 'This program requires the paramiko extension for Python. See http://code.google.com/p/save-simply-your-san/'

import sys
import thread
import threading
import Queue

from optparse import OptionParser
from threading import Thread

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
	parser.add_option("-i", "--ip", help="IP of the switch", type="string", action="store", dest="ip")
	parser.add_option("-s", "--switch", help="Type of the switch. Possible values are : cisco or brocade or mcdata", type="string", action="store", dest="switch")
	parser.add_option("-u", "--user", help="User on the switch", type="string", action="store", dest="user")
	parser.add_option("-p", "--password", help="Password of the user on the switch", type="string", action="store", dest="password")
	parser.add_option("-t", "--transfert", help="Type of transfert. Possible values are : scp (by default) or ftp", type="string", action="store", dest="transfert", default="scp")
	parser.add_option("-e", "--execute", help="Execute the command given on the switch. ", type="string", action="store", dest="command")
	parser.add_option("-c", "--client", help="Type of client. Possible values are : ssh or telnet (SSH by default)", type="string", action="store", dest="client", default="ssh")
	parser.add_option("-g", "--generate", help="Generate a RSA key for the SSH server. Possible values are : yes or no (no by default). The key will be stored in the file new_server_rsa.key. If you want to use it, please rename the new file with the name : server_rsa.key", type="string", action="store", dest="generate", default="no")
	parser.add_option("-l", "--interface", help="The local IP interface on which the server will be attached", type="string", action="store", dest="interface")
	parser.add_option("-n", "--nat", help="The NAT IP address on which the server will be recheable", type="string", action="store", dest="nat")
	parser.add_option("--timeout", help="The timeout value for SSH or Telnet commands. 4.0 seconds by default", type="float", action="store", dest="timeout", default="5.0")
	parser.add_option("-d", "--debug", help="The debug level. Values are : yes or no (no by default).", type="string", action="store", dest="debug", default="no")
	parser.add_option("--dir", help="store the files in the directory specified. If non value is provided, the files are stored in a directory with the switch's name. If you provide the value byday, the files are stored in a directory named by day. Values are : 'directory' or 'byday'.", type="string", action="store", dest="dir", default="no")
	parser.add_option("-k", "--host-key", help="the Switch's SSH private key used for SSH authentication.", type="string", action="store", dest="key")
	(options, args) = parser.parse_args()

	# Generation of the SSH Server's RSA key
	if options.generate == "yes":
	    GenerateRSAKey()
        print "A 1024 bits RSA key has been generated successfuly in the file new_server_rsa.key. The public key is stored in the file new_server_rsa.pub"
        sys.exit(0)

        # verifying mandatory arguments
	if not options.ip:
	    print '*** You must provide an IP address of a switch with -i !'
	    sys.exit(1)
	if not options.user and not options.key:
	    print '*** You must provide a user with -u !'
	    sys.exit(1)
	if not options.password and not options.key:
	    print '*** You must provide a password with -p !'
	    sys.exit(1)
	if not options.switch:
	    print '*** You must provide a type of switch with -s !'
	    sys.exit(1)

        #initialising switch object
        switch = Switch(options.ip, options.switch, options.user, options.password, options.client, options.transfert, float(options.timeout), options.interface, options.nat, options.dir, options.key)
	if options.command:
	    switch.Connect()
	    output = switch.GetCommand(options.command)
	    filename = switch.name + '__' + options.command + '__' + time.strftime('%Y%m%d__%H%M',time.localtime())+ '__' + switch.type + '.txt'
	    switch.SaveFileInDirectory(output, filename, switch.name)
	    switch.client.close()
	    sys.exit(0)

	# Calling the function for getting the configuration from a Mcdata switch
	if switch.type =="mcdata":
		switch.GetMcdataConfig()
        elif (switch.type == "brocade") or (switch.type == "cisco"):
                ssh_server_timeout = 30 # SSH Server will be closed after this timeout value
	        ftp_server_timeout = 30	# FTP Server will be closed after this timeout value
		if not options.transfert:
		    print '*** You must provide a type of transfert with -t !'
		    sys.exit(1)
		# Creating a queue for getting messages between client and server threads
		server_queue = Queue.Queue()
		if not switch.interface:
		    print 'The server will bind on this IP address :'+ str(socket.gethostbyname(socket.gethostname())) + " for the switch's IP :" + str(switch.address)
		else:
		    print 'The server will bind on this IP address :'+ str(switch.interface) + " for the switch's IP : " + str(switch.address)

		if switch.nat:
		    print 'The NAT IP address of the server is :'+ str(switch.nat)
		if switch.transfert_type == 'scp':
		    print 'Starting a SSH server...'
		    server_thread = threading.Thread(None, SSHserver_launch, None, (switch, server_queue, ssh_server_timeout))
		elif switch.transfert_type == 'ftp':
		    print 'Starting a FTP server...'
		    #server_thread = FTPServer(switch, client_queue, server_queue, ftp_server_timeout)
		    server_thread = FTPServer(switch, server_queue, ftp_server_timeout)
		else:
		    print '*** Not a good type of transfert ! Possible values are scp or ftp'
		    sys.exit(1)
                switch.Connect()
		if switch.connection_type == "ssh":
		    switch.SSHSave(server_queue, server_thread)
                elif switch.connection_type == "telnet":
		    switch.TelnetSave(server_queue, server_thread)
		else:
		    print "*** Not a good type of client ! Possible values are ssh or telnet"
		    sys.exit(1)

	else:
		print '*** Invalid type of switch ! Possible values are : cisco or brocade or mcdata'
		sys.exit(1)
############################################
if __name__ == '__main__':
    SaveSimplyyourSAN_CLI()
