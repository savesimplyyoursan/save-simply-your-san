#!/usr/bin/env python
"""
Copyright (c) 2008-2009, Anthony FOIGNANT. All rights reserved.

A simple tool which make the configuration's backup of your SAN switches simple and easy. It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. You don't need to install or configure a SSH or a FTP server on your computer.

Contact Info:
  http://code.google.com/p/save-simply-your-san/
  antispameu-san@yahoo.fr
"""

import base64
import os
import os.path
import sys
import socket
import traceback


import time
import re
import string
import select
import logging
import urllib2
import telnetlib

try:
    import paramiko
except ImportError:
    raise ImportError, 'This program requires the paramiko extension for Python. See http://www.lag.net/paramiko/'
try:
    import pyftpdlib
except ImportError:
    raise ImportError, 'This program requires the pyftpdlib extension for Python. See http://code.google.com/p/pyftpdlib/'



# hexlify used for the public key authentication. Not supported yet because Brocade switch don't support it
#from binascii import hexlify

from random import choice
from pyftpdlib import ftpserver
from paramiko import SSHClient, AutoAddPolicy, BadHostKeyException, AuthenticationException, SSHException
from urlparse import urlparse
from xml.dom.minidom import parseString

################################################################
# Beginning of the Switch's Class
################################################################
class Switch(object):
    """
    Switch(object)
    A class for the switch object
    """
    def __init__(self, address, switch_type, user, password, connection_type, transfert_type, timeout, interface, nat, dir, key):
        """
        Definition of switch's attributes based on the switch's type

        @param address : hostname or ip address
        @type address: str
        @param switch_type: cisco, brocade, mcdata
        @type switch_type: str
        @type user: str
        @type password: str
        @param connection_type: telnet, ssh
        @type connection_type: str
        @param transfert_type: ftp, ssh
        @type transfert_type: str
        @param timeout: timeout
        @type timeout: int
	@param interface : ip address
        @type interface: str
	@param nat: ip address
	@type nat: str
	@param dir: yes, no
	@type dir: str
        """
        self.address = address
        self.type = switch_type
        self.user = user
        self.password = password
        self.connection_type = connection_type
        self.transfert_type = transfert_type
        self.timeout = timeout
        self.interface = interface
	self.nat = nat
	self.dir = dir
	self.ssh_key = key

        self.ssh_shell = False # A flag in order to know if the switch require a real SSH Shell. True if it need a Real SSH Shell
        self.pass_strong = 15 # Define the length of the random strings used for user and password for the transfert between the switch and the server
        self.transfert_user = self.GenRandomWord(self.pass_strong)
        self.transfert_password = self.GenRandomWord(self.pass_strong)
	self.queue_timeout = 20 # timeout for the server queue

        # defining the command that will be used to verify the type of switch
	if self.type == "brocade":
	    self.commandtest = "switchshow"
	    self.banner = "login"
	    self.prompt = ":" + self.user + ">"
	elif self.type == "cisco":
	    self.commandtest = "show switchname"
	    self.banner = "login"
	    self.prompt = "#"
	    self.uptime_command = "show system uptime"
	    self.environment_command = "show environment"
	    self.resources_command = "show system resources"
	    self.interfaces_command = "show interface brief"
        elif self.type == "mcdata":
	    self.commandtest = "show system"
	    #self.banner = "Username"
	    self.banner = "sername"
	    self.prompt = ">"
	else:
	    print "Not a good type of switch ! possibles values are : brocade or cisco or mcdata"
	    sys.exit(1)
	# try to open the SSH private key
	if self.ssh_key:
	   try:
               open(self.ssh_key, 'r')
	   except:
	       print "The SSH private key :"+str(self.ssh_key)+"doesn't exist !"
	       sys.exit(1)
################################################

    def GenRandomWord(self, length):
        """
        GenRandomWord(self, length) -> string

        Function for generating a random  used for the transferts between the switch and the SSH or FTP server.

        @param length: length of the random returned string
        @type length: int
        @rtype: str
        """

        chars = string.letters + string.digits # only digits and letters
        newword = ''
        for i in range(length):
            newword += choice(chars)
        return newword

################################################

    def GetSwitchName(self, output):
        """
        GetSwitchName(self, output) -> Boolean
        verify the output that we get by the commandtest either by SSH, either by Telnet. Return True or False. If true, the switchname attribute is set, the attributes backupname and the commandsave are set.

        @param output: output of the telnet command
        @type output: str
        @rtype: bool
        """
        if ("md parse error" in output) or ("nvalid command" in output) or ("^"  in output) or ("ommand not found" in output) or ("rror" in output):
            return False
        else:
            if self.type == "cisco":
                if self.connection_type == "telnet":
                    lines = output.splitlines()
		    regexp = re.compile(r"^(.*)(#$)", re.IGNORECASE) # prompt looks like : 'hostname#'
		    for line in lines:
                        matchreg = regexp.match(line)
			if matchreg:
			    self.name = matchreg.group(1)
			    break
                    if not matchreg:
                        return False
                elif self.connection_type == "ssh":
                    self.name = output
            elif self.type == "mcdata":
		lines = output.splitlines()
		regexp = re.compile(r"(Name\:\s*)+(.*)$", re.IGNORECASE) # line looks like : 'Name:    hostname'
		for line in lines:
		    matchreg = regexp.match(line)
		    if matchreg:
	                self.name = matchreg.group(2)
			break
                if not matchreg:
                    return False
                self.name = matchreg.group(2)
            elif self.type == "brocade":
		lines = output.splitlines()

		
		if self.ssh_shell:
		    regexp = re.compile(r"^(.*)\:(.*)>", re.IGNORECASE) # prompt looks like : 'hostname:user>'
		else:
                    regexp = re.compile(r"^(.*switchName\:\s*)+(.*)$", re.IGNORECASE) # line looks like : 'switchName:    hostname'
		for line in lines:
		    matchreg = regexp.match(line)
	            if matchreg:
			if self.ssh_shell:
		            self.name = matchreg.group(1)
			else:
			    self.name = matchreg.group(2)
			break
                if not matchreg:
                    return False

            if self.name:
                #redefining the prompt of the switch for brocade and cisco
                if not "mcdata" in self.type:
                    self.prompt = self.name + self.prompt

                
		# set the name of the backup file and store it in self.file attribute
		self.file = self.name + '__config__' + time.strftime('%Y%m%d__%H%M',time.localtime())+ '__' + self.type + '.txt'

                # determining the command that will be send with the type of the switch and the configuration file sended to the server
                if self.type == "brocade":
                    self.commandsave = "configupload"
                elif self.type == "cisco":
                    if not self.nat:
                        if not self.interface:
                            self.commandsave = 'copy running-config '+ self.transfert_type +'://'+ self.transfert_user +'@'+ str(socket.gethostbyname(socket.gethostname())) + '/' + self.file
                        else:
                            self.commandsave = 'copy running-config '+ self.transfert_type +'://'+ self.transfert_user +'@'+ self.interface + '/' + self.file
                    else:
                        self.commandsave = 'copy running-config '+ self.transfert_type +'://'+ self.transfert_user +'@'+ self.nat + '/' + self.file

                return True
################################################

    def ChangeDir(self, directory):
        """
        ChangeDir(self, directory) -> Boolean
        Try to go in the directory specified. If it fails, creates a new directory in the current directory and change into it. Return True or False.

        @rtype: bool
        """
	if self.dir == 'byday':
	    directory = time.strftime('%Y%m%d',time.localtime())
	if self.dir != 'no':
	    directory = str(self.dir)
	if not (os.path.isdir(directory)):
	     try:
                 os.mkdir(directory)
             except:
                 return False
             try:
                 os.chdir(directory)
             except:
                 return False

             return True
        else:
             try:
                 os.chdir(directory)
             except:
                 return False

             return True

#################################################

    def SaveFileInDirectory(self, input, name, directory):
        """
	(old name : SaveFileInDirectory(self, input, name) -> Boolean)
	SaveFileInDirectory(self, output, name, directory): -> Boolean
        Save the output in the file specified in the directory specified. Return True or False.

        @param output: a string that represent the output of the command
        @type output: str
	@type name: str
	@type directory: str

        @rtype: bool
        """
        if not self.ChangeDir(directory):
            print "***SaveFileInDirectory*** Unable to go in the directory :"+str(directory)
            return False
        # first we verify if this backup doesn't exist
        if not (os.path.isfile(name)):
            # we try to make a file
            try :
                backup = open(name, 'w')
                backup.write(input)
                backup.close()
            except:
                return False
        else:
	    name2 = name + "_old.txt"
            #we create a new backup but we don't erase the one that exists
            print "The file "+ str(name) +" already exists ! It will be renamed in : " + str(name2)
	    try:
	        os.rename(name, name2)
	    except:
	        print "***SaveFileInDirectory*** Unable to rename the file:"+str(name)
	        return False
            try:
                backup = open(name, 'w')
                backup.write(input)
                backup.close()
            except:
                return False
        print "Successfully saved the file:"+str(name)
        return True


################################################################
    def Connect(self):
        if self.connection_type == "ssh":
	    if not self.SSHConnect():
		sys.exit(2)
	if self.connection_type == "telnet":
	    if not self.TelnetConnect():
		sys.exit(2)
	return True


################################################################
    def GetCommand(self, command):
        if self.connection_type == "ssh":
	    return self.SSHCommand(command)
	if self.connection_type == "telnet":
	    return self.TelnetCommand(command)

################################################################
## SSHConnect (package Paramiko)
################################################################
    def SSHConnect(self):
        """
        SSHConnect(self) -> Boolean
        Try to establish an SSH connection and return it.

        @param switch: the switch object
        @type switch: switch
	@rtype: bool
        """
        print "Starting the SSH Connection"
        client = SSHClient()
        # set the key policy to add the key if the host is unknown
        client.set_missing_host_key_policy(AutoAddPolicy())
        try :
            #client.load_system_host_keys('known_hosts')
            client.load_host_keys('known_hosts')
        except:
            print "***SSHConnect*** Unable to load the SSH host keys file : known_hosts"
            client.close()
            sys.exit(1)

        try:
            # Connecting to hostname, on port 22 (SSH), username and password defined. Set the timeout and disable the connection to the local agent. An authentification with private key is also tried
            client.connect(self.address, port=22, username=self.user, password=self.password, pkey=None, key_filename=self.ssh_key, timeout=self.timeout, allow_agent=False, look_for_keys=True)
        except BadHostKeyException:
            print '***SSHConnect*** Bad SSH host key ! Closing connection...'
            client.close()
            sys.exit(1)
        except AuthenticationException:
            print '***SSHConnect*** Authentication refused !'
            client.close()
            sys.exit(1)
        except SSHException:
            print '***SSHConnect*** Connection refused !'
            client.close()
            sys.exit(1)
        print "SSH connection successfull"

        # Try to get the switch's name by the self.commandtest
        print "Got a SSH Shell. Testing the switch with the command :" + self.commandtest
        stdin, stdout, stderr = client.exec_command(self.commandtest)
        output = stdout.read().strip('\r\n')
        error = stderr.read().strip('\r\n')
        #print "out : " + output
        #print "err : " + error
        response = []
        if error:
            if self.type == "brocade":
  
            # For Brocade switch running certains Fabric OS versions (> 6), the exec_command doesn't work well so we must try to get an output from the switch by invoking a real shell
	        print "Degrading to a real SSH shell..."
                try:    
                    shell = client.invoke_shell()
                except:
                    print '***SSHConnect*** Unable to have a real SSH shell'
                    client.close()
                    sys.exit(2)
                self.ssh_shell = True # set the flag that the switch require the use of a shell to work well
                shell.set_combine_stderr(True) #combine standard and error outputs
                shellfile = shell.makefile('rw')
                ret = '\r' # defining the return caracter
                # sending the commandtest to the switch
                shellfile.write(self.commandtest + ret)
                shellfile.flush()
	        time.sleep(self.timeout)
                # sending a return caracter in order to get the prompt after the command on the shell
                shellfile.write(ret)
                shellfile.flush()
                commandseen = False #a flag that tell if the command has been seen in the output line
                time_start = time.time()

                while True:
                    if shell.recv_ready():
		        shell_line = shell.recv(512)
		        response.append(shell_line) #concatenate the output
		        lines = response.splitlines()
		        if self.prompt in lines[-1]:
		            break
	        response = ''.join(response)
		"""
                rlist, wlist, xlist = select.select([shell],[],[])
                elapsed = time.time() - time_start
                if elapsed >= self.timeout:
                    print "Timeout with the switch's test"
                    break
	        if commandseen:
                    # when the flag is set we break and get out from the while true
                    shell.close() #closing this shell. We've done the job
		    break
	        if shell in rlist:
                    response += shell.recv(1024).strip()
		    print response
		    if (self.prompt + " " + self.commandtest) in response:
		        commandseen = True # set the flag
			#print "commandseen"
			pass
		"""
            else: # for macdata or cisco switches
                print "***SSHConnect*** Not the good type of switch :" + str(error)
                client.close()
                sys.exit(2)
        else:
            response = output

        if not self.GetSwitchName(response):
            print "***SSHConnect*** Unable to get the switchname from the output :" + str(response)
            client.close()
            sys.exit(2)

        print "Good type of switch ! Switch's name :" + str(self.name)
        self.client = client
	return True

################################################################
## SSHCommand (paramiko)
################################################################

    def SSHCommand(self, command):
        """
        SSHCommand(self, command) --> String
	Try to get the output of the command on the switch
	Return The output of the command

        @param client: An SSH Connection
	@type client: ssh client
	@param command: command
	@type command: str

	@rtype: str
	"""
        print 'Sending the command :' + command

        #filename = self.name + '__' + command + '__' + time.strftime('%Y%m%d__%H%M',time.localtime())+ '__' + self.type + '.txt'
        if not self.ssh_shell:
            stdin, stdout, stderr = self.client.exec_command(command)
	    output = stdout.read().strip('\r\n')
	    error = stderr.read().strip('\r\n')
	    #print "output : " + output
	    #print "error : " + error
	    if error:
	        print "***SSHCommand*** Error with the command on the switch :" + str(error)
	        sys.exit(2)

        else:  #the self.ssh_shell attribute is true
           try:    
               shell = self.client.invoke_shell()
	   except:
   	       print '***SSHCommand*** Unable to have an SSH shell from the switch'
	       self.client.close()
   	       sys.exit(2)

	   shell.set_combine_stderr(True)
	   shellfile = shell.makefile('rw')
           # defining the return caracter
	   ret = '\r'
           # sending the commandtest to the switch
           shellfile.write(command + ret)
           shellfile.flush()
           time.sleep(self.timeout) # wait connectime seconds
           # sending a return caracter in order to get the prompt after the command on the shell
           shellfile.write(ret)
           shellfile.flush()
           commandseen = False #a flag that tell if the command has been seen in the output line
           time_start = time.time() #used for the computation of the timeout
	   output = []
           while True:
               if shell.recv_ready():
                   shell_line = shell.recv(256)
		   output.append(shell_line) #concatenate the output
	           if ("--More--" in shell_line) or ("Type <CR>" in shell_line):
                       print "I'm sending the space caracter to continue."
                       shellfile.write(chr(32)) # chr(32) is the space caracter
		       shellfile.flush()
                       shellfile.write('\n') # Also send return in case of the last line.
		       shellfile.flush()
                       # Cleaning the response
                       #shell_line = shell_line.replace('--More--','')
                       #shell_line = shell_line.replace('Type <CR> or <SPACE BAR> to continue, <q> to stop','')
		   lines = output.splitlines()
		   if self.prompt in lines[-1]:
		       break
           output = ''.join(output)
	return output

################################################################
## SSHSave (paramiko)
################################################################
    def SSHSave(self, server_queue, server_thread):
        """
        SSHSave(self, client, server_queue, server_thread) -> None
        Tell the switch to send its backup config file to the SSH or the FTP Server.

        @param client: an SSH connection
        @param switch: the switch object
        @type switch: Switch
        @param server_queue: server queue
        @param server_thread: server Thread
        @type server_thread: Thread
        """
        # Sending the name of the file that will be transmetted to the server by the queue
        #client_queue.put(self.file)
        try:    
            shell = self.client.invoke_shell()
	except:
   	    print '***SSHSave*** Unable to have an SSH shell from the switch'
	    self.client.close()
   	    sys.exit(2)

	shell.set_combine_stderr(True)
	shellfile = shell.makefile('rw')
	ret = '\r' # defining the return caracter
	server_thread.start()
        # sending the commandtest to the switch
        shellfile.write(self.commandsave + ret)
        shellfile.flush()
        commandseen = False # a flag that tell if the command has been seen in the output line
        time_start = time.time() # used for the computation of the timeout
	while True:
            if shell.recv_ready():
		shell_line = shell.recv(100)
		#print "shell : "+ shell_line
                if self.prompt in shell_line:
                    commandseen = True
		    pass
                if commandseen:
                    if 'authenticity' in shell_line:
                        # on cisco switch it asks for adding the SSH server key
                        print 'Adding the SSH server key to the switch'
			shellfile.write('yes' + ret)
                        shellfile.flush()
                        pass
                    #reading asked line : Password:
                    elif 'assword' in shell_line:
                        print "sending transfert's password"
			shellfile.write(self.transfert_password  + ret)
                        shellfile.flush()
                        break
                    elif ('refused' in shell_line) or ('failed'in shell_line) :
			print '***SSHSave*** Connection refused by the SSH or FTP Server : ' + shell_line
			server_thread._Thread__stop()
                        self.client.close()
			sys.exit(2)
		    #reading asked section line : Section (all|chassis [all]):
		    elif 'ection' in shell_line:
		        print "sending section"
                        shellfile.write("all" + ret)
                        shellfile.flush()
                        pass
		    #reading asked section line : configupload must use secure protocol :
		    elif 'must use secure' in shell_line:
	                print "***SSHSave*** the switch is in secure mode : " + shell_line
			break
                    #reading asked line : Protocol (scp or ftp) [ftp]:
                    elif 'rotocol' in shell_line:
		        print "sending transfert's protocol"
                        shellfile.write(self.transfert_type + ret)
                        shellfile.flush()
                        pass
                    #reading asked line : Server Name or IP Address [host]:
                    elif '[host]' in shell_line:
		        print "sending destination host"
	                if not self.nat:
	                    if not self.interface:
		                shellfile.write( str(socket.gethostbyname(socket.gethostname())) + ret)
		            else:
	                        shellfile.write( self.interface + ret)
	                else:
		            shellfile.write( self.nat + ret)
                        shellfile.flush()
                        pass
                    #reading asked line : User Name [user]:
                    elif 'ser' in shell_line:
		        print "sending transfert's user"
                        shellfile.write(self.transfert_user + ret)
                        shellfile.flush()
                        pass
                    #reading asked line : File Name [config.txt]:
                    elif 'ile' in shell_line:
		        print "sending destination's file"
                        shellfile.write(self.file + ret)
                        shellfile.flush()
                        pass
		    else:
                        elapsed = time.time() - time_start
                        if elapsed >= (self.timeout + 30) :
                            print "***SSHSave*** Timeout with the command"
                            break
   
            else:
                elapsed = time.time() - time_start
                if elapsed >= (self.timeout + 30):
                    print "***SSHSave*** Timeout with the command"
                    break

        # waiting for the result of the server.
	try:
	    result = server_queue.get(True, self.queue_timeout)
	except:
            print '***SSHSave*** Transfert Failed !'
	    server_thread._Thread__stop()
            self.client.close()
	    sys.exit(2)
	    
        if result == 'backup OK':
            print 'Transfert and Backup successfully done ! in the file : '+ self.file
	    server_thread._Thread__stop()
	    self.client.close()
            sys.exit(0)
        else:
	    print '***SSHSave*** Transfert Failed !'
	    server_thread._Thread__stop()
            self.client.close()
	    sys.exit(2)


################################################################
## TelnetConnect (telnetlib)
################################################################
    def TelnetConnect(self):
        """
        TelnetConnect(self) -> Boolean
        Try to establish a telnet connection and return it.

        @rtype: bool
        """
        print "Starting the Telnet connection"
        # waiting for the banner
        try:
	    tn = telnetlib.Telnet(self.address)
            tn.read_until(self.banner, self.timeout)
        except:
            print "***TelnetConnect*** Telnet connection impossible to the host :" + self.address
            return False
        # sending username and password to the switch
        try:
            tn.write(self.user + "\n")
            tn.read_until("assword", self.timeout)
            tn.write(self.password + "\n")
            response = tn.read_until(self.prompt, self.timeout)
        except:
            print "***TelnetConnect*** Connection refused by the host :" + str(self.address)
            tn.close()
            return False

        if not self.prompt in response:  #Verify the switch's type
            print "***TelnetConnect*** Not the good type of switch ! Received the prompt :" + str(response)
            tn.close()
            return False

        # Try to get the switch's name by the switch.commandtest
        print "Got a Telnet Shell. Testing the switch with the command :" + self.commandtest
        tn.write(self.commandtest + "\n")
        response = '' # erase last response
        response = tn.read_until(self.prompt, self.timeout)
        if not self.GetSwitchName(response):
            print "***TelnetConnect*** Unable to get the switchname from the output :" + str(response)
	    tn.close()
            return False
        print "Good type of switch ! Switch's name :" + str(self.name)
        self.client = tn
        return True
################################################################
## TelnetCommand (telnetlib)
################################################################
    def TelnetCommand(self, command):
        """
        TelnetCommand(self, command) -> String
        Get the output of a command on the switch by telnet
	return the output of the command

	@param command: command
	@type command: str

	@rtype: str
        """
        # for cisco switch you can avoid to type space in order to continue
        if self.type == "cisco":
            self.client.write("terminal length 0" + "\n")
	    self.client.read_until(self.prompt, self.timeout)
	
	print "Sending the command to the switch :" + str(command)
        self.client.write(command + "\r") # sending the command

        print "Reading the output..."
        response = [] # erase last response
	shell_line = ''
        while not self.prompt in shell_line:
            shell_line = self.client.read_until(self.prompt, self.timeout)
            response.append(shell_line)
	    # on brocade, it will ask you to press enter to continue
            if ("--More--" in response) or ("Type <CR>" in response):
                print "I'm Sending the space caracter to continue."
                self.client.write(chr(32)) # chr(32) is the space caracter
                self.client.write('\n') # Also send return in case of the last line.
                # Cleaning the response
                #response = response.replace('--More--','')
                #response = response.replace('Type <CR> or <SPACE BAR> to continue, <q> to stop','')
	response = ''.join(response)
	return response

################################################################
## TelnetSave (telnetlib)
################################################################
    #def TelnetSave(switch, tn, client_queue, server_queue, server_thread):
    def TelnetSave(self, server_queue, server_thread):
        """
        TelnetSave(self, server_queue, server_thread) -> None
        Tell the switch to send its backup config file to the SSH or the FTP Server.

        @param server_queue: server queue
        @param server_thread: server Thread
        @type server_thread: Thread
        """
        # Sending the name of the file that will be transmetted to the server by the queue
        #client_queue.put(self.file)
        server_thread.start()
        # sending the command
        print 'Sending the command to the switch : ' + self.commandsave
        self.client.write(self.commandsave + "\n")
        if (self.type == "brocade"):
            # we need to send the protocol, host, user, file and password to begin the transfert.
            response = '' # erasing the last response	
            #reading asked protocol line : Protocol (scp or ftp) [ftp]:
            response = self.client.read_until('rotocol', self.timeout)
            #print "response prot: " + response
            if 'rotocol' in response:
        	#print "response prot: " + response
        	self.client.write( self.transfert_type + "\n")
        	response = ''
        	#reading asked host line : Server Name or IP Address [host]:
        	response = self.client.read_until('host', self.timeout)
		#reading asked section line : configupload must use secure protocol :
        	if 'must use secure protocol' in response:
        	    print "*** TelnetSave *** The switch is in secure mode :" + response
                    print '*** TelnetSave *** Transfert Failed !'
                    server_thread._Thread__stop()
                    self.client.close()
                    sys.exit(2)
        	#print "response host: " + response
        	if not self.nat:
        	    if not self.interface:
        		self.client.write( str(socket.gethostbyname(socket.gethostname())) + "\n")
                    else:
        	        self.client.write( self.interface + "\n")
        	else:
                    self.client.write( self.nat + "\n")
        	response = ''
        	#reading asked user line : User Name [user]:
        	response = self.client.read_until('ser', self.timeout)
        	#print "response user: " + response
        	self.client.write( self.transfert_user + "\n")
        	response = ''
        	#reading asked file line : File Name [config.txt]:
        	response = self.client.read_until('ile', self.timeout)
        	#print "response file: " + response
        	self.client.write( self.file + "\n")
        	response = ''
        	#reading asked section line : Section (all|chassis [all])::
        	response = self.client.read_until('ection', self.timeout)
        	if "ection" in response:
        	    self.client.write( "all" + "\n")
        	response = ''
        	#reading asked password line : Password:
        	response = self.client.read_until('assword', self.timeout)
        	#print "response pass: " + response
        	#sending the password for the transfert
        	print 'Sending password for the transfert'
        	self.client.write( self.transfert_password + "\n")

            elif 'host' in response:
                if not self.nat:
                    if not self.interface:
                        self.client.write( str(socket.gethostbyname(socket.gethostname())) + "\n")
                    else:
                        self.client.write( self.interface + "\n")
                else:
                    self.client.write( self.nat + "\n")
                response = ''
        	#reading asked user line : User Name [user]:
        	response = self.client.read_until('ser', self.timeout)
        	#print "response user: " + response
        	self.client.write( self.transfert_user + "\n")
	        response = ''
	        #reading asked file line : File Name [config.txt]:
	        response = self.client.read_until('ile', self.timeout)
	        #print "response file: " + response
	        self.client.write( self.file+ "\n")
	        response = ''
                #reading asked protocol line : Protocol (scp or ftp) [ftp]:
                response = self.client.read_until('rotocol', self.timeout)
                self.client.write( self.transfert_type + "\n")
                response = ''
	        #reading asked section line : Section (all|chassis [all])::
	        response = self.client.read_until('ection', self.timeout) # a new feature of brocade
	        if "section" in response:
	            self.client.write( "all" + "\n") # we send "all" in response
		#reading asked section line : configupload must use secure protocol :
	        if 'must use secure protocol' in response:
	            print "*** TelnetSave *** The switch is in secure mode :" + response
	        response = ''
                #reading asked password line : Password:
                response = self.client.read_until('assword', self.timeout)
                #print "response pass: " + response
                #sending the password for the transfert
	        print 'Sending password for the transfert'
                self.client.write( self.transfert_password + "\n")

        else: # For Cisco switch :
            response = '' #reading asked section line : configupload must use secure protocol :
            #sending the password for the transfert
            response = self.client.read_until('assword', self.timeout)
            #print "response : " + response
	    if 'assword' in response: 
	        print 'Sending password for the transfert'
	        self.client.write(self.transfert_password + "\n")
            if ('refused' in response) or ('failed' in response):
                print '*** TelnetSave *** Connection refused by the SSH or FTP Server :' + response
                server_thread._Thread__stop()
                self.client.close()
                sys.exit(2)
	    # dealing if the switch ask to add the SSH key on the switch
	    elif 'authenticity' in response:
	        print 'Adding the SSH server key on the switch'
	        self.client.write('yes' + "\n")


        # waiting for the result of the server.
        try:
            result = server_queue.get(True, self.queue_timeout)
        except:
            print '*** TelnetSave *** Transfert Failed !'
            server_thread._Thread__stop()
            self.client.close()
            sys.exit(2)

        if result == 'backup OK':
            print "Transfert and Backup successfully done in the file :" + self.file
            server_thread._Thread__stop()
            self.client.close()
            sys.exit(0)
        else:
            print '*** TelnetSave *** Transfert Failed !'
            server_thread._Thread__stop()
            self.client.close()
            sys.exit(2)
	
################################################################
## GetMcdataConfig Function
## 
################################################################
    def GetMcdataConfig(self):
        """
	GetMcdataConfig(self) -> None
	It grabs the switch's configuration file by http and store it in a folder with the switch's name. It disable the proxy configuration of your browser.
	The output is saved in a file's name pattern : switchname__daytime__switchtype.txt.
	"""

	# Warning !!! it disables the proxy of the navigator if it exists. Sometimes there is some troubles with that.
	proxy_support = urllib2.ProxyHandler({})
	opener = urllib2.build_opener(proxy_support)
	urllib2.install_opener(opener)

	# thanks to http://www.voidspace.org.uk/python/articles/authentication.shtml
	# for it solution in order to deal the HTTP Basic authentication :)
	switchurl = 'http://'+ self.address +'/change_password.htm'            # if you want to run this example you'll need to supply a protected page with your username and password
	req = urllib2.Request(switchurl)
	try:
    		handle = urllib2.urlopen(req)
	except IOError, e:                  # here we are assuming we fail
    		pass
	else:                               # If we don't fail then the page isn't protected
		print "***MCDATA*** Unable to open The switch URL : " +str(switchurl)+" ! Maybe you need a proxy in order to go to this URL ?!"
    		sys.exit(1)
    
	if not hasattr(e, 'code') or e.code != 401:                 # we got an error - but not a 401 error
   		print "***MCDATA*** The switch isn't protected by authentication. But we failed for another reason."
    		sys.exit(1)

	authline = e.headers.get('www-authenticate', '')                # this gets the www-authenticat line from the headers - which has the authentication scheme and realm in it
	if not authline:
    		print '***MCDATA*** A 401 error without an authentication response header - very weird.'
    		sys.exit(1)
    
	authobj = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"](\w+\s\w+)['"]''', re.IGNORECASE)          # this regular expression is used to extract scheme and realm
	matchobj = authobj.match(authline)
	if not matchobj:                                        # if the authline isn't matched by the regular expression then something is wrong
    		print '***MCDATA*** The authentication line is badly formed.'
    		sys.exit(1)
	scheme = matchobj.group(1) 
	realm = matchobj.group(2)
	if scheme.lower() != 'basic':
    		print '***MCDATA*** Only works with BASIC authentication.'
    		sys.exit(1)

	base64string = base64.encodestring('%s:%s' % (self.user, self.password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
    		handle = urllib2.urlopen(req)
	except IOError, e:                  # here we shouldn't fail if the username/password is right
    		print "***MCDATA*** It looks like the username or password is wrong."
    		sys.exit(1)
	server = urlparse(switchurl)[1].lower()            # server names are case insensitive, so we will convert to lower case
	test = server.find(':')
	if test != -1: server = server[:test]           # remove the :port information if present, we're working on the principle that realm names per server are likely to be unique...

	passdict = {(server, realm) : authheader }      # now if we get another 401 we can test for an entry in passdict before having to ask the user for a username/password

	print 'MCDATA : Authentication Successfully Done ! Trying to get the swconfig.xml file from the switch :'+str(self.address)
	
	#the xml configuration filename
	swconfig = 'swconfig.xml'
	urlconfig = 'http://'+ self.address + '/'+ swconfig
	req2 = urllib2.Request(urlconfig)
	req2.add_header("Authorization", authheader)
	try:
    		handle2 = urllib2.urlopen(req2)
	except IOError, e:
    		print "***MCDATA*** Unable to get the swconfig.xml file from the switch !"
    		sys.exit(1)
	theconfig = handle2.read()

	if len(theconfig) == 0:
		print '***MCDATA*** Nothing in the swconfig.xml file !'
		sys.exit(1)
	#now parsing the XML file in order to get the name of the switch.
	dom1 = parseString(theconfig)
	try:
		tagnames = dom1.getElementsByTagName("Name")[0]
		self.name = tagnames.firstChild.data
	except:
		print '***MCDATA*** Unable to find the name of the switch in swconfig.xml !'
	    	sys.exit(1)

        """
	if not self.ChangeDir():
	    print "***MCDATA*** Unable to go in the directory :"+str(self.name)
	    sys.exit(2)
	"""

	# we try to make a file in order to save the configuration file
	self.file = self.name + '__' + time.strftime('%Y%m%d__%H%M',time.localtime()) +'__'+ 'mcdata.xml'

        if not self.SaveFileInDirectory(theconfig, self.file, self.name):
            print "Unable to save the configuration in the file :" + self.file
            sys.exit(2)

        print "Successfully saved the configuration in the file :" + self.file
        sys.exit(0)


################################################################
# End of the Switch's Class
################################################################

################################################################
## Generate 1024 bits SSH RSA key (Paramiko)
################################################################
def GenerateRSAKey(keylength=1024):
    """
    GenerateRSAKey(keylength) -> None
    Create a new 1024 bits RSA key for the SSH server on your host.
    The private key is saved in the file 'new_server_rsa.key' on your current directory. The public key is saved in the file 'new_server_rsa.pub'.
    @param keylength : int
    """
    key = paramiko.RSAKey.generate(int(keylength)) #generate the private key
    key.write_private_key_file('new_server_rsa.key') #saving the private key
    file = open('new_server_rsa.pub','w') #create the file for public key
    file.write("ssh-rsa " +key.get_base64())
    file.close()

################################################################
## SCPServer class (Paramiko)
################################################################

class SCPServer(paramiko.ServerInterface):
    """
    SCPServer()
    A class derived from the SSH Server interface of paramiko.
    Only accept password authentication from client and an SCP transfert command.
    """
    def __init__(self, transfert_user, transfert_password):
        #get the user and password used for the file transfert from the switch
	self.transfert_user = transfert_user
	self.transfert_password = transfert_password
        self.SCPevent = threading.Event() # Used for the timeout of the SSH Server

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.transfert_user) and (password == self.transfert_password):
		print 'SSHServer : Authentication successfully done'
            	return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
	
	# authentication by public key is not implemented because Brocade switch doesn't support this type of authentication on old Fabric OS Release.
    	#def check_auth_publickey(self, username, key):
        	#print 'Auth attempt with key: ' + hexlify(key.get_fingerprint())
        	#if (username == transfert_user) and (key == self.good_pub_key):
            		#return paramiko.AUTH_SUCCESSFUL
        	#return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_exec_request(self, channel, command):
        """
        Check if the SCP command is good

        @type command: str
        """
        #Only accept the 'scp -t' command
	if command.startswith('scp -t'):
		self.SCPevent.set()
		return True
        return False

################################################################
## SSHServer used for SCP (paramiko)
###############################################################

#def SSHserver_launch(switch, client_queue, server_queue, timeout):
def SSHserver_launch(switch, server_queue, timeout):
        """
        SSHserver_launch(switch, server_queue, timeout): -> None
        Launch a SSH Server on the host. It grabs the switch's configuration file by SCP and store it in a folder with the switch's name.
        The output is saved in a file's name pattern : switchname__time__switchtype.txt.

        @param switch: the switch object
        @type switch: Switch
        @param server_queue: server queue
        @param timeout: timeout
        @type timeout: int
        """
	host_key = paramiko.RSAKey(filename='server_rsa.key')

	# you can test with DSS keys
	#host_key = paramiko.DSSKey(filename='server_dss.key')

	#### now start the SSH server in order to get the config
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		if not switch.interface:
    			sock.bind(('', 22))
		else:
			sock.bind((switch.interface, 22))

	except Exception, e:
		print '***SSHServer*** Could not bind on port 22' + str(e)
    		traceback.print_exc()
    		sys.exit(2)

	try:
		#we start the SSH server on only one connection
   		sock.listen(1)
		print 'SSHServer : Listening for connection ...'
    		client, addr = sock.accept()
	except Exception, e:
    		print '***SSHServer*** Listen/accept failed:' + str(e)
    		traceback.print_exc()
    		sys.exit(2)
	try:
    		t = paramiko.Transport(client)
    
    		#t.set_hexdump(True)            # use it only for debugging purpose !
    		try:
        		t.load_server_moduli()
    		except:
        		print '***SSHServer*** (Failed to load moduli -- gex will be unsupported.)'
        		raise
    		t.add_server_key(host_key)
    		SCPserver = SCPServer(switch.transfert_user,switch.transfert_password)
    		try:
        		t.start_server(server=SCPserver)
    		except SSHException:
        		print '***SSHServer*** SSH negociation failed.'
        		sys.exit(2)

    		# waiting timeout seconds for a channel to be opened by the switch
    		serv_chan = t.accept(timeout)
    		if serv_chan is None:
        		print '***SSHServer*** No channel.'
        		server_queue.put('backup FAIL')
			sys.exit(2)
		
		# waiting for the scp command from the switch. See the SCPServer class definition
    		SCPserver.SCPevent.wait(timeout)
    		if not SCPserver.SCPevent.isSet():
        		print '***SSHServer*** Client never ask for an SCP transfer.'
			server_queue.put('backup FAIL')	
			sys.exit(2)
		## Beginning of the SCP protocol : we acknowledge the command received and the rest of the transfert with zero. One zero for the each line of the SCP commands.
		## a really bad hack :-(
		## but it really works :-)
    		serv_chan.send('\0\0\0\\')
    		
    		# we are reading the command sent by the switch and we verify it
    		c = serv_chan.makefile('r')
    		r_command = c.readline().strip('\r\n')
    		c.close()
    		if not r_command.startswith('C'):
        		print '***SSHServer*** Expecting a C command for the SCP transfert, but we received something else !'
			server_queue.put('backup FAIL')
			sys.exit(2)
		# we get the differents arguments of the command
    		r_perm, r_length, r_name = r_command.split(" ")
		# we get the perms, but don't really use it :-(
    		perms = r_perm[1:-1]
    		perms = int(perms, 8)
    		length = int(r_length)
		print 'SSHServer : Getting file: ' + str(r_name)  + ' perms: '+ str(oct(perms))+ ' length of file: ' + str(length)
    		if length == 0:
	    		print '***SSHServer*** Error the length of the file is zero byte !'
	    		server_queue.put('backup FAIL')
			sys.exit(2)
		
		s = serv_chan.makefile('r')
    		data = []
    		try:
	    		while True:
				#data += s.next()
				data.append(s.next())
				if len(data)>length:
					moredata = data[length:]
                			data = data[:length]
                			if moredata != '\0':
                    				print 'Got more '+ str(len(moredata))+ ' bytes than expected, ignoring it !'				
    		except:
			#calculating the percent file received
			done = (len(data)*100/length)
			print 'SSHServer : received ' + str(done) + '%. Length received = ' + str(len(data))
			s.close()
		data = ''.join(data)
		# just another method to get the file by SCP
		'''
    		data = ''
		#we read the file received
	    	while True:
			data += serv_chan.recv(1024)
			#calculating the percent received
			done = (len(data)*100/length)
			# we've got an EOF in the data received so the length received is greater than the length announced
			if len(data) >= length:
				break
		print 'SSHServer : received ' + str(done) + '%. length received = ' + str(len(data))
		'''
                #closing all channels and transports
		serv_chan.shutdown_write()
    		serv_chan.send_exit_status(0) #sending exit status OK
    		serv_chan.close()
    		t.close()

    		if len(data) == 0:
    			print '***SSHServer*** Nothing in the file received'
			server_queue.put('backup FAIL')
			sys.exit(2)
    		if len(data) < length:
	   		print '***SSHServer*** Received not complete !'
			server_queue.put('backup FAIL')
			sys.exit(2)
		
		# getting the file name by the client thread
		#try:
			#backupname = client_queue.get(True, switch.queue_timeout)
		#except:
			#print '***SSHServer*** Unable to have the name of the backup file by the client !'
			#sys.exit(2)

                if not switch.SaveFileInDirectory(data, switch.file, switch.name):
                    print '***SSHServer*** Unable to create and save the file :' + str(switch.file)
                    server_queue.put('backup FAIL')
                else:
    		    print 'SSHServer : Configuration backup done to the file :' + str(switch.file)
		    server_queue.put('backup OK')
		
	except Exception, e:
    		print '***SSHServer*** Caught exception:' + str(e.__class__) + ' : ' + str(e)
    		traceback.print_exc()


################################################################
## FTPServer used for FTP (pyftpdlib)
################################################################

class FTPServer(threading.Thread):
	"""
	FTPServer(threading.Thread)
	Launch an FTP Server on the host. It grabs the switch's configuration file by FTP and store it in a folder with the switch's name.
	The output is saved in a file's name pattern : switchname__daytime__switchtype.txt.
	"""
	#def __init__(self, switch, client_queue, server_queue, timeout):
	def __init__(self, switch, server_queue, timeout):
		"""
		@param switch: the switch object
                @type switch: Switch
                @param server_queue: server queue
                @param timeout: timeout
                @type timeout: int
		"""
        	threading.Thread.__init__(self)
		self.switch = switch
		self.hostname = switch.address
		self.FTPuser = switch.transfert_user
		self.FTPpassword = switch.transfert_password
		#self.client_queue = client_queue
		self.server_queue = server_queue
		self.interface = switch.interface
		self.timeout = timeout
        	self.backupOK = False
		self.file = switch.file

    	def run(self):
		
		#try:
			#self.file = self.client_queue.get(True, self.switch.queue_timeout)
		#except:
			#print '***FTPServer*** Unable to have the name of the backup file by the client !'
			#self.server_queue.put('backup FAIL')
			#sys.exit(2)
		# Changing the working directory
                if not self.switch.ChangeDir(self.switch.name):
                    print "***FTPServer*** Unable to go the directory with this switch's name :"+str(self.switch.name)
		    self.server_queue.put('backup FAIL')
                    sys.exit(2)
		
		# we verify if this backup doesn't exist
		if (os.path.isfile(self.file)):
	            self.file2 = str(self.file) + "_old.txt"
		    print "***FTPServer*** The file "+str(self.file)+" already exists ! It will be renamed in: "+str(self.file2)+" !"
		    try:
		        os.rename(self.file, self.file2)
		    except:
		        print "***FTPServer*** Unable to rename the file:"+str(self.file)
			sys.exit(2)

		# Instantiate a dummy authorizer for managing 'virtual' users
    		authorizer = ftpserver.DummyAuthorizer()
    		# Define a new user having full r/w permissions
    		authorizer.add_user(self.FTPuser, self.FTPpassword, os.getcwd(), perm='elradfmw')
       		# Instantiate FTP handler class
    		ftp_handler = ftpserver.FTPHandler
    		ftp_handler.authorizer = authorizer
    		# Define a customized banner (string returned when client connects)
    		ftp_handler.banner = "FTP ready."
		ftp_handler.timeout = self.timeout
    		# Specify a masquerade address and the range of ports to use for
    		# passive connections.  Decomment in case you're behind a NAT.
		if self.switch.nat:
    		    ftp_handler.masquerade_address = self.switch.nat
    		    ftp_handler.passive_ports = range(60000, 65535)
    		# Instantiate FTP server class and listen to 0.0.0.0:21
		if not self.interface:
    		    address = ('', 21)
		else:
		    address = (self.interface, 21)
		try:
    		    ftpd = ftpserver.FTPServer(address, ftp_handler)
		except:
		    print '***FTPServer*** Unable to bind on the port 21 !'
		    self.server_queue.put('backup FAIL')
		
		# a method that check if the file is arrived in the directory every 2 seconds
    		ftpserver.CallLater(2, self.FTPcheck, (ftpserver))
		# Calling the method FTPquit
		ftpserver.CallLater(self.timeout, self.FTPquit, (ftpd))

    		# set a limit for incoming connections. only 3 incoming connections and only 1 connection by IP
    		ftpd.max_cons = 3
    		ftpd.max_cons_per_ip = 1
		try:
    		    ftpd.serve_forever() # start ftp server
		except:
		    print '***FTPServer*** Error unable to start !'
		    self.server_queue.put('backup FAIL')

	def FTPquit(self, ftpd):
		if os.path.isfile(self.file):
		    print 'FTPServer : Configuration backup done to the file :' + self.file
		    self.server_queue.put('backup OK')
		else:
		    print '***FTPServer*** Unable to find the file:' + self.file
		    self.server_queue.put('backup FAIL')

		# this method close the FTP server
		ftpd.close_all()

	def FTPcheck(self, ftpserver):
		if not self.backupOK:
		    if os.path.isfile(self.file):
		        self.backupOK = True				
			self.server_queue.put('backup OK')
			print 'FTPServer : Configuration backup done to the file :' + self.file
		    else:
			ftpserver.CallLater(2, self.FTPcheck, (ftpserver))
			print "FTPServer : waiting switch's connection..."



############################################
if __name__ == '__main__':
    pass
