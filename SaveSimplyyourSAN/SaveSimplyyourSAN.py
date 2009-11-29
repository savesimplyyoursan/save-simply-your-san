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
import socket
import traceback


import time
import re
import string
import select
import logging
import urllib2
import telnetlib
import thread
import threading

from threading import Thread

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
    def __init__(self, address, user, password, switch_type='cisco', connection_type="ssh", transfert_type="scp", read_timeout=5.0, interface='', nat='', dir="no", pass_strong=15, ssh_shell=False, queue_timeout=20, prompt_timeout=4.0, debug=False, known_hosts='known_hosts', server_key='server_rsa.key', server_key_type='RSA'):
        """
        Definition of switch's attributes based on the switch's type

        @param address : hostname or IP address
        @type address: str
        @param switch_type: cisco, brocade, mcdata
        @type switch_type: str
	@param user: user
        @type user: user used for the equipment's connection 
	@param password: password used for the equipment's connection 
        @type password: str
        @param connection_type: telnet, ssh
        @type connection_type: str
        @param transfert_type: ftp, scp
        @type transfert_type: str
        @param read_timeout: timeout for reading the return of the command
        @type read_timeout: float
	@param interface : ip address
        @type interface: str
	@param nat: IP address
	@type nat: str
	@param dir: yes, no
	@type dir: str
	@param key: SSH private key used for the equipment's connection (for future dev)
	@type key : str
	@param debug: True or False
	@type debug: bool
	@param known_hosts: the known_hosts file
	@type known_hosts: str
        @param server_key: the server key for SCP transferts
	@type server_key: str
	@param server_connection_type : RSA, DSS
	@type server_connection_type : str
	@param prompt_timeout : the timeout for waitin the prompt to appear
	@type prompt_timeout: float
        """
        self.address = address
        self.type = switch_type
        self.user = user
        self.password = password
        self.connection_type = connection_type
        self.transfert_type = transfert_type
        self.read_timeout = read_timeout
	self.prompt_timeout = prompt_timeout
        self.interface = interface
	self.nat = nat
	self.dir = dir
	#self.ssh_key = key
        # A flag in order to know if the switch require a real SSH Shell in case of ssh_command failed.
	# True if it need a Real SSH Shell. False by default
	self.ssh_shell = ssh_shell
	# Define the length of the random strings used for user and password for the transfert between the switch and the server
        self.pass_strong = pass_strong
	# Store the random user and password for transfert to the FTP or SSH Server
        self.transfert_user = self.GenRandomWord(self.pass_strong)
        self.transfert_password = self.GenRandomWord(self.pass_strong)
	self.queue_timeout = queue_timeout # timeout for the server queue
	self.debug = debug
	self.known_hosts = known_hosts #the known_hosts file
	self.server_key_type = server_key_type
	self.server_key = server_key #the known_hosts file
        # defining the command that will be used to verify the type of switch
	if self.type == "brocade":
	    self.commandtest = "switchshow"
	    self.banner = "login"
	    self.prompt = ":" + self.user + ">"
	elif self.type == "cisco":
	    self.commandtest = "show switchname"
	    self.banner = "login"
	    self.prompt = "#"
        elif self.type == "mcdata":
	    self.commandtest = "show system"
	    self.banner = "sername"
	    self.prompt = ">"
        elif self.type == "others":
	    self.commandtest = "hostname"
	    self.banner = "sername"
	    self.prompt = "$"
        else:
	    raise InputError(self.type, "Not a good type of switch ! possibles values are : brocade or cisco or mcdata or others" )
	# try to open the SSH private key
	#if self.ssh_key:
	   #try:
               #open(self.ssh_key, 'r')
	   #except:
	       #print "The SSH private key :"+str(self.ssh_key)+"doesn't exist !"

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
    def GetSwitchTypeFromPrompt(self, output):
        """
        GetSwitchTypeFromPrompt(self, output) -> Boolean
        Try to guess the switch's type with the prompt that we get either by SSH, either by Telnet. Return True or False. If true, the switch self.type attribute is set, the attributes backupname and the commandsave are set.

        @param output: output of the telnet or SSH command
        @type output: str
        @rtype: bool
        """
        if ("md parse error" in output) or ("nvalid command" in output) or ("^"  in output) or ("ommand not found" in output) or ("rror" in output):
            print "***GetSwitchType*** Received an invalid command !"
	    return False
        else:
            lines = output.splitlines()
	    discovered = False # Flag to see if it is discovered
	    cisco_regexp = re.compile(r"^(.+)(#)", re.IGNORECASE) # prompt looks like : 'hostname#'
	    mcdata_regexp = re.compile(r"^(.*)(>)", re.IGNORECASE) # prompt looks like : 'Root>' or '>'
	    brocade_regexp = re.compile(r"^(.+)\:(.+)>", re.IGNORECASE) # prompt looks like : 'hostname:user>'
	    others_regexp = re.compile(r"^(.*)(\$)", re.IGNORECASE) # prompt looks like : 'hostname$'
            for line in lines:
		if self.debug:
		    print "GetSwitchType line: '%s'" % line
	        cisco_matchreg = cisco_regexp.match(line)
		if cisco_matchreg:
		    if self.type != "cisco":
			print "WARNING: We've guessed a Cisco equipment ! please verify your argument. we will assume a cisco for testing equipment"
	            self.type = "cisco"
		    self.prompt = line
		    self.name = cisco_matchreg.group(1).strip()
		    self.commandtest = "show switchname"
		    if self.debug:
		        print "Guessed a CISCO equipment, name '%s', and prompt '%s'" % (self.name, self.prompt)
		    discovered = True
		    break
	        brocade_matchreg = brocade_regexp.match(line)
		if brocade_matchreg:
		    if self.type != "brocade":
			print "WARNING: We've guessed a Brocade equipment ! please verify your argument. we will assume a brocade for testing equipment"			
		    self.type = "brocade"
		    self.prompt = line
		    self.name = brocade_matchreg.group(1).strip()
		    self.commandtest = "switchshow"
		    if self.debug:
			print "Guessed a BROCADE equipment, name '%s', and prompt '%s'" % (self.name, self.prompt)		    
		    discovered = True
		    break
	        mcdata_matchreg = mcdata_regexp.match(line)
		if mcdata_matchreg:
		    if self.type != "mcdata":
			print "WARNING: We've guessed a mcdata equipment ! please verify your argument. we will assume a mcdata for testing equipment"
		    self.type = "mcdata"
		    self.prompt = line
		    self.commandtest = "show system"
		    self.name = ''
		    if self.debug:
			print "Guessed a MCDATA equipment, prompt '%s'" % self.prompt
                    discovered = True
		    return True
		    break
	        others_matchreg = others_regexp.match(line)
		if others_matchreg:
		    if self.type != "others":
			print "WARNING: We've guessed a others equipment ! please verify your argument. we will assume a others for testing equipment"			
		    self.type = "others"
		    self.prompt = line
		    #self.name = others_matchreg.group(1).strip()
		    self.name = ''
		    self.commandtest = "hostname"
		    if self.debug:
			#print "Guessed an OTHERS equipment, name '%s', and prompt '%s'" % (self.name, self.prompt)
			print "Guessed an OTHERS equipment and prompt '%s'" % (self.prompt)
                    discovered = True
		    return True
		    break
            if not discovered:
	        return False
            if self.name:
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
    def GetSwitchName(self, output):
        """
        GetSwitchName(self, output) -> Boolean 
        verify the output that we get by the commandtest either by SSH, either by Telnet. Return True or False. If true, the switchname attribute is set, the attributes backupname and the commandsave are set.
        @param output: output of the telnet or SSH command
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
            elif self.type == "others":
                if self.connection_type == "telnet":
                    self.name = output
                elif self.connection_type == "ssh":
                    self.name = output
            if self.name:
                #redefining the prompt of the switch for brocade and cisco
                #if not "mcdata" in self.type:
                    #self.prompt = self.name + self.prompt

                
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
	    directory = str(time.strftime('%Y%m%d',time.localtime()))
	if self.dir != 'no':
	    directory = str(self.dir)
	#if directory doesn't exist, we create it
	if not (os.path.isdir(directory)):
	    try:
                os.mkdir(directory)
            except:
		print "*** ChangeDir : Impossible to create the directory: %s " % directory
                return False
        try:
            os.chdir(directory)
        except:
	    print "*** ChangeDir : Impossible to go into the directory: %s " % directory
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
            print "***SaveFileInDirectory*** Unable to go in the directory : "+str(directory)
            return False
        # first we verify if this backup doesn't exist
        if (os.path.isfile(name)):
	    name2 = name + "_old.txt"
            #we create a new backup but we don't erase the one that exists
            print "The file "+ str(name) +" already exists ! It will be renamed in: " + str(name2)
	    try:
	        os.rename(name, name2)
	    except:
	        print "***SaveFileInDirectory*** Unable to rename the file: "+str(name)
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
	    return self.SSHConnect()
	elif self.connection_type == "telnet":
	    return self.TelnetConnect()
        else:
            raise InputError(self.connection_type, "Not a good connection type !")

################################################################
    def GetCommand(self, command):
        if self.connection_type == "ssh":
	    return self.SSHCommand(command)
	if self.connection_type == "telnet":
	    return self.TelnetCommand(command)
        else:
            raise InputError(self.connection_type, "Not a good connection type !")
################################################################
    def TestType(self):
        if self.connection_type == "ssh":
	    return self.SSHTestType()
	if self.connection_type == "telnet":
	    return self.TelnetTestType()
        else:
            raise InputError(self.connection_type, "Not a good connection type !")

################################################################
    def GetPromptAndType(self):
        if self.connection_type == "ssh":
	    return self.SSHGetPromptAndType()
	if self.connection_type == "telnet":
	    return self.TelnetGetPromptAndType()
        else:
            raise InputError(self.connection_type, "Not a good connection type !")
################################################################
## SSHConnect (package Paramiko)
################################################################
    def SSHConnect(self):
        """
        SSHConnect(self) -> Boolean
        Try to establish an SSH connection and return True or False.

        @param switch: the switch object
        @type switch: switch
	@rtype: bool
        """
        print "Starting SSH Connection"
        client = SSHClient()
        # set the key policy to add the key if the host is unknown
        client.set_missing_host_key_policy(AutoAddPolicy())
        try :
            client.load_host_keys(self.known_hosts)
        except IOError:
            print "***SSHConnect*** Unable to load the SSH host keys file : %s" % str(self.known_hosts)
            client.close()
            return False

        try:
            # Connecting to hostname, on port 22 (SSH), username and password defined. Set the timeout and disable the connection to the local agent.
            #client.connect(self.address, port=22, username=self.user, password=self.password, pkey=None, key_filename=self.ssh_key, timeout=self.timeout, allow_agent=False, look_for_keys=True)
	    client.connect(self.address, port=22, username=self.user, password=self.password, pkey=None, timeout=self.prompt_timeout, allow_agent=False, look_for_keys=False)
        except BadHostKeyException:
            print '***SSHConnect*** Bad SSH host key ! Closing connection...'
            client.close()
            return False
        except AuthenticationException:
            print '***SSHConnect*** Authentication refused !'
            client.close()
            return False
        except SSHException:
            print '***SSHConnect*** Connection refused for an unknow reason!'
            client.close()
            return False
        except socket.error:
	    print '***SSHConnect*** Connection refused : socket error !'
            client.close()
            return False
        print "SSH connection and authentication successfully done"
        self.client = client
	return True

#################################################################
    def SSHTestType(self):
	"""
        SSHTestType(self) -> Boolean
        Test the switch type and try to grab the switch's name. Return true if it is successful.

        @rtype: bool
        """
        # Try to get the switch's name by the self.commandtest
        print "Testing the switch with the SSH command :" + self.commandtest
        stdin, stdout, stderr = self.client.exec_command(self.commandtest)
        output = stdout.read().strip('\r\n')
        error = stderr.read().strip('\r\n')
	if self.debug:
            print "out : " + output
            print "err : " + error
        response = []
        if error:
            if self.type == "brocade":
                # For Brocade switch running certains Fabric OS versions (> 6), the exec_command doesn't work well so we must try to get an output from the switch by invoking a real shell
	        print "Trying to degrading to a real SSH shell..."
                try:    
                    shell = self.client.invoke_shell()
                except SSHException:
                    print '***SSHTestType*** Unable to have a real SSH shell with this Brocade switch'
                    self.client.close()
                    return False
                self.ssh_shell = True # set the flag that the switch require the use of a shell to work well
                shell.set_combine_stderr(True) #combine standard and error outputs
		shell.settimeout(self.read_timeout) #set timeout for commands
                shellfile = shell.makefile('rw')
                ret = '\r' # defining the return caracter
                # sending the commandtest to the switch
                shellfile.write(self.commandtest + ret)
                shellfile.flush()
	        time.sleep(self.read_timeout)
                # sending a return caracter in order to get the prompt after the command on the shell
                shellfile.write(ret)
                shellfile.flush()
                commandseen = False #a flag that tell if the command has been seen in the output line
                while True:
                    if shell.recv_ready():
			try:
		            shell_line = shell.recv(512)
			except socket.timeout:
		            print '***SSHTestType: Timeout when reading line: "%s" !' % str(shell_line)
			    self.client.close()
			    return False
		        if self.debug:
			    print "SSHTestType shell line: '%s'" % str(shell_line)
		        response.append(shell_line) #concatenate the output
		        #lines = response.splitlines()
			lines = shell_line.splitlines()
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
                print "***SSHTestType*** Not the good type of switch: " + str(error)
                self.client.close()
                return False
        else:
            response = output

        if not self.GetSwitchName(response):
            print '***SSHTestType*** Unable to get the switchname from the output: "%s" !' % str(response)
            self.client.close()
            return False

        print "Good type of switch ! Switch's name: " + str(self.name)
	return True

#################################################################
    def SSHGetPromptAndType(self):
	"""
        SSHGetPromptAndType(self) -> Boolean
	Try to get a Prompt and to guess the type of equipment     

        @rtype: bool
        """
	#we send a return character and we wait for the prompt.
        ret = '\r' # defining the return caracter
        # Try to get the switch's name by the self.commandtest
	print "Waiting the prompt..."
        response = []
        try:    
                shell = self.client.invoke_shell()
        except SSHException:
                print '***SSHGetPrompt*** Unable to have a real SSH shell with this switch !'
                self.client.close()
                return False
        shell.set_combine_stderr(True) #combine standard and error outputs
        shell.settimeout(self.prompt_timeout) #set timeout for commands
        shellfile = shell.makefile('rw')
	time_start = time.time()
        while True:
                    if shell.recv_ready():
			try:
		            shell_line = shell.recv(512)
			except socket.timeout:
		            print '*** SSHGetPrompt: Timeout when reading line: "%s" !' % str(shell_line)
			    self.client.close()
			    return False
		        if self.debug:
			    print "SSHGetPrompt shell line: '%s'" % str(shell_line)
 		        response.append(shell_line) #concatenate the output
			if self.GetSwitchTypeFromPrompt(shell_line):
			    return True
		            break
		    else:
			elapsed = time.time() - time_start
			if elapsed > self.prompt_timeout:
			    if not response:
	                        print "***SSHGetPrompt*** Prompt timeout ! No response for the prompt !"
	                        return False
			    else:
				response = ''.join(response)
                                if self.debug:
				    print 'SSHGetPrompt: Prompt timeout ! Got the response: "%s"' % str(response)
	                        if self.GetSwitchTypeFromPrompt(response):
                                    return True
			        else:
				    print '*** SSHGetPrompt *** Impossible to guess the equipment type from the response: "%s"' % str(response)
			            return False
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
        if not self.ssh_shell:
            stdin, stdout, stderr = self.client.exec_command(command)
	    output = stdout.read().strip('\r\n')
	    error = stderr.read().strip('\r\n')
	    if self.debug:
	        print "output : " + output
	        print "error : " + error
	    if error:
	        print "***SSHCommand*** Error with the command on the switch :" + str(error)
	        raise CommandError(error,"***SSHCommand*** Error with the command on the switch !")

        else:  #the self.ssh_shell attribute is true
           try:    
               shell = self.client.invoke_shell()
	   except SSHException:
   	       print '***SSHCommand*** Unable to have an SSH shell from the switch'
	       self.client.close()
   	       raise ConnectionError("SSHCommand",'***SSHCommand*** Unable to have an SSH shell from the switch' )

	   shell.set_combine_stderr(True)
	   shell.settimeout(self.read_timeout) #set timeout for commands
	   shellfile = shell.makefile('rw')
           # defining the return caracter
	   ret = '\r'
           # sending the commandtest to the switch
           shellfile.write(command + ret)
           shellfile.flush()
           time.sleep(self.read_timeout) # wait connectime seconds
           # sending a return caracter in order to get the prompt after the command on the shell
           shellfile.write(ret)
           shellfile.flush()
           commandseen = False #a flag that tell if the command has been seen in the output line
	   output = []
           while True:
               if shell.recv_ready():
		   try:
                       shell_line = shell.recv(256)
		   except socket.timeout:
		       print '*** SSHCommand: Timeout when reading line: "%s" !' % str(shell_line)
		       self.client.close()
		       raise ConnectionError("SSHCommand",'SSHCommand: Timeout when reading line: "%s" !' % str(shell_line))
	           if self.debug:
		       print "SSHCommand shell line: '%s' " % str(shell_line)

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
		   lines = shell_line.splitlines()
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
	except SSHException:
   	    print '***SSHSave*** Unable to have an SSH shell from the switch !'
	    self.client.close()
   	    return False

	shell.set_combine_stderr(True)
	shell.settimeout(self.read_timeout) #set timeout for commands
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
			raise ConnectionError('***SSHSave***','Connection refused by the SSH or FTP Server !')
		    #reading asked section line : Section (all|chassis [all]):
		    elif 'section' in shell_line.lower():
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
                        if elapsed >= (self.read_timeout + 30) :
                            print "***SSHSave*** Timeout with the command"
                            break
   
            else:
                elapsed = time.time() - time_start
                if elapsed >= (self.read_timeout + 30):
                    print "***SSHSave*** Timeout with the command"
                    break

        # waiting for the result of the server.
	try:
	    result = server_queue.get(True, self.queue_timeout)
	except:
            print '***SSHSave*** Transfert Failed !'
	    server_thread._Thread__stop()
            self.client.close()
	    return False
	    
        if result == 'backup OK':
            print 'Transfert and Backup successfully done ! in the file : '+ self.file
	    server_thread._Thread__stop()
	    self.client.close()
            return True
        else:
	    print '***SSHSave*** Transfert Failed !'
	    server_thread._Thread__stop()
            self.client.close()
	    return False


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
	#promptlist = ['login', 'sername'] #prompt can be login or username
	response = ''
        try:
	    tn = telnetlib.Telnet(self.address)
            response = tn.read_until('ogin', self.prompt_timeout)
	    #(index, match, response) = tn.expect(promptlist, self.prompt_timeout)
	    #(response) = tn.read_all()
            #(response) = tn.read_some()
	    if self.debug:
                print "TelnetConnect: login response: '%s'" % str(response)
        except EOFError:
            print "***TelnetConnect*** Telnet connection impossible to connect to the host :" + self.address
            return False
        """
        if not 'sername' in response:
            print "***TelnetConnect*** Telnet connection impossible to connect to the host :" + self.address
            return False
	"""
        # sending username and password to the switch
        try:
	    print "sending username..."
            tn.write(self.user + "\n")
        except socket.error:
            print "***TelnetConnect*** Connection refused by the host when trying to write username :" + str(self.address)
            tn.close()
            return False
        response = ''
        try:
            response = tn.read_until("assword", self.prompt_timeout)
	    if self.debug:
                print "TelnetConnect: password response: '%s'" % str(response)
        except EOFError:
            print "***TelnetConnect*** Connection refused by the host when waiting for the password prompt :" + str(self.address)
            tn.close()
            return False
        if ('sername' in response) or ('ogin' in response):
            print "***TelnetConnect*** wrong username for host :" + str(self.address)
            tn.close()
            return False
	try:
	    print "sending password..."
            tn.write(self.password + "\n")
        except socket.error:
            print "***TelnetConnect*** Connection refused by the host when trying to write password :" + str(self.address)
            tn.close()
            return False
        
            #response = tn.read_until(self.prompt, self.prompt_timeout)
	response = ''
	promptlist = ['#', '>', '\$']
	(index, match, response) = tn.expect(promptlist, self.prompt_timeout)
	if self.debug:
            print "TelnetConnect: index %s, match %s, response: '%s'" % (str(index), str(match), str(response))
        if ('assword' in response) or ('ogin' in response) or ('sername' in response):
            print "***TelnetConnect*** Connection refused by the host. Wrong login or password for host :" + str(self.address)
            tn.close()
            return False
        if match:
	    self.prompt = promptlist[index]
            self.client = tn
            return True
################################################################
    def TelnetTestType(self):
	"""
        TelnetTestType(self) -> Boolean
        Test the switch type and try to grab the switch's name. Return true if it is successful.

        @rtype: bool
        """
        # Try to get the switch's name by the switch.commandtest
        print "Got a Telnet Shell. Testing the switch with the command :" + self.commandtest
        self.client.write(self.commandtest + "\n")
        response = '' # erase last response
        response = self.client.read_until(self.prompt, self.read_timeout)
	if self.debug:
	    print "TelnetTestType response: '%s'" % response
        if not self.GetSwitchName(response):
            print "***TelnetTestType*** Unable to get the switchname from the output :" + str(response)
	    self.client.close()
            return False
        print "Good type of switch ! Switch's name :" + str(self.name)
        return True

################################################################
    def TelnetGetPromptAndType(self):
	"""
        TelnetGetPromptAndType(self) -> Boolean
        Test the switch type and try to grab the switch's name. Return true if it is successful.

        @rtype: bool
        """
        # Try to get the switch's name by the switch.commandtest
	#we send a return character and we wait for the prompt.
        ret = '\r\n' # defining the return caracter
        self.client.write(ret)
        response = '' # erase last response
        response = self.client.read_until(self.prompt, self.read_timeout)
	if self.debug:
	    print "TelnetGetPromptAndType response: '%s'" % response
	if self.GetSwitchTypeFromPrompt(response):
            return True
        else:
	    print "***TelnetGetPromptAndType*** Unable to guess the type from the output :" + str(response)
	    return False
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
	    self.client.read_until(self.prompt, self.read_timeout)
	
	print "Sending the command to the switch :" + str(command)
        self.client.write(command + "\r") # sending the command

        print "Reading the output..."
        response = [] # erase last response
	shell_line = ''
        while not self.prompt in shell_line:
            shell_line = self.client.read_until(self.prompt, self.read_timeout)
            response.append(shell_line)
	    if self.debug:
		print "TelnetCommand shell line: '%s'" % str(shell_line)
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
    def TelnetSave(self, server_queue, server_thread):
        """
        TelnetSave(self, server_queue, server_thread) -> None
        Tell the switch to send its backup config file to the SSH or the FTP Server.

        @param server_queue: server queue
        @param server_thread: server Thread
        @type server_thread: Thread
        """
        server_thread.start() #start the FTP or SCP Server
        # sending the command
        print 'Sending the command to the switch : ' + self.commandsave
        self.client.write(self.commandsave + "\n")
        if (self.type == "brocade"):
            # we need to send the protocol, host, user, file and password to begin the transfert.
            response = '' # erasing the last response	
            #reading asked protocol line : Protocol (scp or ftp) [ftp]:
            response = self.client.read_until('rotocol', self.read_timeout)
            #print "response prot: " + response
            if 'rotocol' in response:
        	#print "response prot: " + response
        	self.client.write( self.transfert_type + "\n")
        	response = ''
        	#reading asked host line : Server Name or IP Address [host]:
        	response = self.client.read_until('host', self.read_timeout)
		#reading asked section line : configupload must use secure protocol :
        	if 'must use secure protocol' in response:
        	    print "*** TelnetSave *** The switch is in secure mode :" + response
                    print '*** TelnetSave *** Transfert Failed !'
                    server_thread._Thread__stop()
                    self.client.close()
                    raise ConnectionError('*** TelnetSave ***','The switch is in secure mode !')
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
        	response = self.client.read_until('ser', self.read_timeout)
        	#print "response user: " + response
        	self.client.write( self.transfert_user + "\n")
        	response = ''
        	#reading asked file line : File Name [config.txt]:
        	response = self.client.read_until('ile', self.read_timeout)
        	#print "response file: " + response
        	self.client.write( self.file + "\n")
        	response = ''
        	#reading asked section line : Section (all|chassis [all])::
        	response = self.client.read_until('ection', self.read_timeout)
        	if "ection" in response:
        	    self.client.write( "all" + "\n")
        	response = ''
        	#reading asked password line : Password:
        	response = self.client.read_until('assword', self.read_timeout)
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
        	response = self.client.read_until('ser', self.read_timeout)
        	#print "response user: " + response
        	self.client.write( self.transfert_user + "\n")
	        response = ''
	        #reading asked file line : File Name [config.txt]:
	        response = self.client.read_until('ile', self.read_timeout)
	        #print "response file: " + response
	        self.client.write( self.file+ "\n")
	        response = ''
                #reading asked protocol line : Protocol (scp or ftp) [ftp]:
                response = self.client.read_until('rotocol', self.read_timeout)
                self.client.write( self.transfert_type + "\n")
                response = ''
	        #reading asked section line : Section (all|chassis [all])::
	        response = self.client.read_until('ection', self.read_timeout) # a new feature of brocade
	        if "section" in response:
	            self.client.write( "all" + "\n") # we send "all" in response
		#reading asked section line : configupload must use secure protocol :
	        if 'must use secure protocol' in response:
	            print "*** TelnetSave *** The switch is in secure mode :" + response
	        response = ''
                #reading asked password line : Password:
                response = self.client.read_until('assword', self.read_timeout)
                #print "response pass: " + response
                #sending the password for the transfert
	        print 'Sending password for the transfert'
                self.client.write( self.transfert_password + "\n")

        else: # For Cisco switch :
            response = '' #reading asked section line : configupload must use secure protocol :
            #sending the password for the transfert
            response = self.client.read_until('assword', self.read_timeout)
            #print "response : " + response
	    if 'assword' in response: 
	        print 'Sending password for the transfert'
	        self.client.write(self.transfert_password + "\n")
            if ('refused' in response) or ('failed' in response):
                print '*** TelnetSave *** Connection refused by the SSH or FTP Server :' + response
                server_thread._Thread__stop()
                self.client.close()
                return False
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
            return False

        if result == 'backup OK':
            print "Transfert and Backup successfully done in the file :" + self.file
            server_thread._Thread__stop()
            self.client.close()
            return True
        else:
            print '*** TelnetSave *** Transfert Failed !'
            server_thread._Thread__stop()
            self.client.close()
            return False
	
################################################################
## GetMcdataConfig Function
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
    		return False
    
	if not hasattr(e, 'code') or e.code != 401:                 # we got an error - but not a 401 error
   		print "***MCDATA*** The switch isn't protected by authentication. But we failed for another reason."
    		return False

	authline = e.headers.get('www-authenticate', '')                # this gets the www-authenticat line from the headers - which has the authentication scheme and realm in it
	if not authline:
    		print '***MCDATA*** A 401 error without an authentication response header - very weird.'
    		return False
    
	authobj = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"](\w+\s\w+)['"]''', re.IGNORECASE)          # this regular expression is used to extract scheme and realm
	matchobj = authobj.match(authline)
	if not matchobj:                                        # if the authline isn't matched by the regular expression then something is wrong
    		print '***MCDATA*** The authentication line is badly formed.'
    		return False
	scheme = matchobj.group(1) 
	realm = matchobj.group(2)
	if scheme.lower() != 'basic':
    		print '***MCDATA*** Only works with BASIC authentication.'
    		return False

	base64string = base64.encodestring('%s:%s' % (self.user, self.password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
    		handle = urllib2.urlopen(req)
	except IOError, e:                  # here we shouldn't fail if the username/password is right
    		print "***MCDATA*** It looks like the username or password is wrong."
    		return False
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
    		return False
	theconfig = handle2.read()

	if len(theconfig) == 0:
		print '***MCDATA*** Nothing in the swconfig.xml file !'
		return False
	#now parsing the XML file in order to get the name of the switch.
	dom1 = parseString(theconfig)
	try:
		tagnames = dom1.getElementsByTagName("Name")[0]
		self.name = tagnames.firstChild.data
	except:
		print '***MCDATA*** Unable to find the name of the switch in swconfig.xml !'
	    	return False

	# we try to make a file in order to save the configuration file
	self.file = self.name + '__' + time.strftime('%Y%m%d__%H%M',time.localtime()) +'__'+ 'mcdata.xml'

        if not self.SaveFileInDirectory(theconfig, self.file, self.name):
            print "Unable to save the configuration in the file :" + self.file
            return False

        print "Successfully saved the configuration in the file :" + self.file
        return True


################################################################
# End of the Switch's Class
################################################################

################################################################
## Generate 1024 bits SSH key for the SSH Server (Paramiko)
################################################################
def GenerateServerKey(type='RSA', keylength=1024):
    """
    GenerateServerKey(type, keylength) -> None
    Create a new 1024 bits key for the SSH server on your host. The Key can be an RSA (default) or DSS key.
    The private key is saved in the file 'new_server_'type'.key' on your current directory. The public key is saved in the file 'new_server_'type'.pub'.

    @param type : str
    @param keylength : int
    """
    if type == 'RSA':
        key = paramiko.RSAKey.generate(int(keylength)) #generate the private key
	public_key_header = "ssh-rsa "
    elif type == 'DSS':
        key = paramiko.DSSKey.generate(int(keylength)) #generate the private key
	public_key_header = "ssh-dss "
    else:
	print "*** GenerateServerKey *** Not a good type of key. Possible values are RSA or DSS !"
	raise InputError("*** GenerateServerKey ***", "Not a good type of key. Possible values are RSA or DSS !")
    
    filename = 'new_server_%s' % str(type)
    key.write_private_key_file(filename + '.key') #saving the private key
    public_file = open(filename + '.pub','w') #create the file for public key
    public_file.write(public_key_header + key.get_base64())
    public_file.close()

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
def SSHserver_launch(switch, server_queue, timeout):
        """
        SSHserver_launch(switch, server_queue, timeout): -> None
        Launch an SSH Server on the host. It grabs the switch's configuration file by SCP and store it in a folder with the switch's name.
        The output is saved in a file's name pattern : switchname__time__switchtype.txt.

        @param switch: the switch object
        @type switch: Switch
        @param server_queue: server queue
        @param timeout: timeout
        @type timeout: int
        """
	if switch.server_key_type == 'RSA':
	    host_key = paramiko.RSAKey(filename=switch.server_key)
        elif switch.server_key_type == 'DSS':
	    host_key = paramiko.DSSKey(filename=switch.server_key)
        else:
	    print "***SSHServer*** Wrong type of SSH key. Possible values are RSA or DSS !"
	    raise SCPError("SSHServer","Wrong type of SSH key. Possible values are RSA or DSS !")
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
    		raise SCPError("SSHServer","Could not bind on port 22 !")

	try:
		#we start the SSH server for only one connection
   		sock.listen(1)
		print 'SSHServer : Listening for connection ...'
    		client, addr = sock.accept()
	except Exception, e:
    		print '***SSHServer*** Listen/accept failed:' + str(e)
    		traceback.print_exc()
    		raise SCPError("SSHServer", "Listen/accept failed !")
	try:
    		t = paramiko.Transport(client)
    
		if switch.debug:
			t.set_hexdump(True)            # use it only for debugging purpose !
		if not t.load_server_moduli():
        		print '***SSHServer*** (Failed to load moduli -- gex will be unsupported.)'
    		t.add_server_key(host_key)
		#instantiate an SCP Server
    		SCPserver = SCPServer(switch.transfert_user,switch.transfert_password)
    		try:
        		t.start_server(server=SCPserver)
    		except SSHException:
        		print '***SSHServer*** SSH negociation failed !'
        		raise SCPError('***SSHServer***', 'SSH negociation failed !')

    		# waiting timeout seconds for a channel to be opened by the switch
    		serv_channel = t.accept(timeout)
    		if serv_channel is None:
        		print '***SSHServer*** No channel before the timeout !'
        		server_queue.put('backup FAIL')
		
		# waiting for the scp command from the switch. See the SCPServer class definition
    		SCPserver.SCPevent.wait(timeout)
    		if not SCPserver.SCPevent.isSet():
        		print '***SSHServer*** Client has never asked for an SCP transfer.'
			server_queue.put('backup FAIL')	

		## Beginning of the SCP protocol : we acknowledge the command received and the rest of the transfert with zero. One zero for the each line of the SCP commands.
		## a really bad hack :-(
		## but it really works :-)
    		serv_channel.send('\0\0\0\\')
    		
    		# we are reading the command sent by the switch and we verify it
    		channel_file = serv_channel.makefile('r')
    		received_command = channel_file.readline().strip('\r\n')
    		channel_file.close()
    		if not received_command.startswith('C'):
			print '***SSHServer*** Expecting a C command for the SCP transfert, but we received: %s.' % str(received_command)
			server_queue.put('backup FAIL')
		# we get the differents arguments of the command
    		r_perm, r_length, r_name = received_command.split(" ")
		# we get the perms, but don't really use it :-(
    		perms = r_perm[1:-1]
    		perms = int(perms, 8)
    		length = int(r_length)
		print 'SSHServer : Getting file: ' + str(r_name)  + ' perms: '+ str(oct(perms))+ ' length of file: ' + str(length)
    		if length == 0:
	    		print '***SSHServer*** Error the length of the file is zero byte !'
	    		server_queue.put('backup FAIL')
			
		
		s = serv_channel.makefile('r')
    		data = []
    		try:
	    		while True:
				#data += s.next()
				data.append(s.next())
				if switch.debug:
					print 'SSH Server: received data : %s' % str(data[-1])
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
		serv_channel.shutdown_write()
    		serv_channel.send_exit_status(0) #sending exit status OK
    		serv_channel.close()
    		t.close()

    		if len(data) == 0:
    			print '***SSHServer*** Nothing in the file received'
			server_queue.put('backup FAIL')
			
    		if len(data) < length:
	   		print '***SSHServer*** Received not complete !'
			server_queue.put('backup FAIL')

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
		self.server_queue = server_queue
		self.interface = switch.interface
		self.timeout = timeout
        	self.backupOK = False
		self.file = switch.file

    	def run(self):
		# Changing the working directory
                if not self.switch.ChangeDir(self.switch.name):
                    print "***FTPServer*** Unable to go the directory with this switch's name : "+str(self.switch.name)
		    self.server_queue.put('backup FAIL')
                    raise FTPError("FTPServer", "Unable to go the directory with this switch's name")
		
		# we verify if this backup doesn't exist
		if (os.path.isfile(self.file)):
	            self.file2 = str(self.file) + "_old.txt"
		    print "***FTPServer*** The file "+str(self.file)+" already exists ! It will be renamed in: "+str(self.file2)+" !"
		    try:
		        os.rename(self.file, self.file2)
		    except:
		        print "***FTPServer*** Unable to rename the file:"+str(self.file)
			raise FTPError("FTPServer", "Unable to rename the file")

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
    		# Specify a masquerade address and the range of ports to use for passive connections.
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
# Class for raising exceptions
############################################
class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class InputError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

class CommandError(Error):
    """Exception raised for errors with connection.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

class ConnectionError(Error):
    """Exception raised for errors with connection.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

class FTPError(Error):
    """Exception raised for errors with connection.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

class SCPError(Error):
    """Exception raised for errors with connection.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

############################################
# END 
############################################
if __name__ == '__main__':
    pass
