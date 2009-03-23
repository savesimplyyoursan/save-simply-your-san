#!/usr/bin/python
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
import paramiko
import telnetlib

# hexlify used for the public key authentication. Not supported yet because Brocade switch don't support it
#from binascii import hexlify

from random import choice
from optparse import OptionParser
from paramiko import SSHClient, AutoAddPolicy, BadHostKeyException, AuthenticationException, SSHException

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

################################################################
# Beginning of the Host's Class
################################################################
class Host(object):
    """
    Host(object)
    A class for the switch object
    """
    def __init__(self, address, switch_type, user, password, connection_type, timeout, key):
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
        @param timeout: timeout
        @type timeout: int
	@param nat: ip address
	@type nat: str
        """
        self.address = address
        self.type = switch_type
        self.user = user
        self.password = password
        self.connection_type = connection_type
        self.timeout = timeout
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
	       sys.exit(STATE_WARNING)
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
                return True
################################################

    def ChangeDir(self, directory):
        """
        ChangeDir(self, directory) -> Boolean
        Try to go in the directory specified. If it fails, creates a new directory in the current directory and change into it. Return True or False.

        @rtype: bool
        """
	"""
	if self.dir == 'byday':
	    directory = time.strftime('%Y%m%d',time.localtime())
	if self.dir != 'no':
	    directory = str(self.dir)
	"""
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
		sys.exit(STATE_CRITICAL)
	if self.connection_type == "telnet":
	    if not self.TelnetConnect():
		sys.exit(STATE_CRITICAL)
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
        #print "Starting the SSH Connection"
        client = SSHClient()
        # set the key policy to add the key if the host is unknown
        client.set_missing_host_key_policy(AutoAddPolicy())
	"""
	try:
            know = open('known_hosts', 'w')
	    know.close()
	except:
            print "impossible to create the file"
	#client.load_host_keys('known_hosts')
        try :
            #client.load_system_host_keys('known_hosts')
            client.load_host_keys('known_hosts')
        except IOError:
            dir = sys.path[0]
	    print "***SSHConnect*** Unable to load the SSH host keys file : known_hosts in the directory: "+str(dir)
            client.close()
            return False
	"""
        try:
            # Connecting to hostname, on port 22 (SSH), username and password defined. Set the timeout and disable the connection to the local agent. An authentification with private key is also tried
            client.connect(self.address, port=22, username=self.user, password=self.password, pkey=None, key_filename=self.ssh_key, timeout=self.timeout, allow_agent=False, look_for_keys=True)
        except BadHostKeyException:
            print '***SSHConnect*** Bad SSH host key ! Closing connection...'
            client.close()
            return False
        except AuthenticationException:
            print '***SSHConnect*** Authentication refused !'
            client.close()
            return False
        except SSHException:
            print '***SSHConnect*** Connection refused !'
            client.close()
            return False
        #print "SSH connection successfull"

        # Try to get the switch's name by the self.commandtest
        #print "Got a SSH Shell. Testing the switch with the command :" + self.commandtest
        stdin, stdout, stderr = client.exec_command(self.commandtest)
        output = stdout.read().strip('\r\n')
        error = stderr.read().strip('\r\n')
        response = []
        if error:
            if self.type == "brocade":
  
            # For Brocade switch running certains Fabric OS versions (> 6), the exec_command doesn't work well so we must try to get an output from the switch by invoking a real shell
	        #print "Degrading to a real SSH shell..."
                try:    
                    shell = client.invoke_shell()
                except SSHException:
                    print '***SSHConnect*** Unable to have a real SSH shell'
                    client.close()
                    sys.exit(STATE_CRITICAL)
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
			response.append(shell_line)
			lines = shell_line.splitlines()
		        if self.prompt in lines[-1]:
		            break
	        response = ''.join(response)
            else: # for macdata or cisco switches
                print "***SSHConnect*** Not the good type of switch :" + str(error)
                client.close()
                return False
        else:
            response = output

        if not self.GetSwitchName(response):
            print "***SSHConnect*** Unable to get the switchname from the output :" + str(response)
            client.close()
            return False

        #print "Good type of switch ! Switch's name :" + str(self.name)
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
        #print 'Sending the command :' + command

        #filename = self.name + '__' + command + '__' + time.strftime('%Y%m%d__%H%M',time.localtime())+ '__' + self.type + '.txt'
        if not self.ssh_shell:
            stdin, stdout, stderr = self.client.exec_command(command)
	    output = stdout.read().strip('\r\n')
	    error = stderr.read().strip('\r\n')
	    if error:
	        print "***SSHCommand*** Error with the command on the switch :" + str(error)
	        sys.exit(STATE_CRITICAL)

        else:  #the self.ssh_shell attribute is true
           try:    
               shell = self.client.invoke_shell()
	   except SSHException:
   	       print '***SSHCommand*** Unable to have an SSH shell from the switch'
	       self.client.close()
   	       sys.exit(STATE_CRITICAL)

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
		   output.append(shell_line)
	           if ("--More--" in shell_line) or ("Type <CR>" in shell_line):
                       #print "I'm sending the space caracter to continue."
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
## TelnetConnect (telnetlib)
################################################################
    def TelnetConnect(self):
        """
        TelnetConnect(self) -> Boolean
        Try to establish a telnet connection and return it.

        @rtype: bool
        """
        #print "Starting the Telnet connection"
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
        #print "Got a Telnet Shell. Testing the switch with the command :" + self.commandtest
        tn.write(self.commandtest + "\n")
        response = '' # erase last response
        response = tn.read_until(self.prompt, self.timeout)
        if not self.GetSwitchName(response):
            print "***TelnetConnect*** Unable to get the switchname from the output :" + str(response)
	    tn.close()
            return False
        #print "Good type of switch ! Switch's name :" + str(self.name)
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
	
	#print "Sending the command to the switch :" + str(command)
        self.client.write(command + "\r") # sending the command

        #print "Reading the output..."
	response = [] # erase last response
	shell_line =''
        while not self.prompt in shell_line:
	    shell_line = self.client.read_until(self.prompt, self.timeout) # join the output
	    response.append(shell_line)
            # on brocade, it will ask you to press enter to continue
            if ("--More--" in shell_line) or ("Type <CR>" in shell_line):
                print "I'm Sending the space caracter to continue."
                self.client.write(chr(32)) # chr(32) is the space caracter
                self.client.write('\n') # Also send return in case of the last line.
                # Cleaning the response
                #response = response.replace('--More--','')
                #response = response.replace('Type <CR> or <SPACE BAR> to continue, <q> to stop','')
	response = ''.join(response)
	return response
####################################################
### Parsing Functions
####################################################

#####################"
def ParseUptime(switch, input):
    """
    ParseUptime(switch, input) -> Boolean
    Parse to find an uptime (status, description)

    @param input: type of check
    @type input: bool

    @rtype: bool
    """
    lines = input.splitlines()
    if switch.type == "cisco":
        regexp = re.compile(r".*uptime:\s+(\d+)\sdays,\s(\d+)\shours,\s(\d+)\sminutes,\s(\d+)\sseconds$", re.IGNORECASE)
        system_line = [line for line in lines if line.startswith("System uptime")]
	kernel_line = [line for line in lines if line.startswith("Kernel uptime")]
        active_line = [line for line in lines if line.startswith("Active supervisor uptime")]

        if (not system_line[0]) or (not kernel_line[0]) or (not active_line[0]):
            return False
        sys_matchreg = [regexp.match(line) for line in system_line]
        kern_matchreg = [regexp.match(line) for line in kernel_line]
        active_matchreg = [regexp.match(line) for line in active_line]
        if (not sys_matchreg[0]) or (not kern_matchreg[0]) or (not active_matchreg[0]):
            return False
	days, hours, minutes, seconds = sys_matchreg[0].group(1), sys_matchreg[0].group(2), sys_matchreg[0].group(3), sys_matchreg[0].group(4)
	switch.sys_uptime = int(minutes) + 60 * int(hours) + 1440 * int(days)
	days, hours, minutes, seconds = kern_matchreg[0].group(1), kern_matchreg[0].group(2), kern_matchreg[0].group(3), kern_matchreg[0].group(4)
	switch.kernel_uptime = int(minutes) + 60 * int(hours) + 1440 * int(days)
	days, hours, minutes, seconds = active_matchreg[0].group(1), active_matchreg[0].group(2), active_matchreg[0].group(3), active_matchreg[0].group(4)
	switch.active_uptime = int(minutes) + 60 * int(hours) + 1440 * int(days)
	return True
    elif switch.type == "brocade":
	#line = 3:08pm   up for 469 days 2 hrs 21 mins
	regexp = re.compile(r".*\s+(\d+)\sdays\s+(\d+)\shrs\s+(\d+)\smins", re.IGNORECASE)
	matchreg =  [regexp.match(line) for line in lines]
        if not matchreg[0]:
            return False
	days, hours, minutes = matchreg[0].group(1), matchreg[0].group(2), matchreg[0].group(3)
	switch.uptime = int(minutes) + 60 * int(hours) + 1440 * int(days)
        return True
    elif switch.type == "mcdata":
	#show fru
	#FRU       Position  State   Serial Num  Part Num             Beacon  Pwr On Hrs
	#--------  --------  ------  ----------  -------------------  ------  ----------
	#CTP       0         Active  E11111111   111111111            off     12662     
	#Power     0         Active                                                     
	#Power     1         Active     
	regexp = re.compile(r"^CTP.*\s+(\d+).*$", re.IGNORECASE)
	matchreg =  [regexp.match(line) for line in lines if line.startswith(u"CTP")]
        if not matchreg[0]:
            return False
	hours = matchreg[0].group(1)
	switch.uptime = 60 * int(hours)
        return True
    else:
	return False

######################
def ParseEnvironment(switch, input):
    """
    ParseEnvironment(switch, input) -> Boolean
    Parse to find an uptime (status, description)

    @param input: type of check
    @type input: bool

    @rtype: bool
    """
    lines = input.splitlines()

    if switch.type == "cisco":
	switch.fan_list = []
	switch.clock_list = []
	switch.temp_list = []
	switch.ps_list = []
	switch.module_list = []
	fan_flag = False
	clock_flag = False
	temp_flag = False
	ps_flag = False
	module_flag = False
	fan_regexp = re.compile(u"^([^\s]+)\s+(.*)\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
	clock_regexp = re.compile(u"^([^\s]+)\s+(.*)\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
	temp_regexp = re.compile(u"^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
	ps_regexp = re.compile(u"^([^\s]+)\s+([^\s]*)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
	module_regexp = re.compile(u"^([^\s]+)\s+([^\s]*)\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+([^\s]+)", re.IGNORECASE)
        for line in lines:
		#print fan_flag
	    if line.startswith("Fan:"):
                fan_flag = True
	    if line.startswith("Clock:"):
                clock_flag = True
	    if line.startswith("Temperature:"):
                    temp_flag = True
	    if line.startswith("Power Supply:"):
                ps_flag = True
		temp_flag = False
	    if line.startswith("Mod "):
                module_flag = True
	    if line is "":
                fan_flag = False
		clock_flag = False
		ps_flag = False
		module_flag = False
	    if fan_flag:
		matchreg = fan_regexp.match(line)
	        if matchreg:
	            fan = name, model, hw, status = matchreg.group(1), matchreg.group(2), matchreg.group(3), matchreg.group(4)
	            if not "Status" in status:
			switch.fan_list.append(fan)
	    if clock_flag:
		clock_list = line.split('  ')
		clock_list = [list for list in clock_list if not list.startswith('---') ]
		if ( len(clock_list) > 1 ) and ( not clock_list[0].startswith(u"Clock") ):
		#if (not clock_list[0].startswith(u"Clock")):
		    clock = name, model, hw, status = clock_list[0], clock_list[1], clock_list[2], clock_list[-1]
		    switch.clock_list.append(clock)

	    if temp_flag:
		matchreg = temp_regexp.match(line)
	        if matchreg:
	            temperature = module, name, MajorThresh, MinorThresh, CurTemp, status = matchreg.group(1), matchreg.group(2), matchreg.group(3), matchreg.group(4), matchreg.group(5), matchreg.group(6)
		    if not "Status" in status:
			switch.temp_list.append(temperature)
	    if ps_flag:
		matchreg = ps_regexp.match(line)
	        if matchreg:
	            ps = number, model, Watts, Amp, status = matchreg.group(1), matchreg.group(2), matchreg.group(3), matchreg.group(4), matchreg.group(5)
	            if not "Status" in status:
			switch.ps_list.append(ps)
	    if module_flag:
		matchreg = module_regexp.match(line)
	        if matchreg:
	            module = number, model, status = matchreg.group(1), matchreg.group(2), matchreg.group(3)
		    if not ("Status" in status or "---" in status):
			switch.module_list.append(module)
	if not matchreg:
            return False
        else:
	    return True
    elif switch.type == "brocade":
        return False
    elif switch.type == "mcdata":
        return False
    else:
        return False

#####################
def ParseResources(switch, input):
    """
    ParseResources(switch, input) -> Boolean
    Parse to find an uptime (status, description)

    @param input: type of check
    @type input: bool

    @rtype: bool
    """
    lines = input.splitlines()
    cpu_flag = False
    mem_flag = False
    proc_flag = False
    if switch.type == "cisco":
	cpu_line = [line for line in lines if line.startswith("CPU")]
	mem_line = [line for line in lines if line.startswith("Memory")]
	proc_line = [line for line in lines if line.startswith("Processes")]
	    
	if (not cpu_line) or (not mem_line) or (not proc_line):
            return False
        cpu_regexp = re.compile(u"^CPU\sstates\s+:\s+(\d+).*\s+(\d+).*\s+(\d+).*\sidle", re.IGNORECASE)
	mem_regexp = re.compile(u"^Memory\susage.*\s+(\d+).*\s+(\d+).*\s+(\d+).*\sfree", re.IGNORECASE)
	proc_regexp = re.compile(u"^Processes\s+:\s+(\d+).*\s+(\d+)\srunning", re.IGNORECASE)
        proc_matchreg = [proc_regexp.search(line) for line in proc_line]
	cpu_matchreg = [cpu_regexp.match(line) for line in cpu_line]
	mem_matchreg = [mem_regexp.match(line) for line in mem_line]
	if (not proc_matchreg) or (not cpu_matchreg) or (not mem_matchreg):
            return False
        switch.cpu = user, kernel, idle = cpu_matchreg[0].group(1), cpu_matchreg[0].group(2), cpu_matchreg[0].group(3)
	switch.mem = total, used, free = mem_matchreg[0].group(1), mem_matchreg[0].group(2), mem_matchreg[0].group(3)
	switch.proc = total, running = proc_matchreg[0].group(1), proc_matchreg[0].group(2)
        return True
    elif switch.type == "brocade":
        return False
    elif switch.type == "mcdata":
        return False
    else:
	return False

#####################
def ParseInterfaces(switch, input):
    """
    ParseInterfaces(switch, input) -> Boolean
    Parse to find an uptime (status, description)

    @param input: type of check
    @type input: bool

    @rtype: bool
    """
    lines = input.splitlines()
    if switch.type == "cisco":
	sfp_flag = False
	ip_flag = False
	fcip_flag = False
	int_flag = False
	switch.int_list = []
	switch.sfp_list = []
	switch.ip_list = []
	switch.fcip_list = []
	for line in lines:
	    if "SFP" in line:
                sfp_flag = True
	    if "MTU" in line:
                ip_flag = True
	    if "fcip" in line:
                fcip_flag = True
	    if "Interface" in line:
                int_flag = True
	    if line is "":
                sfp_flag = False
		ip_flag = False
		fcip_flag = False
		int_flag = False
	    if sfp_flag:
		if "Mode" in line:
		    continue
		if line.startswith('---'):
		    continue
		if line.startswith(u'Interface'):
		    continue
		words = line.split()
		#line = fc1/1      1      E      auto    up               swl    E       2    --
                int_sfp = name, admin_mode, status, oper_mode = words[0], words[2], words[4], words[6]
		switch.sfp_list.append(int_sfp)
		interface = name, status, mode = words[0], words[4], words[6]
		switch.int_list.append(interface)
		#print interface
	    if ip_flag:
		if "Channel" in line:
		    continue
		if line.startswith('---'):
		    continue
		if line.startswith(u'Interface'):
		    continue
		words = line.split()
		#line = GigabitEthernet1/1       down       --                 auto     1500  --
		#line = mgmt0                    up         160.92.239.104/24  100 Mbps 1500
                int_ip = name, status, address = words[0], words[1], words[2]
		switch.ip_list.append(int_ip)
		interface = name, status, mode = words[0], words[1], "N/A"
		switch.int_list.append(interface)
		#print interface
	    if fcip_flag:
		if "Mode" in line:
		    continue
		if line.startswith('---'):
		    continue
		if line.startswith(u'Interface'):
		    continue
		words = line.split()
                int_fcip = name, admin_mode, status, oper_mode, Eth = words[0], words[2], words[4], words[5], words[7]
		switch.fcip_list.append(int_fcip)
		interface = name, status, mode = words[0], words[4], words[5]
		switch.int_list.append(interface)
		#print interface

	    if int_flag:
		if u"Gbps" in line:
		    continue
		if u"Mode" in line:
		    continue
		if line.startswith('---'):
		    continue
		if line.startswith(u'Interface'):
		    continue
		words = line.split()
		if len(words) == 3:
		    interface = name, status, mode = words[0], words[1], "N/A"
		    switch.int_list.append(interface)

	if not switch.int_list:
	    return False
        return True
    elif switch.type == "brocade":
        return False
    elif switch.type == "mcdata":
        return False
    else:
	return False
#####################
def ParseInterfacesDescription(switch, input):
    """
    ParseInterfacesDescription(switch, input) -> Boolean
    Parse to find interfaces description port name, port description

    @param input: type of check
    @type input: bool

    @rtype: bool
    """
    lines = input.splitlines()
    if switch.type == "cisco":
	switch.int_descr_list = []
	for line in lines:
	    if line.startswith('---'):
		continue
	    if line.startswith(u'Interface'):
		continue
	    if line is "":
	        continue
	    regexp = re.compile(u"^([^\s]+)\s+(.*)", re.IGNORECASE)
	    matchreg = regexp.match(line)
	    if matchreg:
		interface = name, description = matchreg.group(1), matchreg.group(2)
		switch.int_descr_list.append(interface)

	if not switch.int_descr_list:
	    return False
        return True
    elif switch.type == "brocade":
        return False
    elif switch.type == "mcdata":
        return False
    else:
	return False


#################################

def output(code, msg=''):
    outfp = sys.stdout
    if msg:
        print >> outfp, msg
    sys.exit(code)
################################################################
## CheckUptime (paramiko)
################################################################
def CheckUptime(switch, warning_threshold, critical_threshold):
    """
    CheckUptime(switch, warning_threshold, critical_threshold)
    Check a switch's uptime for Nagios.

    @param check_type: type of check
    @type check_type: str

    """
    if switch.type == "cisco":
        switch.uptime_command = "show system uptime"
    elif switch.type == "brocade":
        #switch.uptime_command = "uptime"
        switch.uptime_command = "switchuptime"	
    elif switch.type == "mcdata":
        switch.uptime_command = "show fru"

    uptime = switch.GetCommand(switch.uptime_command)
    switch.client.close()
    if not ParseUptime(switch, uptime):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output : " + str(uptime))
    else:
        if switch.type == "cisco":
            if ( switch.sys_uptime <= int(critical_threshold) ) and ( switch.kernel_uptime <= int(critical_threshold) ) and ( switch.active_uptime <= int(critical_threshold) ):
	        output(STATE_CRITICAL, "CRITICAL : Device has rebooted ! System Uptime: " + str(switch.sys_uptime) +
		        " minutes. Kernel uptime: "+ str(switch.kernel_uptime) +
		        " minutes. Active supervisor uptime: "+ str(switch.active_uptime) +
		        " minutes.")
            elif ( switch.sys_uptime <= int(warning_threshold) ) and ( switch.kernel_uptime <= int(warning_threshold) ) and ( switch.active_uptime <= int(warning_threshold) ):
	        output(STATE_WARNING, "WARNING : Device has rebooted ! Uptime : " + str(switch.sys_uptime) +
		        " minutes. Kernel uptime: "+ str(switch.kernel_uptime) +
		        " minutes. Active supervisor uptime: "+ str(switch.active_uptime) +
		        " minutes.")
	    else:
                output(STATE_OK, "OK : Device uptime : " + str(switch.sys_uptime) +
		        " minutes. Kernel uptime: "+ str(switch.kernel_uptime) +
		        " minutes. Active supervisor uptime: "+ str(switch.active_uptime) +
		        " minutes.")
        elif switch.type == "brocade":
            if ( switch.uptime <= int(critical_threshold) ):
	        output(STATE_CRITICAL, "CRITICAL : Device has rebooted ! System Uptime: " + str(switch.uptime) +" minutes.")
	    elif ( switch.uptime <= int(warning_threshold) ):
                output(STATE_WARNING, "WARNING : Device has rebooted ! System Uptime: " + str(switch.uptime) +" minutes.")
	    else:
                output(STATE_OK, "OK : Device uptime : " + str(switch.uptime) +" minutes.")
        elif switch.type == "mcdata":
            if ( switch.uptime <= int(critical_threshold) ):
	        output(STATE_CRITICAL, "CRITICAL : Device has rebooted ! System Uptime: " + str(switch.uptime) +" minutes.")
	    elif ( switch.uptime <= int(warning_threshold) ):
                output(STATE_WARNING, "WARNING : Device has rebooted ! System Uptime: " + str(switch.uptime) +" minutes.")
	    else:
                output(STATE_OK, "OK : Device uptime : " + str(switch.uptime) +" minutes.")
################################################################
## CheckEnv (paramiko)
################################################################
def CheckEnv(switch, warning_threshold, critical_threshold):
    """
    CheckEnv(switch, warning_threshold, critical_threshold)
    Check a switch's environment for Nagios.

    @param check_type: type of check
    @type check_type: str

    """
    if switch.type == "cisco":
        switch.environment_command = "show environment"
    elif switch.type == "brocade":
        switch.environment_command = "switchStatusShow"
        switch.environment_command = "fanShow"
        switch.environment_command = "psShow"
        switch.environment_command = "tempShow"
    elif switch.type == "mcdata":
        switch.environment_command = "show all"
    env = switch.GetCommand(switch.environment_command)

    switch.client.close()
    if not ParseEnvironment(switch, env):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output : " + str(env))
    else:
	nb_failed = 0
	msg = []
	for (name, model, hw, status) in switch.fan_list:
	    if not str(status).startswith("ok") :
	        nb_failed += 1
		msg.append("Fan "+str(name) + " is in status: " + str(status) + " (model: "+str(model)+ ") ! ")
	    else:
		msg.append("Fan "+str(name) + " is: " + str(status) + ". ")
	for (name, model, hw, status) in switch.clock_list:
	    if str(status).lstrip().startswith("ok") or "not present" in status:
		msg.append("Clock "+str(name) + " is: " + str(status) + ". ")
	    else:
		nb_failed += 1
		msg.append("Clock "+str(name) + " is in status: " + str(status) + " ! ")
	for (module, name, MajorThresh, MinorThresh, CurTemp, status) in switch.temp_list:
	    if not str(status).startswith("ok") :
	        nb_failed += 1
		msg.append("Temp "+str(name) + ", Module "+ str(module) +" is in status: " + str(status) + " ! ")
	    else:
		msg.append("Temp "+str(name) + ", Module "+ str(module) +" is: " + str(status) + ". ")
	for (number, model, Watts, Amp, status) in switch.ps_list:
	    if not str(status).startswith("ok") :
	        nb_failed += 1
		msg.append("Power Supply " + str(number) + " is in status: " + str(status) + " ! ")
	    else:
		msg.append("Power Supply " + str(number) + " is: " + str(status) + ". ")
	for (number, model, status) in switch.module_list:
	    if not str(status).startswith("powered-up") :
	        nb_failed += 1
		msg.append("Module " + str(number) + " is in status: " + str(status) + " ! ")
	    else:
		msg.append("Module " + str(number) + " is: " + str(status) + ". ")
	msg = ''.join(msg)
	if ( nb_failed >= int(critical_threshold) ):
	    output(STATE_CRITICAL, "CRITICAL: " + str(msg))
        elif ( nb_failed >= int(warning_threshold) ):
	    output(STATE_WARNING, "WARNING: " + str(msg))
	else:
            output(STATE_OK, "OK: " + str(msg))

################################################################
## CheckResources (paramiko)
################################################################
def CheckResources(switch, warning_threshold, critical_threshold):
    """
    CheckResources(switch, warning_threshold, critical_threshold)
    Check a switch's resources cpu and mem for Nagios.

    @param check_type: type of check
    @type check_type: str

    """
    if switch.type == "cisco":
        switch.resources_command = "show system resources"
    elif switch.type == "brocade":
        switch.resources_command = "uptime"
        switch.resources_command = "memShow"
    elif switch.type == "mcdata":
        output(STATE_WARNING, "WARNING : Not Possible on mcdata's switch")
    resources = switch.GetCommand(switch.resources_command)
    switch.client.close()
    if not ParseResources(switch, resources):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output: " + str(resources))
    else:
	crit_flag = False
	warn_flag = False
	msg = []
	(total, used, free) = switch.mem
	mem_used_perc = int(100 * ( float(used) / float(total) ))
	(user, kernel, idle) = switch.cpu
	cpu_used_perc = int(user) + int(kernel)
        if ( int(mem_used_perc) >= int(critical_threshold) ):
	    crit_flag = True
	    msg.append("Memory usage is Critical ! ")
        elif ( int(mem_used_perc) >= int(warning_threshold) ):
	    warn_flag = True
	    msg.append("Memory usage is higher than warning threshold ! ")

        if ( int(cpu_used_perc) >= int(critical_threshold) ):
	    crit_flag = True
	    msg.append("CPU usage is Critical ! ")
        elif ( int(cpu_used_perc) >= int(warning_threshold) ):
	    warn_flag = True
	    msg.append("CPU usage is higher than warning threshold ! ")


        (total, running) = switch.proc
	msg.append("CPU usage: " + str(cpu_used_perc) + " %. Memory usage: "+ str(mem_used_perc) + " %. Total Processes: " + str(total) + ". " + str(running) + " running.")
	msg = ''.join(msg)
	if crit_flag:
	    output(STATE_CRITICAL, "CRITICAL: " + str(msg))
        elif warn_flag:
	    output(STATE_WARNING, "WARNING: " + str(msg))
	else:
            output(STATE_OK, "OK: " + str(msg))

################################################################
## CheckInterfaces (paramiko)
################################################################
def CheckInterfaces(switch, warning_threshold, critical_threshold):
    """
    CheckInterfaces(switch, warning_threshold, critical_threshold)
    Check a switch's interfaces for Nagios.

    @param check_type: type of check
    @type check_type: str

    """
    if switch.type == "cisco":
        switch.interfaces_command = "show interface brief"
	switch.interfaces_description_command = "show interface description"
    elif switch.type == "brocade":
        switch.interfaces_command = "diagShow"
        switch.interfaces_command2 = "switchShow"
	switch.interfaces_description_command = ""
    elif switch.type == "mcdata":
        switch.interfaces_command = "show port opticHealth"
        switch.interfaces_command2 = "show port status"	
	switch.interfaces_description_command = "show port config"

    interfaces = switch.GetCommand(switch.interfaces_command)
    interfaces_descr = switch.GetCommand(switch.interfaces_description_command)
    switch.client.close()
    if not ParseInterfaces(switch, interfaces):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output: " + str(interfaces))
    if not ParseInterfacesDescription(switch, interfaces_descr):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output: " + str(interfaces_descr))
    else:
	crit_flag = False
	warn_flag = False
	msg = []
	failed_list = []
	for (name, status, mode) in switch.int_list:
	    if not status.startswith('up') and not status.startswith('down') and not status.startswith('trunking'):
		descr_list = [description for (descr_name, description) in switch.int_descr_list if descr_name == name]
		if descr_list[0]:
		    description = descr_list[0]
		else:
	            description = "No description"
		failed_list.append((name, status, mode, description))
        #print failed_list
        if ( len(failed_list) >= int(critical_threshold) ):
	    crit_flag = True   
	    for (name, status, mode, description) in failed_list:
	        msg.append("Interface: " + str(name) + " (" + str(description) + ") "+" mode: " + str(mode) + " is in status: " + str(status) + " ! ")

        elif ( len(failed_list) >= int(warning_threshold) ):
	    warn_flag = True 
	    for (name, status, mode, description) in failed_list:
	        msg.append("Interface: " + str(name) + " (" + str(description) + ") "+" mode: " + str(mode) + " is in status: " + str(status) + " ! ")

        else:
	    for (name, status, mode, description) in failed_list:
	        msg.append("Failed interface: " + str(name) + " (" + str(description) + ") mode: " + str(mode) + " status: " + str(status) + ". \n")
	    msg.append("Interface summary: ")
	    for (name, status, mode) in switch.int_list:
	        msg.append("%s (%s), " % (name, mode))
        msg = ''.join(msg)
	if crit_flag:
	    output(STATE_CRITICAL, "CRITICAL: " + str(msg))
        elif warn_flag:
	    output(STATE_WARNING, "WARNING: " + str(msg))
	else:
            output(STATE_OK, "OK: " + str(msg))
################################################################
## CheckInterface (paramiko)
################################################################
def CheckInterface(switch, interface_arg):
    """
    CheckInterfaces(switch, warning_threshold, critical_threshold)
    Check a switch's interfaces for Nagios.

    @param check_type: type of check
    @type check_type: str

    """
    if switch.type == "cisco":
        switch.interfaces_command = "show interface brief"
	switch.interfaces_description_command = "show interface description"
    elif switch.type == "brocade":
        switch.interfaces_command = "show interface brief"
    elif switch.type == "mcdata":
        switch.interfaces_command = "show interface brief"

    interfaces = switch.GetCommand(switch.interfaces_command)
    interfaces_descr = switch.GetCommand(switch.interfaces_description_command)
    switch.client.close()
    if not ParseInterfaces(switch, interfaces):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output: " + str(interfaces))
    if not ParseInterfacesDescription(switch, interfaces_descr):
	output(STATE_UNKNOWN, "UNKNOWN : incorrect switch output: " + str(interfaces_descr))
    else:
	crit_flag = False
	warn_flag = False
	msg = []
	msg_ok = []
	msg_critical = []
	failed_list = []
        interface_arg_list = interface_arg.split(",")
	# verifying it the interface is in the list of the switch's interface
	for int_arg in interface_arg_list:
            name_list = [name for (name, status, mode) in switch.int_list if name == int_arg]
	    if not name_list:
		for (name, status, mode) in switch.int_list:
		    int_name = ''.join(" %s," % name)
		msg.append("unknown interface: " + str(int_arg) + ". Possible values are:"+str(int_name))
		msg = ''.join(msg)
		output(STATE_UNKNOWN, "UNKNOW :" + str(msg))
        #browse each interface and verifying if it is up.
	#it constructs a list with the failed interfaces
	for (name, status, mode) in switch.int_list:
	    if not status.startswith('up') and not status.startswith('trunking'):
		failed_list.append((name, status, mode))
	#if the interface in the argument list is in the failed list, it is critical.
	msg_ok.append("Interfaces OK: ")
	for int_arg in interface_arg_list:
	    failed_arg_list = [(name, status, mode) for (name, status, mode) in failed_list if name == int_arg]
	    if failed_arg_list:
	        crit_flag = True #critical flag set
		for (name, status, mode) in failed_arg_list:
		    descr_list = [description for (descr_name, description) in switch.int_descr_list if descr_name == name]
		    if descr_list[0]:
		        description = descr_list[0]
	            else:
			description = "No description"
		    msg_critical.append("Interface: " + str(name) + " (" + str(description) + ") "+" mode: " + str(mode) + " is in status: " + str(status) + " ! ")
            else:
		int_msg_list = [(name, mode) for (name, status, mode) in switch.int_list if name == int_arg]
                descr_list = [description for (descr_name, description) in switch.int_descr_list if descr_name == int_arg]
		(name, mode) = int_msg_list[0]
		if descr_list[0]:
		    description = descr_list[0]
	        else:
	            description = "No description"
		int_msg = ''.join("%s (%s - %s), " % (name, description, mode))
		msg_ok.append(int_msg)

	if msg_critical:
	    msg_critical.append("\n")
	msg = ''.join(msg_critical + msg_ok)
        msg = ''.join(msg)
	if crit_flag:
	    output(STATE_CRITICAL, "CRITICAL: " + str(msg))
        elif warn_flag:
	    output(STATE_WARNING, "WARNING: " + str(msg))
	else:
            output(STATE_OK, "OK: " + str(msg))


################################################################
## SANagios() Function
## 
################################################################

def SANagios():
	#Main function, deals with arguments and launch the program
	if not sys.argv[1:]:
	    sys.stdout.write("SANagios: version 0.1. You must specify more arguments. More help avalaible with -h or --help option")
            sys.exit(1)
	usage = "usage: %prog [options] arg"
	# Definitions of the options
	parser = OptionParser(usage)
	parser.add_option("-i", "--ip", help="IP of the switch", type="string", action="store", dest="ip")
	parser.add_option("-s", "--switch", help="Type of the switch. Possible values are : cisco or brocade or mcdata", type="string", action="store", dest="switch")
	parser.add_option("-u", "--user", help="User on the switch", type="string", action="store", dest="user")
	parser.add_option("-p", "--password", help="Password of the user on the switch", type="string", action="store", dest="password")
	parser.add_option("-c", "--client", help="Type of client. Possible values are : ssh or telnet (SSH by default)", type="string", action="store", dest="client", default="ssh")
	parser.add_option("--timeout", help="The timeout value for SSH or Telnet commands. 4.0 seconds by default", type="float", action="store", dest="timeout", default="5.0")
	parser.add_option("-d", "--debug", help="The debug level. Values are : yes or no (no by default).", type="string", action="store", dest="debug", default="no")
	parser.add_option("-k", "--host-key", help="the Switch's SSH private key used for SSH authentication.", type="string", action="store", dest="key")
	parser.add_option("--check", help="For Nagios check (cisco): uptime, env, interfaces, resources, interface", type="string", action="store", dest="check")
	parser.add_option("--warning", help="For Nagios check (cisco): warning threshold value", type="string", action="store", dest="warning")
	parser.add_option("--critical", help="For Nagios check (cisco): critical threshold value", type="string", action="store", dest="critical")
	parser.add_option("--interface", help="For Nagios check (cisco): interface list", type="string", action="store", dest="interface")
	parser.add_option("--file", help="For debug", type="string", action="store", dest="file")
	(options, args) = parser.parse_args()

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
	if not options.check:
	    print '*** You must provide a type of check with --check !'
	    sys.exit(1)
        #initialising switch object
        switch = Host(options.ip, options.switch, options.user, options.password, options.client, float(options.timeout), options.key)
	if options.check:

	    if options.check == "uptime":
	        if not options.critical:
	            print '*** You must provide a critical value with --critical !'
	            sys.exit(1)
	        if not options.warning:
	            print '*** You must provide a warning value with --warning !'
	            sys.exit(1)
	        switch.Connect()
		CheckUptime(switch, options.warning, options.critical)

	    elif options.check == "env":
	        if not options.critical:
	            print '*** You must provide a critical value with --critical !'
	            sys.exit(1)
	        if not options.warning:
	            print '*** You must provide a warning value with --warning !'
	            sys.exit(1)
	        switch.Connect()
	        CheckEnv(switch, options.warning, options.critical)

	    elif options.check == "resources":
	        if not options.critical:
	            print '*** You must provide a critical value with --critical !'
	            sys.exit(1)
	        if not options.warning:
	            print '*** You must provide a warning value with --warning !'
	            sys.exit(1)
	        switch.Connect()
		CheckResources(switch, options.warning, options.critical)

	    elif options.check == "interfaces":
	        if not options.critical:
	            print '*** You must provide a critical value with --critical !'
	            sys.exit(1)
	        if not options.warning:
	            print '*** You must provide a warning value with --warning !'
	            sys.exit(1)
	        switch.Connect()
	        CheckInterfaces(switch, options.warning, options.critical)

	    elif options.check == "interface":
	        if options.interface:
		    switch.Connect()
	            CheckInterface(switch, options.interface)
		else:
		    print "*** you must provide a list of interface with --interface like fc1/1,fc1/2"
		    sys.exit(1)
	    else:
		print "*** not a possible option ! Possible values: uptime, env, resources, interfaces, interface"
		sys.exit(1)

    	else:
		print '*** Invalid type of switch ! Possible values are : cisco or brocade or mcdata'
		sys.exit(1)

############################################
if __name__ == '__main__':
    SANagios()

