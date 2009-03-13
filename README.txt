----------------------------------------------------------------
Save Simply your SAN (Feb 17th 2009)
----------------------------------------------------------------

CONTENTS
1. LEGAL
   1.1. Copyright
   1.2. License agreement and Disclaimer
2. SYSTEM REQUIREMENTS
3. HOW TO INSTALL & UNINSTALL
   3.1. Installing
   3.2. Help?
   3.3. Uninstalling
4. DESCRIPTION
5. AUTHOR
   5.1. Web site

----------------------------------------------------------------
1. LEGAL

   1.1. Copyright

        Copyright © 2008-2009 by Anthony FOIGNANT. All rights
        reserved.

        By using this software you accept all the terms and
        conditions of the license agreement and disclaimer
        below.

        All registered and unregistered trademarks mentioned in
        this document are the property of their respective
        holders.

   1.2. License agreement and Disclaimer

        This program is free software; you can redistribute it
        and/or modify it under the terms of the GNU General
        Public License as published by the Free Software
        Foundation; either version 2 of the License, or (at your
        option) any later version.

	    This program is distributed in the hope that it will be
	    useful, but WITHOUT ANY WARRANTY; without even the
	    implied warranty of MERCHANTABILITY or FITNESS FOR A
	    PARTICULAR PURPOSE.  See the GNU General Public License
	    for more details.

      1.2.1 GNU General Public License
	      The GNU General Public License (GNU GPL) is attached
            in the file LICENSE.txt

----------------------------------------------------------------
2. SYSTEM REQUIREMENTS

   This version of Save Simply your SAN runs on Windows 2000, XP
----------------------------------------------------------------
3. HOW TO INSTALL & UNINSTALL

   3.1. Installing
        If you have python and all required modules, run : "python setup.py install"
  	If you want to build an executable for windows with py2exe, just run : "python setup-py2exe.py py2exe"

        If you want to use the windows built package, unzip the package Save-Simply-your-San-win32-XX.zip in the directory of your choice.
	Run SaveSimplyyourSAN.exe

   3.2. Help?

      Run SaveSimplyyourSAN.exe -h
	For making a backup of the running-config of a cisco switch by SCP with a SSH connection :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s cisco -t scp -c ssh
	Or more simply (SCP and SSH connection are values by default) :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s cisco

	For making a backup of the configuration of brocade switch by FTP with a telnet connection :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s brocade -t ftp -c telnet

	For making a backup of the configuration of brocade switch by SCP and specify the local network address 192.168.1.50 to which the SSH Server will bind :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s brocade -l 192.168.1.50

	For making a backup of the configuration of brocade switch by FTP and specify the NAT address of the IP Address (192.168.1.52) of the local FTP server :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s brocade -t ftp -n 192.168.1.52

	For making a backup of a McData switch and redirect the result in a file and redirect errors (works on windows too):
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s mcdata >mcdata-backup.log 2>&1

	For making a backup of a configuration of a McData switch (grab the output of the command "show all" by telnet)
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s mcdata -c telnet -e "show all"

	For making a supportshow a brocade switch by SSH :
		SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s brocade -c ssh -e "supportshow"

	Now you can schedule your backup ! :-)

   3.3. Uninstalling

        Remove the directory in which the executable is installed.

----------------------------------------------------------------
4. DESCRIPTION

   Simply Save your SAN is a simple tool for doing back-up
   of your SAN switches : Cisco, Brocade or Mcdata


----------------------------------------------------------------
5. AUTHOR
   
   The maintainer of this project is Anthony FOIGNANT.
   For more information visit :
   http://code.google.com/p/save-simply-your-san/

   5.1. Web site

        You can download the latest version at the Google Code page.

        http://code.google.com/p/save-simply-your-san/downloads/list

----------------------------------------------------------------
