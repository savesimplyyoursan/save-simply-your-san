A simple tool which make the configuration's backup of your SAN switches simple and easy. It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. You don't need to install or configure a SSH or a FTP server on your computer.

It is a command-line program that connect with SSH to your switch. The support of telnet connections will come soon.

It use differents components : Paramiko, pyftpdlib.

The support of the TFTP protocol doesn't work for the moment because the library tftpy doesn't support downloads.

It is very simple to use it. options are :

-i : IP of the switch.

-s : Type of the switch. Possible values are : cisco or brocade or mcdata

-u : User on the switch.

-p : Password of the user on the switch.

-t : Type of transfert. Possible values are : scp (by default) or ftp

-c : Type of client. Possible values are : ssh or telnet (SSH by default).

-g : Generate a RSA key for the SSH server. Possible values are : yes or no (no by default). The key will be stored in the file new\_server\_rsa.key. If you want to use it, please rename the new file with the name : server\_rsa.key

-e : Execute a command. Save the output of the command fulfilled in a file.

-l : The IP interface on which the server will be attached

-n : The NAT IP address on which the server will be recheable

-o : The float timeout value in for SSH or Telnet commands. 5.0 seconds by default

Your configuration will be stored in a directory with the name of your switch.

Examples:
> For making a backup of a cisco switch by SCP with a SSH connection :
> > SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s cisco -t scp -c ssh

> or more simply (SCP and SSH connection are values by default) :
> > SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s cisco


> For making a backup of a brocade switch by FTP with a telnet connection :
> > SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s brocade -t ftp -c telnet


> For making a backup of a McData switch and redirect the result in a file (works on windows):
> > SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s mcdata >mcdata-backup.log 2>&1


> For making a backup of a configuration of a McData switch (grab the output of the command "show all" by telnet)
> > SaveSimplyyourSAN -i 192.168.0.1 -u admin -p password -s mcdata -c telnet -e "show all"

Just use it and enjoy it !

On cisco switches, if you want to erase the SSH keys on your switch, use this command :
"clear ssh hosts"
On brocade, you cannot do this on Fabric OS version < 6.1.