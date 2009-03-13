SaveSimplyyourSAN -i 192.168.0.1 -s brocade -u admin -p password -t ftp >brocade-backup.log 2>&1

SaveSimplyyourSAN -i 192.168.0.1 -s cisco -u admin -p password >cisco-backup.log 2>&1

SaveSimplyyourSAN -i 192.168.0.1 -s mcdata -u admin -p password >mcdata-backup.log 2>&1

SaveSimplyyourSAN -i 192.168.0.1 -s mcdata -u admin -p password -c telnet -e "show all">>mcdata-backup.log 2>&1