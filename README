nmapdb parses nmap's XML output files and inserts them into an SQLite database.

I coded this a while back (mid 2009) and have been using it since.  Some
people I have shared nmapdb with have found it useful, so I am releasing it
publicly.

Example usage:

$ sudo nmap -A -oX scanme.xml scanme.nmap.org

Starting Nmap ...

$ ls scanme.xml
scanme.xml
$ ./nmapdb.py -h
usage: ./nmapdb.py [options] <nmap output XML file(s)>
options:
     (-h) --help         this message
     (-v) --verbose      verbose output
     (-c) --create       specify input SQL file to create SQLite DB
     (-d) --database     specify output SQLite DB file
     (-f) --frequency    list most frequent open ports from specified DB
     (-n) --nodb         do not perform any DB operations (i.e. dry run)
     (-V) --version      output version number and exit

Use -c to create a database from the schema on the first run:

$ ./nmapdb.py -c nmapdb.sql -d myscan.db scanme.xml
$ file myscan.db
myscan.db: SQLite 3.x database
$ sqlite3 myscan.db
SQLite version 3.7.7 ...
sqlite> select * from hosts;
74.207.244.221||scanme.nmap.org|ipv4|Linux 2.6.18|Linux|85|2.6.X|1316681984|up|
sqlite> select * from ports;
74.207.244.221|22|tcp|ssh|open|
74.207.244.221|80|tcp|http|open|

Subsequent scans can be entered into the same database:

$ ./nmapdb.py -d myscan.db bar.xml foo.xml host1.xml host2.xml \
    host3.xml host4.xml meh.xml (or simply *.xml)
$ sqlite3 myscan.db
SQLite version 3.7.7 ...
sqlite> select * from ports where ports.port='22';
aa.bb.244.221|22|tcp|ssh|open|
204.cc.ddd.250|22|tcp|ssh|open|
bbb.242.aa.180|22|tcp|ssh|open|
aa.bb.121.21|22|tcp|ssh|open|
sqlite> select * from ports where ports.port='23';
192.168.1.254|23|tcp|telnet|open|
sqlite> select * from hosts inner join ports on hosts.ip=ports.ip where hosts.ip='192.168.1.254' and ports.state='open';
192.168.1.254|00:00:C5:CF:86:30|modem|ipv4||||||up|Farallon Computing/netopia|192.168.1.254|23|tcp|telnet|open|
192.168.1.254|00:00:C5:CF:86:30|modem|ipv4||||||up|Farallon Computing/netopia|192.168.1.254|80|tcp|http|open|
sqlite> select * from hosts inner join ports on hosts.ip=ports.ip where hosts.os_name like '%bsd%' and ports.port=22;
aa.bb.91.25||foo.bar.org|ipv4|FreeBSD 7.0-STABLE|FreeBSD|95|7.X|1231841556|up||aa.bb.91.25|22|tcp|ssh|open|

Feel free to fork, submit patches, whatever.

Thanks to antonat and thomas for providing feedback.

argp, Mon Apr 30 14:49:21 EEST 2012

