#!/usr/bin/env python
#
# nmapdb - Parse nmap's XML output files and insert them into an SQLite database
# Copyright (c) 2012 Patroklos Argyroudis <argp at domain census-labs.com>

import sys
import os
import getopt
import xml.dom.minidom
from pysqlite2 import dbapi2 as sqlite

VERSION = "1.2"
DEFAULT_DATABASE = "./nmapdb.db"

true = 1
false = 0
vflag = false

def myprint(msg):
    global vflag
    if vflag == true:
        print msg

    return

def usage(name):
    print "usage: %s [options] <nmap output XML file(s)>" % name
    print "options:"
    print "     (-h) --help         this message"
    print "     (-v) --verbose      verbose output"
    print "     (-c) --create       specify input SQL file to create SQLite DB"
    print "     (-d) --database     specify output SQLite DB file"
    print "     (-f) --frequency    list most frequent open ports from specified DB"
    print "     (-n) --nodb         do not perform any DB operations (i.e. dry run)"
    print "     (-V) --version      output version number and exit"

    return

def main(argv, environ):
    global vflag
    nodb_flag = false
    freq_flag = false
    db_path = DEFAULT_DATABASE
    sql_file = ""
    argc = len(argv)

    if argc == 1:
        usage(argv[0])
        sys.exit(0)
 
    try:
        alist, args = getopt.getopt(argv[1:], "hvd:c:f:nV",
                ["help", "verbose", "database=", "create=", "frequency=",
                 "nodb", "version"])
    except getopt.GetoptError, msg:
        print "%s: %s\n" % (argv[0], msg)
        usage(argv[0]);
        sys.exit(1)
 
    for(field, val) in alist:
        if field in ("-h", "--help"):
            usage(argv[0])
            sys.exit(0)
        if field in ("-v", "--verbose"):
            vflag = true
        if field in ("-d", "--database"):
            db_path = val
        if field in ("-c", "--create"):
            sql_file = val
        if field in ("-f", "--frequency"):
            freq_flag = true
            db_path = val
        if field in ("-n", "--nodb"):
            nodb_flag = true
        if field in ("-V", "--version"):
            print "nmapdb v%s by Patroklos Argyroudis <argp at domain census-labs.com>" % (VERSION)
            print "parse nmap's XML output files and insert them into an SQLite database"
            sys.exit(0)

    if freq_flag == false:
        if len(args[0]) == 0:
            usage(argv[0])
            sys.exit(1)

    if nodb_flag == false:
        if db_path == DEFAULT_DATABASE:
            print "%s: no output SQLite DB file specified, using \"%s\"\n" % (argv[0], db_path)

        conn = sqlite.connect(db_path)
        cursor = conn.cursor()

        myprint("%s: successfully connected to SQLite DB \"%s\"\n" % (argv[0], db_path))

        # helpful queries on the database
        if freq_flag == true:
            freq_sql = "select count(port) as frequency,port as fport from ports where ports.state='open' group by port having count(fport) > 1000"

            cursor.execute(freq_sql)
            print "Frequency|Port"

            for row in cursor:
                print(row)
            
            sys.exit(0)

    if nodb_flag == false:
        if sql_file != "":
            sql_string = open(sql_file, "r").read()
        
            try:
                cursor.executescript(sql_string)
            except sqlite.ProgrammingError, msg:
                print "%s: error: %s\n" % (argv[0], msg)
                sys.exit(1)

            myprint("%s: SQLite DB created using SQL file \"%s\"\n" % (argv[0], sql_file))
    
    for fname in args:
        try:
            doc = xml.dom.minidom.parse(fname)
        except IOError:
            print "%s: error: file \"%s\" doesn't exist\n" % (argv[0], fname)
            continue
        except xml.parsers.expat.ExpatError:
            print "%s: error: file \"%s\" doesn't seem to be XML\n" % (argv[0], fname)
            continue

        for host in doc.getElementsByTagName("host"):
            try:
                address = host.getElementsByTagName("address")[0]
                ip = address.getAttribute("addr")
                protocol = address.getAttribute("addrtype")
            except:
                # move to the next host since the IP is our primary key
                continue

            try:
                mac_address = host.getElementsByTagName("address")[1]
                mac = mac_address.getAttribute("addr")
                mac_vendor = mac_address.getAttribute("vendor")
            except:
                mac = ""
                mac_vendor = ""

            try:
                hname = host.getElementsByTagName("hostname")[0]
                hostname = hname.getAttribute("name")
            except:
                hostname = ""

            try:
                status = host.getElementsByTagName("status")[0]
                state = status.getAttribute("state")
            except:
                state = ""

            try:
                os_el = host.getElementsByTagName("os")[0]
                os_match = os_el.getElementsByTagName("osmatch")[0]
                os_name = os_match.getAttribute("name")
                os_accuracy = os_match.getAttribute("accuracy")
                os_class = os_el.getElementsByTagName("osclass")[0]
                os_family = os_class.getAttribute("osfamily")
                os_gen = os_class.getAttribute("osgen")
            except:
                os_name = ""
                os_accuracy = ""
                os_family = ""
                os_gen = ""

            try:
                timestamp = host.getAttribute("endtime")
            except:
                timestamp = ""

            try:
                hostscript = host.getElementsByTagName("hostscript")[0]
                script = hostscript.getElementsByTagName("script")[0]
                id = script.getAttribute("id")

                if id == "whois":
                    whois_str = script.getAttribute("output")
                else:
                    whois_str = ""

            except:
                whois_str = ""

            myprint("================================================================")

            myprint("[hosts] ip:\t\t%s" % (ip))
            myprint("[hosts] mac:\t\t%s" % (mac))
            myprint("[hosts] hostname:\t%s" % (hostname))
            myprint("[hosts] protocol:\t%s" % (protocol))
            myprint("[hosts] os_name:\t%s" % (os_name))
            myprint("[hosts] os_family:\t%s" % (os_family))
            myprint("[hosts] os_accuracy:\t%s" % (os_accuracy))
            myprint("[hosts] os_gen:\t\t%s" % (os_gen))
            myprint("[hosts] last_update:\t%s" % (timestamp))
            myprint("[hosts] state:\t\t%s" % (state))
            myprint("[hosts] mac_vendor:\t%s" % (mac_vendor))
            myprint("[hosts] whois:\n")
            myprint("%s\n" % (whois_str))

            if nodb_flag == false:
                try:
                    cursor.execute("INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (ip, mac, hostname, protocol, os_name, os_family, os_accuracy,
                            os_gen, timestamp, state, mac_vendor, whois_str))
                except sqlite.IntegrityError, msg:
                    print "%s: warning: %s: table hosts: ip: %s\n" % (argv[0], msg, ip)
                    continue
                except:
                    print "%s: unknown exception during insert into table hosts\n" % (argv[0])
                    continue

            try:
                ports = host.getElementsByTagName("ports")[0]
                ports = ports.getElementsByTagName("port")
            except:
                print "%s: host %s has no open ports\n" % (argv[0], ip)
                continue

            for port in ports:
                pn = port.getAttribute("portid")
                protocol = port.getAttribute("protocol")
                state_el = port.getElementsByTagName("state")[0]
                state = state_el.getAttribute("state")

                try:
                    service = port.getElementsByTagName("service")[0]
                    port_name = service.getAttribute("name")
                    product_descr = service.getAttribute("product")
                    product_ver = service.getAttribute("version")
                    product_extra = service.getAttribute("extrainfo")
                except:
                    service = ""
                    port_name = ""
                    product_descr = ""
                    product_ver = ""
                    product_extra = ""
                    
                service_str = "%s %s %s" % (product_descr, product_ver, product_extra)

                info_str = ""

                for i in (0, 1):
                    try:
                        script = port.getElementsByTagName("script")[i]
                        script_id = script.getAttribute("id")
                        script_output = script.getAttribute("output")
                    except:
                        script_id = ""
                        script_output = ""

                    if script_id != "" and script_output != "":
                        info_str += "%s: %s\n" % (script_id, script_output)

                myprint("\t------------------------------------------------")

                myprint("\t[ports] ip:\t\t%s" % (ip))
                myprint("\t[ports] port:\t\t%s" % (pn))
                myprint("\t[ports] protocol:\t%s" % (protocol))
                myprint("\t[ports] name:\t\t%s" % (port_name))
                myprint("\t[ports] state:\t\t%s" % (state))
                myprint("\t[ports] service:\t%s" % (service_str))
                
                if info_str != "":
                    myprint("\t[ports] info:\n")
                    myprint("%s\n" % (info_str))

                if nodb_flag == false:
                    try:
                        cursor.execute("INSERT INTO ports VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, pn, protocol, port_name, state, service_str, info_str))
                    except sqlite.IntegrityError, msg:
                        print "%s: warning: %s: table ports: ip: %s\n" % (argv[0], msg, ip)
                        continue
                    except:
                        print "%s: unknown exception during insert into table ports\n" % (argv[0])
                        continue

                myprint("\t------------------------------------------------")

            myprint("================================================================")

    if nodb_flag == false:
        conn.commit()

if __name__ == "__main__":
    main(sys.argv, os.environ)
    sys.exit(0)

# EOF
