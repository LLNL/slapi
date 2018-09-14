#!/usr/bin/python3

import argparse
import sys
import os
import stat
import time
import pathlib
import configparser
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import xml.etree.ElementTree
import xml.dom.minidom

class SpectraLogicLoginError(Exception):

    LoginErrorRaised = False

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class SpectraLogicAPI:

    def __init__(self, args):
        self.server     = args.server
        self.user       = args.user
        self.passwd     = args.passwd
        self.verbose    = args.verbose
        self.insecure   = args.insecure
        self.loggedin   = False
        self.sessionid  = ""
        self.cookiefile = self.slapidirectory() + "/cookies.txt"
        self.cookiejar  = http.cookiejar.LWPCookieJar()
        self.load_cookie()
        self.baseurl    = "https://" + args.server + "/gf"
        if self.insecure:
            self.baseurl    = "http://" + args.server + "/gf"


    def slapidirectory(self):

        home = os.path.expanduser('~')
        if os.path.exists(home) == False:
            raise(Exception(home + " does not exist."))
        if os.path.isdir(home) == False:
            raise(Exception(home + " is not a directory."))

        slapidir = home + "/.slapi"
        if os.path.exists(slapidir):
            if os.path.isdir(slapidir):
                return(slapidir)
            else:
                raise(Exception(slapidir + " is not a directory."))
        else:
            # Directory does not exist
            # Let's try to create it
            try:
                os.mkdir(slapidir, 0o700)
                return(slapidir)
            except OSError as e:
                raise(e)

    def cookie_is_old(self):

        try:
            now   = time.time()
            mtime = os.stat(self.cookiefile)[stat.ST_MTIME]
            age   = now - mtime
            if age < 3600:
                return(False)
            else:
                return(True)

        except Exception as e:
            return(True)

    def load_cookie(self):

        try:
            self.cookiejar.load(self.cookiefile, ignore_discard=True, ignore_expires=False)
            for cookie in self.cookiejar:
                if cookie.domain == self.server and cookie.name == "sessionID":
                    if cookie.is_expired() or self.cookie_is_old():
                        self.cookiejar.clear(self.server)
                        os.umask(0o077)
                        self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)
                        self.loggedin  = False
                        self.sessionid = ""
                    else:
                        self.sessionid = cookie.value
                        self.loggedin = True
                        return

        except Exception as e:
            os.umask(0o077)
            self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)
            self.loggedin  = False
            self.sessionid = ""

    def run_command(self, url):

        try:

            if self.verbose:
                print("--------------------------------------------------", file=sys.stderr)
                print("Command: " + url, file=sys.stderr)
                print("--------------------------------------------------", file=sys.stderr)
                print("", file=sys.stderr)

            # FIXME someday...
            # The libraries currently use self-signed certs
            # Do not verify the certificate for now...
            ssl._create_default_https_context = ssl._create_unverified_context
            opener    = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookiejar))
            opener.addheaders.append(("Cookie", "sessionID=" + self.sessionid))
            request   = urllib.request.Request(url)
            response  = opener.open(request)
            xmldoc    = response.read()
            tree      = xml.etree.ElementTree.fromstring(xmldoc)

            if self.verbose:
                print("--------------------------------------------------", file=sys.stderr)
                print("XML Document:", file=sys.stderr)
                xmlstr = xml.dom.minidom.parseString(xmldoc).toprettyxml(indent="   ")
                xmllines = xmlstr.splitlines()
                for line in xmllines:
                    line = line.rstrip()
                    if line != "":
                        print(line, file=sys.stderr)
                print("--------------------------------------------------", file=sys.stderr)
                print("", file=sys.stderr)

            if tree.tag == "error":
                for child in tree:
                    if (child.text.find("Error: No active session found.") >= 0):
                        raise(SpectraLogicLoginError("Error: No active session found."))
                
                errstr = ""
                for child in tree:
                    errstr = errstr + child.tag + ": " + child.text + "\n"
                raise(Exception(errstr))
            
            tree = xml.etree.ElementTree.fromstring(xmldoc)
            return(tree)

        except SpectraLogicLoginError as e:

            try:

                if (self.verbose):
                    print("Loginerror: Raised: " + str(SpectraLogicLoginError.LoginErrorRaised), file=sys.stderr)

                if SpectraLogicLoginError.LoginErrorRaised == False:
                    SpectraLogicLoginError.LoginErrorRaised = True
                    self.login()
                    return(self.run_command(url))
                else:
                    raise(e)

            except Exception as e:
                raise(e)
            
        except Exception as e:
            raise(e)
            
            

    def login(self):

        try:
            url  = self.baseurl + "/login.xml?username=" + self.user + "&password=" + self.passwd
            tree = self.run_command(url)
            for child in tree:
                if child.tag == "status" and child.text == "OK":
                    os.umask(0o077)
                    self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)
                    self.load_cookie()

            if self.loggedin == False:
                print("Login Failed...\n", file=sys.stderr)
                self.loggedin  = False
                self.sessionid = ""
                self.cookiejar.clear(self.server)
                os.umask(0o077)
                self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)

        except Exception as e:
            print("Login Error: " + str(e), file=sys.stderr)

    def logout(self):

        try:
            url  = self.baseurl + "/logout.xml"
            tree = self.run_command(url)

        except Exception as e:
            print("Logout Error: " + str(e), file=sys.stderr)

        self.loggedin  = False
        self.sessionid = ""
        self.cookiejar.clear(self.server)
        os.umask(0o077)
        self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)

    def partitionlist(self):

        try:
            url  = self.baseurl + "/partitionList.xml"
            tree = self.run_command(url)
            for child in tree:
                print(child.tag + ": " + child.text)

        except Exception as e:
            print("PartitionList Error: " + str(e), file=sys.stderr)

    def etherlibstatus(self):

        try:
            url  = self.baseurl + "/etherLibStatus.xml?action=list"
            tree = self.run_command(url)
            for child in tree:
                print (child.tag + ":" + child.text.rstrip())
                for grandchild in child:
                    print("  " + grandchild.tag + ":" + grandchild.text.rstrip())
                    for ggrandchild in grandchild:
                        print("    " + ggrandchild.tag + ": " + ggrandchild.text.rstrip())
            #iter_ = tree.getiterator()
            #for elem in iter_:
            #    #print (elem.tag)
            #    for child in elem:
            #       print ("  " + child.tag + ":" + child.text.rstrip()) 
                    
            #appointments = tree.getchildren()
            #for appointment in appointments:
            #    appt_children = appointment.getchildren()
            #    for appt_child in appt_children:
            #        print (appt_child.tag + ":" + appt_child.text)

            #for elem in tree.iter():
            #    print (elem.tag, elem.attrib, elem.text)
            #for target in tree.iter('target'):
            #    print ("hello" + target.text)
            #print(tree.tag)

        except Exception as e:
            print("EtherLibStatus Error: " + str(e), file=sys.stderr)

    def inventorylist(self, partition):

        try:
            url       = self.baseurl + "/inventory.xml?action=list&partition=" + partition
            tree      = self.run_command(url)
            for part in tree:
                print('{:6} {:6} {:10} {:6} {:6}'.format("ID", "Offset", "Barcode", "Queued", "Full"))
                print('{:6} {:6} {:10} {:6} {:6}'.format("--", "------", "-------", "------", "----"))
                for elt in part:
                    if elt.tag != "name":
                        myid = ""
                        offset = ""
                        barcode = ""
                        isqueued = ""
                        full = ""
                        for slot in elt:
                            if slot.tag == "id":
                                myid = slot.text
                            elif slot.tag == "offset":
                                offset = slot.text
                            elif slot.tag == "barcode":
                                barcode = slot.text.strip()
                            elif slot.tag == "isQueued":
                                isqueued = slot.text
                            elif slot.tag == "full":
                                full = slot.text
                        print('{:6} {:6} {:10} {:6} {:6}'.format(myid, offset, barcode, isqueued, full))

        except Exception as e:
            print("InventoryList Error: " + str(e), file=sys.stderr)
    
    

def main():

    cmdparser     = argparse.ArgumentParser(description='Spectra Logic TFinity API Tool.')
    cmdsubparsers = cmdparser.add_subparsers(title="commands", dest="command")

    cmdparser.add_argument('--version', '-V', action='version', version='%(prog)s 1.0')

    cmdparser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                           help='Increase the verbosity for the output.')

    cmdparser.add_argument('--insecure', '-i', dest='insecure', action='store_true',
                           help='Talk to library over http:// instead of https://')

    cmdparser.add_argument('--config', '-c', dest='configfile', nargs='?',
                           required=True,
                           type=argparse.FileType('r'), default='/etc/slapi.cfg',
                           help='Configuration file for Spectra Logic API..')

    cmdparser.add_argument('--server', '-s', dest='server',
                           required=True,
                           help='IP Address/Hostname of Spectra Logic Library.')

    cmdparser.add_argument('--user', '-u', dest='user',
                           help='User name for Spectra Logic Library Login.')

    cmdparser.add_argument('--passwd', '-p', dest='passwd',
                           help='Password for Spectra Logic Library Login. ' +
                                'Do not use this option if you care about security. ' +
                                'Specify the password in the config file instead.')


    partitionlist_parser = cmdsubparsers.add_parser('partitionlist',
                                                    help='List all Spectra Logic Library partitions.')
    
    etherlibstatus_parser = cmdsubparsers.add_parser('etherlibstatus',
                                                    help='Retrieve status of the library EtherLib connections.')

    inventorylist_parser = cmdsubparsers.add_parser('inventorylist',
                                                    help='List inventory for the specified partition.')
    inventorylist_parser.add_argument('partition', action='store', help='Spectra Logic Partition')

    args = cmdparser.parse_args()

    cfgparser = configparser.ConfigParser()
    cfgparser.read(args.configfile.name)
    try:
        config = cfgparser[args.server]
    except Exception as e:
        config = cfgparser["DEFAULT"]

    try:
        if args.user is None:
           args.user   = config["username"]
        if args.passwd is None:
            args.passwd = config["password"]
    except Exception as e:
        cmdparser.print_help()
        sys.exit(1)

    slapi = SpectraLogicAPI(args)
    if args.command is None:
        cmdparser.print_help()
        sys.exit(1)
    elif args.command == "partitionlist":
        slapi.partitionlist()
    elif args.command == "etherlibstatus":
        slapi.etherlibstatus()
    elif args.command == "inventorylist":
        slapi.inventorylist(args.partition)
    else:
        cmdparser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
