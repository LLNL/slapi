#!/usr/bin/python3

import getopt
import sys
import os
import pathlib
import configparser
import urllib.request
import urllib.error
import http.cookiejar
import xml.etree.ElementTree as ElementTree

class SpectraLogicLoginError(Exception):

    LoginErrorRaised = False

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class SpectraLogicAPI:

    def __init__(self, server, user, passwd):
        self.server     = server
        self.baseurl    = "http://" + server + "/gf"
        self.user       = user
        self.passwd     = passwd
        self.loggedin   = False
        self.sessionid  = ""
        self.cookiefile = self.slapidirectory() + "/cookies.txt"
        self.cookiejar  = http.cookiejar.LWPCookieJar()
        self.load_cookie()

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

    def load_cookie(self):

        try:
            self.cookiejar.load(self.cookiefile, ignore_discard=True, ignore_expires=False)
            for cookie in self.cookiejar:
                if cookie.domain == self.server and cookie.name == "sessionID" and not cookie.is_expired():
                    self.sessionid = cookie.value
                    self.loggedin = True
                    return

        except (IOError):
            os.umask(0o077)
            self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)
            self.loggedin  = False
            self.sessionid = ""

    def run_command(self, url):

        try:
            print(url)
            opener    = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookiejar))
            opener.addheaders.append(("Cookie", "sessionID=" + self.sessionid))
            request   = urllib.request.Request(url)
            response  = opener.open(request)
            xmldoc    = response.read()
            tree      = ElementTree.fromstring(xmldoc)

            if tree.tag == "error":
                for child in tree:
                    if (child.tag.find("Error: No active session found.") < 0):
                        raise(SpectraLogicLoginError("Error: No active session found."))
                
                raise(Exception(xmldoc))
            
            tree = ElementTree.fromstring(xmldoc)
            return(tree)

        except SpectraLogicLoginError as e:

            try:
                print("Loginerror: Raised: " + str(SpectraLogicLoginError.LoginErrorRaised))
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
                print("Login Failed...\n")
                self.loggedin  = False
                self.sessionid = ""
                self.cookiejar.clear(self.server)
                os.umask(0o077)
                self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)

        except Exception as e:
            print("LOGIN: " + str(e))

    def logout(self):

        try:
            url  = self.baseurl + "/logout.xml"
            tree = self.run_command(url)

        except Exception as e:
            print(str(e))

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
            print("PARTLIST: " + str(e))

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
            print(str(e))
    

def usage():
    progname = os.path.basename(__file__)
    print("usage: " + progname)
    print("          --config <configfile>")
    print("          --server <tfin_ipaddr>")
    print("          --user   <username>")
    print("          --help")
    print("          --verbose")

def main():
    helpme     = False
    configfile = None
    server     = None
    user       = None
    passwd     = None
    verbose    = False

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hc:s:u:v",
                                   ["help",
                                    "config=",
                                    "server=",
                                    "user=",
                                    "verbose"])
    except getopt.GetoptError as e:
        print(str(e))
        sys.exit(1)

    for o, a in opts:
        if o in ("-h", "--help"):
            helpme = a
        elif o in ("-c", "--config"):
            configfile = a
        elif o in ("-u", "--user"):
            user = a
        elif o in ("-s", "--server"):
            server = a
        elif o in ("-v", "--verbose"):
            verbose = True

    if configfile is None:
        print("Please specify a config file", file=sys.stderr)
        usage()
        sys.exit(1)

    parser = configparser.ConfigParser()
    parser.read(configfile)
    try:
        config = parser[server]
    except Exception as e:
        config = parser["DEFAULT"]

    if user is None:
        user   = config["username"]
    if passwd is None:
        passwd = config["password"]

    if server is None:
        print("Please specify an IP address", file=sys.stderr)
        usage()
        sys.exit(1)
    if user is None:
        print("Please specify a user name", file=sys.stderr)
        usage()
        sys.exit(1)
    if passwd is None:
        print("Please specify a password", file=sys.stderr)
        usage()
        sys.exit(1)

    slapi = SpectraLogicAPI(server, user, passwd)
    #slapi.login()
    slapi.partitionlist()
    #slapi.inventorylist("NERF")
    #slapi.logout()

if __name__ == "__main__":
    main()
