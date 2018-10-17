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
        self.longlist   = args.longlist
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


    #--------------------------------------------------------------------------
    #
    # Prints xml output as a one item per line hierarchy. Similar to XML output,
    # but without all the XML markup.
    #
    def longlisting(self, element, level):

        # add two spaces for each level
        for i in range(level):
            print("  ", end='')

        # print the name of the element
        print(element.tag, end='')

        # print the text of the element; "None" if no text
        if element.text:
            print(": " + element.text.rstrip())
        else:
            print(": None")

        # recurse to the next level of elements
        for subelem in element:
            self.longlisting(subelem, (level+1))


    #--------------------------------------------------------------------------
    #
    # Runs the XML comand
    #
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




    #==========================================================================
    # DEFINE COMMAND FUNCTIONS
    #==========================================================================


    #--------------------------------------------------------------------------
    #
    # Returns controller status, type, firmware, failover configuration, and
    # port configuration information for all controllers in the library.
    #
    def controllerslist(self):

        listFormat = '{:20} {:8} {:13} {:22} {:20} {:20} {:8} {:14} {:6} {:16} {:19}'

        try:
            url  = self.baseurl + "/controllers.xml?action=list"
            tree = self.run_command(url)
            print("\nControllers List")
            print("----------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            print(listFormat. \
                format("ID", "Status", "Firmware",
                       "Type", "FailoverFrom",
                       "FailoverTo", "PortName", "UseSoftAddress",
                       "LoopID", "InitiatorEnabled", "FibreConnectionMode"))
            print(listFormat. \
                format("--------------------", "--------", "-------------",
                       "----------------------", "--------------------",
                       "--------------------", "--------", "--------------",
                       "------", "----------------", "-------------------"))
            for controllers in tree:
                myid = status = firmware = ctype = failoverFrom = ""
                failoverTo = portName = useSoftAddress = loopID = ""
                initiatorEnabled = fibreConnectionMode = ""
                for element in controllers:
                    if element.tag == "ID":
                        myid = element.text.rstrip()
                    elif element.tag == "status":
                        status = element.text.rstrip()
                    elif element.tag == "firmware":
                        firmware = element.text.rstrip()
                    elif element.tag == "type":
                        ctype = element.text.rstrip()
                    elif element.tag == "failoverFrom":
                        failoverFrom = element.text.rstrip()
                    elif element.tag == "failoverTo":
                        failoverTo = element.text.rstrip()
                    elif element.tag == "port":
                        for port in element:
                            if port.tag == "name":
                                portName = port.text.rstrip()
                            elif port.tag == "useSoftAddress":
                                useSoftAddress = port.text.rstrip()
                            elif port.tag == "loopId":
                                loopId = port.text.rstrip()
                            elif port.tag == "initiatorEnabled":
                                initiatorEnabled = port.text.rstrip()
                            elif port.tag == "fibreConnectionMode":
                                fibreConnectionMode = port.text.rstrip()
                print(listFormat. \
                    format(myid, status, firmware,
                           ctype, failoverFrom,
                           failoverTo, portName, useSoftAddress,
                           loopID, initiatorEnabled, fibreConnectionMode))

        except Exception as e:
            print("ControllersList Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns detailed information about each of the drives in the library.
    #
    def drivelist(self):

        driveFormat = '{:25} {:11} {:8} {:12} {:25} {:15} {:15} {:13} {:11} {:25} {:9} {:7} {:6} {:9} {:10} {:8} {:14} {:15}'

        try:
            url  = self.baseurl + "/driveList.xml?action=list"
            tree = self.run_command(url)
            print("\nDrive List")
            print("----------")
            if self.longlist:
                self.longlisting(tree, 0)
                #TODO: Need to add getDriveLoadCount to long format
                return
            print(driveFormat. \
                format("ID", "DriveStatus", "Parition",
                       "PartDriveNum", "DriveType",
                       "SerialNum", "MfrSerialNum", "DriveFirmware",
                       "DCMFirmware", "WWN", "FibreAddr",
                       "LoopNum", "Health", "LoadCount",
                       "SparedWith", "SpareFor", "SparePotential",
                       "FirmwareStaging"))
            print(driveFormat. \
                format("-------------------------", "-----------", "--------",
                       "------------", "-------------------------",
                       "---------------", "---------------", "-------------",
                       "-----------", "-------------------------", "---------",
                       "-------", "------", "---------",
                       "----------", "--------", "--------------",
                       "---------------"))
            for drive in tree:
                myid = ""
                status = ""
                partition = ""
                paritionDriveNum = ""
                driveType = ""
                serialNum = ""
                manuSerialNum = ""
                driveFW = ""
                dcmFW = ""
                wwn = ""
                fibreAddress = ""
                loopNum = ""
                health = ""
                sparedWith = spareFor = sparePotential = ""
                firmwareStaging = ""
                loadCount = ""
                for element in drive:
                    if element.tag == "ID":
                        myid = element.text.rstrip()
                        # TBD #####
                        # Getting "returned an invalid load count" when running
                        # the command while testing on NERF. So comment out for
                        # now. Todd sent email to Spectra. 10/16/18
                        #url2 = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + myid
                        ##print("url2: " + url2)
                        #driveLoadTree = self.run_command(url2)
                        #for item in driveLoadTree:
                        #    if item.tag == "loadCount":
                        #        loadCount = item.text.rstrip()
                    elif element.tag == "driveStatus":
                        status = element.text.rstrip()
                    elif element.tag == "partition":
                        partition = element.text.rstrip()
                    elif element.tag == "partitionDriveNumber":
                        paritionDriveNum = element.text.rstrip()
                    elif element.tag == "driveType":
                        driveType = element.text.rstrip()
                    elif element.tag == "serialNumber":
                        serialNum = element.text.rstrip()
                    elif element.tag == "manufacturerSerialNumber":
                        manuSerialNum = element.text.rstrip()
                    elif element.tag == "driveFirmware":
                        driveFW = element.text.rstrip()
                    elif element.tag == "dcmFirmware":
                        dcmFW = element.text.rstrip()
                    elif element.tag == "wwn":
                        wwn = element.text.rstrip()
                    elif element.tag == "fibreAddress":
                        fibreAddress = element.text.rstrip()
                    elif element.tag == "loopNumber":
                        loopNum = element.text.rstrip()
                    elif element.tag == "health":
                        health = element.text.rstrip()
                    #TODO: wasn't able to test sparedWith, spareFor, sparePotential
                    elif element.tag == "sparedWith":
                        sparedWith = element.text.rstrip()
                    elif element.tag == "spareFor":
                        spareFor = element.text.rstrip()
                    elif element.tag == "sparePotential":
                        sparePotential = element.text.rstrip()
                    #TODO: wasn't able to test firmwareStaging
                    elif element.tag == "firmwareStaging":
                        firmware = complete = percentStaged = committing = ""
                        for item in element:
                            if item.tag == "firmware":
                                firmware = item.text.rstrip()
                            elif item.tag == "complete":
                                complete = item.text.rstrip()
                            elif item.tag == "percentStaged":
                                percentStaged = item.text.rstrip()
                            elif item.tag == "committing":
                                committing = item.text.rstrip()
                        firmwareStaging = firmware + ":" \
                                            " complete=" + complete + \
                                            " %Staged=" + percentStaged + \
                                            " committing=" + committing

                print(driveFormat. \
                    format(myid, status, partition, paritionDriveNum, driveType,
                           serialNum, manuSerialNum, driveFW,
                           dcmFW, wwn, fibreAddress, loopNum, health, loadCount,
                           sparedWith, spareFor, sparePotential,
                           firmwareStaging) )

        except Exception as e:
            print("DriveList Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Retrieves the EtherLib status information gathered with the refresh
    # action.
    #
    def etherlibstatus(self):

        listFormat = '{:5} {:10} {:9}'

        try:
            url  = self.baseurl + "/etherLibStatus.xml?action=list"
            tree = self.run_command(url)
            print("\nEtherLib Status")
            print("---------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            print(listFormat. \
                format("ID", "Target", "Connected"))
            print(listFormat. \
                format("-----", "----------", "---------"))
            for component in tree:
                myid = target = connected = ""
                for element in component:
                    if element.tag == "ID":
                        myid = element.text.rstrip()
                    elif element.tag == "connection":
                        for connection in element:
                            if connection.tag == "target":
                                target = connection.text.rstrip()
                            elif connection.tag == "connected":
                                connected = connection.text.rstrip()
                print(listFormat. \
                    format(myid, target, connected))

        except Exception as e:
            print("EtherLibStatus Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns a report showing the current data for all of the Hardware Health
    # Monitoring (HHM) counters for the library.
    #
    def hhmdata(self):

        counterFormat = '{:19} {:15} {:6} {:6} {:25} {:8} {:9} {:9} {:10}'

        try:
            url  = self.baseurl + "/HHMData.xml?action=list"
            tree = self.run_command(url)
            print("\nHardware Health Monitoring (HHM) Counters")
            print("-----------------------------------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            print(counterFormat. \
                format("CounterName", "SubType", "Value",
                       "Unit", "Reminder", "Severity",
                       "DefThresh", "CurThresh", "PostedDate"))
            print(counterFormat. \
                format("-------------------", "---------------", "------",
                       "------", "-------------------------", "--------",
                       "---------", "---------", "----------"))
            for child in tree:
                if child.tag == "counter":
                    typeName = ""
                    subTypeName = subTypeValue = subTypeUnit = ""
                    reminderName = reminderSeverity = ""
                    reminderDefThresh = reminderCurThresh = ""
                    reminderPostedDate = ""
                    for element in child:
                        if element.tag == "typeName":
                            typeName = element.text.rstrip()
                        elif element.tag == "subType":
                            subTypeName = subTypeValue = subTypeUnit = ""
                            for subtype in element:
                                if subtype.tag == "typeName":
                                    subTypeName = subtype.text.rstrip()
                                elif subtype.tag == "value":
                                    subTypeValue = subtype.text.rstrip()
                                elif subtype.tag == "unit":
                                    subTypeUnit = subtype.text.rstrip()
                                elif subtype.tag == "reminder":
                                    reminderName = reminderSeverity = ""
                                    reminderDefThresh = reminderCurThresh = ""
                                    reminderPostedDate = ""
                                    for reminder in subtype:
                                        if reminder.tag == "typeName":
                                            reminderName = reminder.text.rstrip()
                                        elif reminder.tag == "severity":
                                            reminderSeverity = reminder.text.rstrip()
                                        elif reminder.tag == "defaultThreshold":
                                            reminderDefThresh = reminder.text.rstrip()
                                        elif reminder.tag == "currentThreshold":
                                            reminderCurThresh = reminder.text.rstrip()
                                        elif reminder.tag == "postedDate":
                                            reminderPostedDate = reminder.text.rstrip()
                            print(counterFormat. \
                                format(typeName, subTypeName, subTypeValue,
                                       subTypeUnit, reminderName,
                                       reminderSeverity, reminderDefThresh,
                                       reminderCurThresh, reminderPostedDate))

        except Exception as e:
            print("hhmdata Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Lists all storage slots, entry/exit slots, and drives in the specified
    # partition.
    # - For each slot and drive, the list indicates whether or not it is full.
    # - For each occupied slot or drive, the list also indicates the barcode
    #   information of the cartridge and whether or not the cartridge is queued
    #   for eject.
    #
    def inventorylist(self, partition):

        try:
            url       = self.baseurl + "/inventory.xml?action=list&partition=" + partition
            tree      = self.run_command(url)
            if self.longlist:
                self.longlisting(tree, 0)
                return
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


    #--------------------------------------------------------------------------
    #
    # Returns the library type, serial number, component status, and engineering
    # change level information for the library that received the command.
    #
    def librarystatus(self):

        try:
            url  = self.baseurl + "/libraryStatus.xml"
            tree = self.run_command(url)
            if self.longlist:
                self.longlisting(tree, 0)
                return
            for child in tree:
                if ( (child.tag == "robot") or
                     (child.tag == "excessiveMoveFailures") ):
                    print(child.tag + ":", end='')
                    for item in child:
                        print(" ", end='')
                        print(item.tag, item.text, sep='=', end='')
                    print() #newline
                elif (child.tag == "controllerEnvironmentInfo"):
                    for cei in child:
                        if ( (cei.tag == "controller") or
                             (cei.tag == "driveControlModule") or
                             (cei.tag == "serviceBayControlModule") ):
                            print(cei.tag + ":", end='')
                            for item in cei:
                                print(" ", end='')
                                print(item.tag, item.text, sep='=', end='')
                            print() #newline
                        elif ( (cei.tag == "powerSupplyFRU") or
                               (cei.tag == "powerControlModule") or
                               (cei.tag == "fanControlModule") or
                               (cei.tag == "frameManagementModule") ):
                            print(cei.tag + ":", end='')
                            for item in cei:
                                print(" ", end='')
                                if ( (item.tag == "fanInPowerSupplyFRU") or
                                     (item.tag == "powerSupplyInPowerSupplyFRU") or
                                     (item.tag == "powerSupplyInPCM") or
                                     (item.tag == "fanInFCM") or
                                     (item.tag == "lightBank") or
                                     (item.tag == "fanPair") or
                                     (item.tag == "fanInFMM") or
                                     (item.tag == "powerSupplyInFMM") ):
                                    print(item.tag + "=(", end='')
                                    count = 0
                                    for subitem in item:
                                        if (count > 0):
                                            print(" ", end='')
                                        print(subitem.tag, subitem.text, sep='=', end='')
                                        count = count + 1
                                    print(")", end='')
                                else:
                                    print(item.tag, item.text, sep='=', end='')
                            print() #newline
                elif (child.tag == "ECInfo"):
                    for component in child:
                        print(child.tag, component.tag, sep=': ', end='')
                        for item in component:
                            print(item.tag, item.text, sep='=', end='')
                            print(" ", end='')
                        print() #newline
                else:
                    print(child.tag, child.text, sep=': ')

        except Exception as e:
            print("LibraryStatus Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Connects to the library using the specified username and password. See
    # "Configuring Library Users" in your library User Guide for information
    # about configuring users and passwords, as well as information about what
    # sort of actions each user type can perform.
    #
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


    #--------------------------------------------------------------------------
    #
    # Closes the connection to the library.
    #
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


    #--------------------------------------------------------------------------
    #
    # Retrieves the name of the BlueScale package currently used by the library.
    # The data returned by the command also lists all of the BlueScale package
    # files currently stored on the memory card in the LCM.
    #
    def packagelist(self):

        try:
            url  = self.baseurl + "/package.xml?action=list"
            tree = self.run_command(url)
            print("\nBlueScale Package List")
            print("----------------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            for child in tree:
                if child.tag == "current":
                    for element in child:
                        if element.tag == "name":
                            print("Currently Running", element.text.rstrip(), sep=(': '))
                if child.tag == "list":
                    print("Currently Stored on Library:", end='')
                    for element in child:
                        if element.tag == "name":
                            print(" " + element.text.rstrip(), end='')
                    print() #newline

        except Exception as e:
            print("packagelist Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns a list of all the partitions configured in the library.
    #
    # **Note** This command is different from "partition.xml?action=list"
    #          which lists all existing partitions including details such as
    #          partition type, size, assigned drives, etc.
    #
    def partitionlist(self):

        try:
            url  = self.baseurl + "/partitionList.xml"
            tree = self.run_command(url)
            if self.longlist:
                self.longlisting(tree, 0)
                return
#TBD: the below is basically doing a long list...do we still need?
            for child in tree:
                print(child.tag + ": " + child.text)

        except Exception as e:
            print("PartitionList Error: " + str(e), file=sys.stderr)


#==============================================================================
def main():

    cmdparser     = argparse.ArgumentParser(description='Spectra Logic TFinity API Tool.')
    cmdsubparsers = cmdparser.add_subparsers(title="commands", dest="command")

    cmdparser.add_argument('--version', '-V', action='version', version='%(prog)s 1.0')

    cmdparser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                           help='Increase the verbosity for the output.')

    cmdparser.add_argument('--longlist', '-l', dest='longlist', action='store_true',
                           help='Format the output as a long listing; one     \
                           attribute per line. Easier for the human eye; but  \
                           difficult to parse.')

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


    controllerslist_parser = cmdsubparsers.add_parser('controllerslist',
        help='Returns controller status, type, firmware, and failover and port information.')

    drivelist_parser = cmdsubparsers.add_parser('drivelist',
        help='Returns detailed information about each of the drives in the library.')

    etherlibstatus_parser = cmdsubparsers.add_parser('etherlibstatus',
        help='Retrieve status of the library EtherLib connections.')

    hhmdata_parser = cmdsubparsers.add_parser('hhmdata',
        help='Returns a report showing the current data for all of the Hardware Health Monitoring (HHM) counters for the library.')

    inventorylist_parser = cmdsubparsers.add_parser('inventorylist',
        help='List inventory for the specified partition.')
    inventorylist_parser.add_argument('partition', action='store', help='Spectra Logic Partition')

    librarystatus_parser = cmdsubparsers.add_parser('librarystatus',
        help='Returns library type, serial number, component status and engineering change level information.')

    partitionlist_parser = cmdsubparsers.add_parser('partitionlist',
        help='List all Spectra Logic Library partitions.')

    packagelist_parser = cmdsubparsers.add_parser('packagelist',
        help='Retrieves the name of the BlueScale package currently used by the library along with the list of packages currently stored on the memory card in the LCM.')


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
    elif args.command == "controllerslist":
        slapi.controllerslist()
    elif args.command == "drivelist":
        slapi.drivelist()
    elif args.command == "etherlibstatus":
        slapi.etherlibstatus()
    elif args.command == "hhmdata":
        slapi.hhmdata()
    elif args.command == "inventorylist":
        slapi.inventorylist(args.partition)
    elif args.command == "librarystatus":
        slapi.librarystatus()
    elif args.command == "partitionlist":
        slapi.partitionlist()
    elif args.command == "packagelist":
        slapi.packagelist()
    else:
        cmdparser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
