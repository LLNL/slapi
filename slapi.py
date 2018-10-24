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
import traceback

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

        listFormat = '{:20} {:8} {:13} {:22} {:20} {:20} {:8} {:14} {:6} {:19}'

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
                       "LoopID", "FibreConnectionMode"))
            print(listFormat. \
                format("--------------------", "--------", "-------------",
                       "----------------------", "--------------------",
                       "--------------------", "--------", "--------------",
                       "------", "-------------------"))
            for controllers in tree:
                myid = status = firmware = ctype = failoverFrom = ""
                failoverTo = portName = useSoftAddress = loopID = ""
                fibreConnectionMode = ""
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
                            #initiatorEnabled is no longer supported
                            elif port.tag == "fibreConnectionMode":
                                fibreConnectionMode = port.text.rstrip()
                print(listFormat. \
                    format(myid, status, firmware,
                           ctype, failoverFrom,
                           failoverTo, portName, useSoftAddress,
                           loopID, fibreConnectionMode))

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
                print("\ngetDriveLoadCount:");
                for drive in tree:
                    for element in drive:
                        if element.tag == "ID":
                            myid = element.text.rstrip()
                            print("  drive:")
                            print("    ID: " + myid);
                            loadCount = self.GetDriveLoadCount(myid)
                            print("    loadCount: " + loadCount);
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
                myid = status = partition = paritionDriveNum = ""
                driveType = serialNum = manuSerialNum = driveFW = ""
                dcmFW = wwn = fibreAddress = loopNum = health = ""
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
                        # 10/17/18: Spectra believes that the problem is because
                        # the drive has never been loaded since the firmware
                        # update. So told me to load/unload. I tried that, but
                        # am now having HW problems.
                        loadCount = self.GetDriveLoadCount(myid)

                        #try:
                        #    url2 = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + "FR2/DBA1/fLTO-DRV1"
                        #    print("url2: " + url2)
                        #    driveLoadTree = self.run_command(url2)
                        #except Exception as e:
                        #    print("DriveList LTO-DRV1 Error: " + str(e), file=sys.stderr)

                        #try:
                        #    url2 = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + "FR2/DBA1/fLTO-DRV2"
                        #    print("url2: " + url2)
                        #    driveLoadTree = self.run_command(url2)
                        #except Exception as e:
                        #    print("DriveList LTO-DRV2 Error: " + str(e), file=sys.stderr)

                        #try:
                        #    url2 = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + "FR2/DBA6/fTS11x0-DRV3"
                        #    print("url2: " + url2)
                        #    driveLoadTree = self.run_command(url2)
                        #except Exception as e:
                        #    print("DriveList TS11x0-DRV3 Error: " + str(e), file=sys.stderr)

                        #try:
                        #    url2 = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + "FR2/DBA6/fTS11x0-DRV4"
                        #    print("url2: " + url2)
                        #    driveLoadTree = self.run_command(url2)
                        #except Exception as e:
                        #    print("DriveList TS11x0-DRV4 Error: " + str(e), file=sys.stderr)
                        #return

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
    # Using an inputed driveID (format from drivelist ID), this routine will
    # get the drive load count for the driveID. Upon success, it returns the
    # load count, otherwise, it returns the string "INVALID".
    #
    def GetDriveLoadCount(self, driveID):

        try:
            url = self.baseurl + "/driveList.xml?action=getDriveLoadCount&driveName=" + driveID
            driveLoadTree = self.run_command(url)
        except Exception as e:
            loadCount = "INVALID"
        else:
            for count in driveLoadTree:
                if count.tag == "loadCount":
                    loadCount = count.text.rstrip()
        return(loadCount)

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

        listFormat = '{:6} {:6} {:10} {:6} {:4}'

        try:
            url       = self.baseurl + "/inventory.xml?action=list&partition=" + partition
            tree      = self.run_command(url)
            if self.longlist:
                self.longlisting(tree, 0)
                return
            print("\nInventory List")
            print("--------------")
            for part in tree:
                print(listFormat.
                    format("ID", "Offset", "Barcode", "Queued", "Full"))
                print(listFormat.
                    format("------", "------", "----------", "------", "----"))
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
                        print(listFormat.format(myid, offset, barcode, isqueued, full))

        except Exception as e:
            print("InventoryList Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns the library type, serial number, component status, and engineering
    # change level information for the library that received the command. With
    # headers.
    #
    def librarystatus(self):

        topFormat = '{:11} {:11} {:9}'
        robotFormat = '{:6} {:9} {:15} {:12} {:19} {:28} {:23} {:32} {:11} {:13} {:14} {:17}'
        moveFormat  = '{:12} {:12} {:12} {:12} {:20} {:19}'
        controllerFormat = '{:25} {:13} {:11} {:11} {:14}'
        driveCMFormat = '{:25} {:13} {:12} {:16} {:15}'
        powerSupplyFRUFormat = '{:25} {:12} {:13} {:11} {:9} {:8} {:11} {:9} {:8} {:20} {:13} {:13} {:20} {:9} {:9} {:9}'
        powerCMFormat = '{:25} {:13} {:17} {:16} {:18} {:22} {:16} {:18} {:13} {:12} {:20} {:19} {:19}'
        fanCMFormat = '{:25} {:8} {:13} {:15} {:14} {:17} {:24} {:12} {:15} {:15} {:15} {:11} {:11} {:16} {:12} {:12}'
        frameMMFormat = '{:25} {:13} {:12} {:13} {:19} {:19} {:20} {:16} {:12} {:13} {:16} {:25} {:20} {:24} {:12} {:14} {:16} {:15} {:19} {:11} {:13} {:17} {:17} {:21} {:21}'
        fanPairFormat = '{:25} {:8} {:16}'
        fanInFMMFormat = '{:25} {:6} {:13}'
        serviceFormat = '{:25} {:11} {:15} {:14} {:15} {:15} {:9} {:19} {:13} {:14} {:10} {:19} {:15}'
        powerInFMMFormat = '{:25} {:19} {:19}'
        componentFormat = '{:25} {:2} {:15} {:18} {:25} {:10}'

        try:
            url  = self.baseurl + "/libraryStatus.xml"
            tree = self.run_command(url)
            print("\nLibrary Status")
            print("--------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return

            # top level stuff
            libraryType = tree.find("libraryType")
            railPowerOn = tree.find("railPowerOn")
            serialNumber = tree.find("serialNumber")
            print()
            print(topFormat. \
                format("LibraryType", "RailPowerOn", "SerialNum"))
            print(topFormat. \
                format("-----------", "-----------", "---------"))
            print(topFormat. \
                format(libraryType.text.strip(),
                       railPowerOn.text.strip(),
                       serialNumber.text.strip()))

            # initialize some header print variables
            robotHeaderPrinted = False
            controllerHeaderPrinted = False
            driveCMHeaderPrinted = False
            psFRUHeaderPrinted = False
            powerCMHeaderPrinted = False
            fanCMHeaderPrinted = False
            frameMMHeaderPrinted = False
            componentHeaderPrinted = False
            fanPairStringList = []
            fanInFMMStringList = []
            powerInFMMStringList = []
            serviceStringList = []

            for child in tree:

                # robot list
                if child.tag == "robot":
                    if robotHeaderPrinted == False:
                        print() #newline
                        print(robotFormat. \
                            format("Robot", "State", "TransporterType",
                                   "ServiceFrame", "TapeInPickerCurrent",
                                   "TeraPackInTransporterCurrent",
                                   "TapeInPickerUponService",
                                   "TeraPackInTransporterUponService",
                                   "TopHAXGear", "BottomHAXGear",
                                   "TopHAXSolenoid", "BottomHAXSolenoid"))
                        print(robotFormat. \
                            format("------", "---------", "---------------",
                                   "------------", "-------------------",
                                   "----------------------------",
                                   "-----------------------",
                                   "--------------------------------",
                                   "-----------", "-------------",
                                   "--------------", "-----------------"))
                        robotHeaderPrinted = True;
                    number = state = transporterType = serviceFrame = ""
                    tapeInPickerCurrent = TeraPackInTransporterCurrent = ""
                    tapeInPickerUponService = ""
                    TeraPackInTransporterUponService = topHAXGear = ""
                    bottomHAXGear = topHAXSolenoid = bottomHAXSolenoid = ""
                    for robot in child:
                        if robot.tag == "number":
                            number = robot.text.strip()
                        elif robot.tag == "state":
                            state = robot.text.strip()
                        elif robot.tag == "transporterType":
                            transporterType = robot.text.strip()
                        elif robot.tag == "serviceFrame":
                            serviceFrame = robot.text.strip()
                        elif robot.tag == "tapeInPickerCurrent":
                            tapeInPickerCurrent = robot.text.strip()
                        elif robot.tag == "TeraPackInTransporterCurrent":
                            TeraPackInTransporterCurrent = robot.text.strip()
                        elif robot.tag == "tapeInPickerUponService":
                            tapeInPickerUponService = robot.text.strip()
                        elif robot.tag == "TeraPackInTransporterUponService":
                            TeraPackInTransporterUponService = robot.text.strip()
                        elif robot.tag == "topHAXGear":
                            topHAXGear = robot.text.strip()
                        elif robot.tag == "bottomHAXGear":
                            bottomHAXGear = robot.text.strip()
                        elif robot.tag == "topHAXSolenoid":
                            topHAXSolenoid = robot.text.strip()
                        elif robot.tag == "bottomHAXSolenoid":
                            bottomHAXSolenoid = robot.text.strip()
                    print(robotFormat. \
                        format(number, state, transporterType,
                               serviceFrame, tapeInPickerCurrent,
                               TeraPackInTransporterCurrent,
                               tapeInPickerUponService,
                               TeraPackInTransporterUponService,
                               topHAXGear, bottomHAXGear,
                               topHAXSolenoid, bottomHAXSolenoid))

                # excessiveMoveFailures list
                if child.tag == "excessiveMoveFailures":
                    print("\nExcessive Move Failures:")
                    print(moveFormat. \
                        format("Partition", "Source", "Destination",
                               "NumFailures", "LastSenseInfo",
                               "LastFailedMoveTime"))
                    print(moveFormat. \
                        format("------------", "------------", "------------",
                               "------------", "--------------------",
                               "-------------------"))
                    partition = source = destination = numberOfFailures = ""
                    lastSenseInfo = lastFailedMoveTime = ""

                    for move in child:
                        if move.tag == "partition":
                            partition = move.text.strip()
                        elif move.tag == "source":
                            source = move.text.strip()
                        elif move.tag == "destination":
                            destination = move.text.strip()
                        elif move.tag == "numberOfFailures":
                            numberOfFailures = move.text.strip()
                        elif move.tag == "lastSenseInfo":
                            lastSenseInfo = move.text.strip()
                        elif move.tag == "lastFailedMoveTime":
                            lastFailedMoveTime = move.text.strip()
                    print(moveFormat. \
                        format(partition, source, destination,
                               numberOfFailures, lastSenseInfo,
                               lastFailedMoveTime))

                # controllerEnvironmentInfo list
                if child.tag == "controllerEnvironmentInfo":
                    for ceinfo in child:

                        # controllers
                        if ceinfo.tag == "controller":
                            if controllerHeaderPrinted == False:
                                #print("\nController Environmental Info")
                                #print(  "-----------------------------")
                                print()
                                print(controllerFormat. \
                                    format("ControllerID", "TempInCelsius",
                                           "PortALinkUp", "PortBLinkUp",
                                           "FailoverStatus"))
                                print(controllerFormat. \
                                    format("-------------------------",
                                           "-------------", "-----------",
                                           "-----------", "--------------"))
                                controllerHeaderPrinted = True
                            ID = temperatureInCelsius = portALinkUp = ""
                            portBLinkUp = failoverStatus = ""
                            for controller in ceinfo:
                                if controller.tag == "ID":
                                    ID = controller.text.strip()
                                elif controller.tag == "temperatureInCelsius":
                                    temperatureInCelsius = controller.text.strip()
                                elif controller.tag == "portALinkUp":
                                    portALinkUp = controller.text.strip()
                                elif controller.tag == "portBLinkUp":
                                    portBLinkUp = controller.text.strip()
                                elif controller.tag == "failoverStatus":
                                    failoverStatus = controller.text.strip()
                            print(controllerFormat. \
                                format(ID, temperatureInCelsius, portALinkUp,
                                       portBLinkUp, failoverStatus))

                        # drive control modules
                        if ceinfo.tag == "driveControlModule":
                            if driveCMHeaderPrinted == False:
                                #print("\nDrive Control Module Environmental Info")
                                #print(  "---------------------------------------")
                                print()
                                print(driveCMFormat. \
                                    format("DriveControlModuleID", "12VoltVoltage",
                                           "5VoltVoltage", "FanCurrentInAmps",
                                           "TempInCelsius"))
                                print(driveCMFormat. \
                                    format("-------------------------",
                                           "-------------", "------------",
                                           "----------------", "---------------"))
                                driveCMHeaderPrinted = True
                            ID = twelveVoltVoltage = fiveVoltVoltage = ""
                            fanCurrentInAmps = temperatureInCelsius = ""
                            for driveCM in ceinfo:
                                if driveCM.tag == "ID":
                                    ID = driveCM.text.strip()
                                elif driveCM.tag == "twelveVoltVoltage":
                                    twelveVoltVoltage = driveCM.text.strip()
                                elif driveCM.tag == "fiveVoltVoltage":
                                    fiveVoltVoltage = driveCM.text.strip()
                                elif driveCM.tag == "fanCurrentInAmps":
                                    fanCurrentInAmps = driveCM.text.strip()
                                elif driveCM.tag == "temperatureInCelsius":
                                    temperatureInCelsius = driveCM.text.strip()
                            print(driveCMFormat. \
                                format(ID, twelveVoltVoltage, fiveVoltVoltage,
                                       fanCurrentInAmps, temperatureInCelsius))

                        # power supply FRUs
                        if ceinfo.tag == "powerSupplyFRU":
                            if psFRUHeaderPrinted == False:
                                print()
                                print(powerSupplyFRUFormat. \
                                    format("PowerSupplyFRUID", "InputPowerOK",
                                           "OutputPowerOK", "TempWarning",
                                           "TempAlarm", "ModelNum",
                                           "ManuPartNum", "SerialNum",
                                           "ModLevel", "Manufacturer",
                                           "CountryOfManu", "TempInCelsius",
                                           "CommunicatingWithPCM",
                                           "Fan1_Okay", "Fan2_Okay", "Fan3_Okay"))
                                print(powerSupplyFRUFormat. \
                                    format("-------------------------", #25
                                           "------------",  #12
                                           "-------------", #13
                                           "-----------",   #11
                                           "---------", #9
                                           "--------",   #8
                                           "-----------", #11
                                           "---------", #9
                                           "--------",  #8
                                           "--------------------", #20
                                           "-------------", #13
                                           "-------------", #13
                                           "--------------------", #20
                                           "---------", #9
                                           "---------", #9
                                           "---------")) #9
                                psFRUHeaderPrinted = True

                            ID = inputPowerOkay = outputPowerOkay = ""
                            temperatureWarning = temperatureAlarm = ""
                            modelNumber = manufacturerPartNumber = ""
                            serialNumber = modLevel = manufacturer = ""
                            countryOfManufacturer = temperatureInCelsius = ""
                            communicatingWithPCM = ""
                            fanOne = fanTwo = fanThree = ""

                            for psFRU in ceinfo:
                                if psFRU.tag == "ID":
                                    ID = psFRU.text.strip()
                                elif psFRU.tag == "inputPowerOkay":
                                    inputPowerOkay = psFRU.text.strip()
                                elif psFRU.tag == "outputPowerOkay":
                                    outputPowerOkay = psFRU.text.strip()
                                elif psFRU.tag == "temperatureWarning":
                                    temperatureWarning = psFRU.text.strip()
                                elif psFRU.tag == "temperatureAlarm":
                                    temperatureAlarm = psFRU.text.strip()
                                elif psFRU.tag == "modelNumber":
                                    modelNumber = psFRU.text.strip()
                                elif psFRU.tag == "manufacturerPartNumber":
                                    manufacturerPartNumber = psFRU.text.strip()
                                elif psFRU.tag == "serialNumber":
                                    serialNumber = psFRU.text.strip()
                                elif psFRU.tag == "modLevel":
                                    modLevel = psFRU.text.strip()
                                elif psFRU.tag == "manufacturer":
                                    manufacturer = psFRU.text.strip()
                                elif psFRU.tag == "countryOfManufacturer":
                                    countryOfManufacturer = psFRU.text.strip()
                                elif psFRU.tag == "temperatureInCelsius":
                                    temperatureInCelsius = psFRU.text.strip()
                                elif psFRU.tag == "communicatingWithPCM":
                                    communicatingWithPCM = psFRU.text.strip()
                                elif psFRU.tag == "fanInPowerSupplyFRU":
                                    fanNum = fanOkay = ""
                                    for fan in psFRU:
                                        if fan.tag == "number":
                                            fanNum = fan.text.strip()
                                        elif fan.tag == "okay":
                                            fanOkay = fan.text.strip()
                                            if fanNum == "1":
                                                fanOne = fanOkay
                                            elif fanNum == "2":
                                                fanTwo = fanOkay
                                            elif fanNum == "3":
                                                fanThree = fanOkay

                            print(powerSupplyFRUFormat. \
                                format(ID, inputPowerOkay, outputPowerOkay,
                                       temperatureWarning, temperatureAlarm,
                                       modelNumber, manufacturerPartNumber,
                                       serialNumber, modLevel, manufacturer,
                                       countryOfManufacturer,
                                       temperatureInCelsius,
                                       communicatingWithPCM,
                                       fanOne, fanTwo, fanThree))

                        # power control modules
                        if ceinfo.tag == "powerControlModule":
                            if powerCMHeaderPrinted == False:
                                print()
                                print(powerCMFormat. \
                                    format("PowerControlModuleID",
                                           "TempInCelsius",
                                           "ParallelACPresent",
                                           "PrimaryACPresent",
                                           "SecondaryACPresent",
                                           "SupplyDetectionWorking",
                                           "PrimaryACVoltage",
                                           "SecondaryACVoltage",
                                           "12VoltVoltage",
                                           "5VoltVoltage",
                                           "OnBoardTempInCelsius",
                                           "PowerSupplyPosition",
                                           "PowerSupplyFaulted?"))
                                print(powerCMFormat. \
                                    format("-------------------------", #25
                                           "-------------", #13
                                           "-----------------", #17
                                           "----------------", #16
                                           "------------------", #18
                                           "----------------------", #22
                                           "----------------", #16
                                           "------------------", #18
                                           "-------------", #13
                                           "------------", #12
                                           "--------------------", #20
                                           "-------------------", #19
                                           "-------------------")) #19
                                powerCMHeaderPrinted = True

                            ID = temperatureInCelsius = parallelACPresent = ""
                            primaryACPresent = secondaryACPresent = ""
                            supplyDetectionWorking = ""
                            primaryACVoltage = secondaryACVoltage = ""
                            twelveVoltVoltage = fiveVoltVoltage = ""
                            onBoardTemperatureInCelsius = ""
                            position = faulted = ""
                            origPosition = origFaulted = ""

                            for pcm in ceinfo:
                                if pcm.tag == "ID":
                                    ID = pcm.text.strip()
                                elif pcm.tag == "temperatureInCelsius":
                                    temperatureInCelsius = pcm.text.strip()
                                elif pcm.tag == "parallelACPresent":
                                    parallelACPresent = pcm.text.strip()
                                elif pcm.tag == "primaryACPresent":
                                    primaryACPresent = pcm.text.strip()
                                elif pcm.tag == "secondaryACPresent":
                                    secondaryACPresent = pcm.text.strip()
                                elif pcm.tag == "supplyDetectionWorking":
                                    supplyDetectionWorking = pcm.text.strip()
                                #ACCurrentInAmps is no longer supported
                                elif pcm.tag == "primaryACVoltage":
                                    primaryACVoltage = pcm.text.strip()
                                elif pcm.tag == "secondaryACVoltage":
                                    secondaryACVoltage = pcm.text.strip()
                                elif pcm.tag == "twelveVoltVoltage":
                                    twelveVoltVoltage = pcm.text.strip()
                                elif pcm.tag == "fiveVoltVoltage":
                                    fiveVoltVoltage = pcm.text.strip()
                                elif pcm.tag == "onBoardTemperatureInCelsius":
                                    onBoardTemperatureInCelsius = pcm.text.strip()
                                #remoteTemperatureInCelsius is no longer supported
                                elif pcm.tag == "powerSupplyInPCM":
                                    # The PCM can have multiple power supplies,
                                    # so output one line per power supply
                                    # location.
                                    for item in pcm:
                                        if item.tag == "position":
                                            origPosition = position
                                            position = item.text.strip()
                                        elif item.tag == "faulted":
                                            origFaulted = faulted
                                            faulted = item.text.strip()
                                        if ( (origPosition != position) and
                                             (origFaulted != faulted) ):
                                            print(powerCMFormat. \
                                                format(ID, temperatureInCelsius,
                                                    parallelACPresent, primaryACPresent,
                                                    secondaryACPresent,
                                                    supplyDetectionWorking,
                                                    primaryACVoltage, secondaryACVoltage,
                                                    twelveVoltVoltage, fiveVoltVoltage,
                                                    onBoardTemperatureInCelsius,
                                                    position,
                                                    faulted))
                                            position = faulted = ""
                                            origPosition = origFaulted = ""


                        # fan control modules
                        # Note: wasn't able to test on NERF Tfinity as it
                        # apparently doesn't have any fan control modules!
                        if ceinfo.tag == "fanControlModule":
                            if fanCMHeaderPrinted == False:
                                print()
                                print(fanCMFormat. \
                                    format("FanControlModuleID",
                                           "FrameNum",
                                           "TempInCelsius",
                                           "BackPanelSwitch",
                                           "FanPanelSwitch",
                                           "FilterPanelSwitch",
                                           "FrontTAPFramePanelSwitch",
                                           "BoardVoltage",
                                           "FanInputVoltage",
                                           "FanSpeedVoltage",
                                           "FanSpeedSetting",
                                           "FanInFCMNum",
                                           "FanInFCMOn?",
                                           "FanInFCMSpeedInRPM",
                                           "LightBankNum",
                                           "LightBankOn?"))
                                print(powerCMFormat. \
                                    format("-------------------------", #25
                                           "--------", #8
                                           "-------------", #13
                                           "---------------", #15
                                           "--------------", #14
                                           "-----------------", #17
                                           "------------------------", #24
                                           "------------", #12
                                           "---------------", #15
                                           "---------------", #15
                                           "---------------", #15
                                           "-----------", #11
                                           "-----------", #11
                                           "------------------", #16
                                           "------------", #12
                                           "------------")) #12
                                fanCMHeaderPrinted = True

                            ID = frameNumber = temperatureInCelsius = ""
                            backPanelSwitch = fanPanelSwitch = ""
                            filterPanelSwitch = frontTAPFramePanelSwitch = ""
                            boardVoltage = fanInputVoltage = ""
                            fanSpeedVoltage = fanSpeedSetting = ""

                            for fcm in ceinfo:
                                if fcm.tag == "ID":
                                    ID = fcm.text.strip()
                                elif fcm.tag == "frameNumber":
                                    frameNumber = fcm.text.strip()
                                elif fcm.tag == "temperatureInCelsius":
                                    temperatureInCelsius = fcm.text.strip()
                                elif fcm.tag == "backPanelSwitch":
                                    backPanelSwitch = fcm.text.strip()
                                elif fcm.tag == "fanPanelSwitch":
                                    fanPanelSwitch = fcm.text.strip()
                                elif fcm.tag == "filterPanelSwitch":
                                    filterPanelSwitch = fcm.text.strip()
                                elif fcm.tag == "frontTAPFramePanelSwitch":
                                    frontTAPFramePanelSwitch = fcm.text.strip()
                                elif fcm.tag == "boardVoltage":
                                    boardVoltage = fcm.text.strip()
                                elif fcm.tag == "fanInputVoltage":
                                    fanInputVoltage = fcm.text.strip()
                                elif fcm.tag == "fanSpeedVoltage":
                                    fanSpeedVoltage = fcm.text.strip()
                                elif fcm.tag == "fanSpeedSetting":
                                    fanSpeedSetting = fcm.text.strip()
                                #newFansCalibrated is no longer used
                                #newFilterCalibrated is no longer used
                                elif fcm.tag == "fanInFCM":
                                    fanInFCMList = fcm.findall("fanInFCM")
                                elif fcm.tag == "lightBank":
                                    lightBankList = fcm.findall("fanInFCM")

                            fanNumber = fanOn = fanSpeedInRPM = ""
                            lightBankNumber = lightBankOn = ""
                            for fan in fanInCMList:
                                if fan.tag == "number":
                                    fanNumber = fan.text.strip()
                                elif fan.tag == "on":
                                    fanOn = fan.text.strip()
                                elif fan.tag == "speedInRPM":
                                    fanSpeedInRPM = fan.text.strip()

                                print(fanCMFormat. \
                                    format(ID, frameNumber,
                                           temperatureInCelsius,
                                           backPanelSwitch, fanPanelSwitch,
                                           filterPanelSwitch,
                                           frontTAPFramePanelSwitch,
                                           boardVoltage, fanInputVoltage,
                                           fanSpeedVoltage, fanSpeedSetting,
                                           fanNumber, fanOn, fanSpeedInRPM,
                                           lightBankNumber, lightBankOn))

                            fanNumber = fanOn = fanSpeedInRPM = ""
                            lightBankNumber = lightBankOn = ""
                            for lightBank in lightBankList:
                                if lightBank.tag == "number":
                                    lightBankNumber = lightBank.text.strip()
                                elif lightBank.tag == "on":
                                    lightBankOn = lightBank.text.strip()

                                print(fanCMFormat. \
                                    format(ID, frameNumber,
                                           temperatureInCelsius,
                                           backPanelSwitch, fanPanelSwitch,
                                           filterPanelSwitch,
                                           frontTAPFramePanelSwitch,
                                           boardVoltage, fanInputVoltage,
                                           fanSpeedVoltage, fanSpeedSetting,
                                           fanNumber, fanOn, fanSpeedInRPM,
                                           lightBankNumber, lightBankOn))

                        # frame management modules
                        if ceinfo.tag == "frameManagementModule":
                            if frameMMHeaderPrinted == False:
                                print()
                                print(frameMMFormat. \
                                    format("FrameManagementModuleID",
                                           "24VoltVoltage", "5VoltVoltage",
                                           "FanRailVoltage",
                                           "SwitchedRailVoltage",
                                           "24VoltCurrentInAmps",
                                           "PowerConsumedInWatts",
                                           "SampleRateInSecs", "SamplesTaken",
                                           "TempInCelsius", "EPMTempInCelsius",
                                           "FrameToFrameTempInCelsius",
                                           "FrameToFrameAttached",
                                           "FrameToFrame5VoltEnabled",
                                           "FansEnabled", "BackSwitchOpen",
                                           "FilterSwitchOpen",
                                           "FrontSwitchOpen",
                                           "SafetyInterlockOpen",
                                           "FrameIDInfo", "DriveFrameNum",
                                           "SwitchedRailState",
                                           "RobotPowerEnabled",
                                           "InternalLightsEnabled",
                                           "ExternalLightsEnabled"))
                                print(frameMMFormat. \
                                    format("-------------------------", #25
                                           "-------------", #13
                                           "------------", #12
                                           "--------------", #13
                                           "-------------------", #19
                                           "-------------------", #19
                                           "--------------------", #20
                                           "----------------", #16
                                           "------------", #12
                                           "-------------", #13
                                           "----------------", #16
                                           "-------------------------", #25
                                           "--------------------", #20
                                           "------------------------", #24
                                           "-----------", #12
                                           "--------------", #14
                                           "----------------", #16
                                           "---------------", #15
                                           "-------------------", #19
                                           "-----------", #11
                                           "-------------", #13
                                           "-----------------", #17
                                           "-----------------", #17
                                           "---------------------", #21
                                           "---------------------")) #21
                                frameMMHeaderPrinted = True

                            ID = twentyFourVoltVoltage = fiveVoltVoltage = ""
                            fanRailVoltage = switchedRailVoltage = ""
                            twentyFourVoltCurrentInAmps = ""
                            powerConsumedInWatts = sampleRateInSeconds = ""
                            samplesTaken = temperatureInCelsius = ""
                            EPMTemperatureInCelsius = ""
                            frameToFrameTemperatureInCelsius = ""
                            frameToFrameAttached = ""
                            frameToFrameFiveVoltEnabled = fansEnabled = ""
                            backSwitchOpen = filterSwitchOpen = ""
                            frontSwitchOpen = safetyInterlockOpen = ""
                            frameIDInfo = driveFrameNumber = ""
                            switchedRailState = robotPowerEnabled = ""
                            internalLightsEnabled = externalLightsEnabled = ""

                            for frameMM in ceinfo:
                                if frameMM.tag == "ID":
                                    ID = frameMM.text.strip()
                                elif frameMM.tag == "twentyFourVoltVoltage":
                                    twentyFourVoltVoltage = frameMM.text.strip()
                                elif frameMM.tag == "fiveVoltVoltage":
                                    fiveVoltVoltage = frameMM.text.strip()
                                elif frameMM.tag == "fanRailVoltage":
                                    fanRailVoltage = frameMM.text.strip()
                                elif frameMM.tag == "switchedRailVoltage":
                                    switchedRailVoltage = frameMM.text.strip()
                                elif frameMM.tag == "twentyFourVoltCurrentInAmps":
                                    twentyFourVoltCurrentInAmps = frameMM.text.strip()
                                elif frameMM.tag == "powerConsumedInWatts":
                                    powerConsumedInWatts = frameMM.text.strip()
                                elif frameMM.tag == "sampleRateInSeconds":
                                    sampleRateInSeconds = frameMM.text.strip()
                                elif frameMM.tag == "samplesTaken":
                                    samplesTaken = frameMM.text.strip()
                                elif frameMM.tag == "temperatureInCelsius":
                                    temperatureInCelsius = frameMM.text.strip()
                                elif frameMM.tag == "EPMTemperatureInCelsius":
                                    EPMTemperatureInCelsius = frameMM.text.strip()
                                elif frameMM.tag == "frameToFrameTemperatureInCelsius":
                                    frameToFrameTemperatureInCelsius = frameMM.text.strip()
                                elif frameMM.tag == "frameToFrameAttached":
                                    frameToFrameAttached = frameMM.text.strip()
                                elif frameMM.tag == "frameToFrameFiveVoltEnabled":
                                    frameToFrameFiveVoltEnabled = frameMM.text.strip()
                                elif frameMM.tag == "fansEnabled":
                                    fansEnabled = frameMM.text.strip()
                                elif frameMM.tag == "backSwitchOpen":
                                    backSwitchOpen = frameMM.text.strip()
                                elif frameMM.tag == "filterSwitchOpen":
                                    filterSwitchOpen = frameMM.text.strip()
                                elif frameMM.tag == "frontSwitchOpen":
                                    frontSwitchOpen = frameMM.text.strip()
                                elif frameMM.tag == "safetyInterlockOpen":
                                    safetyInterlockOpen = frameMM.text.strip()
                                elif frameMM.tag == "frameIDInfo":
                                    frameIDInfo = frameMM.text.strip()
                                elif frameMM.tag == "driveFrameNumber":
                                    driveFrameNumber = frameMM.text.strip()
                                elif frameMM.tag == "switchedRailState":
                                    switchedRailState = frameMM.text.strip()
                                elif frameMM.tag == "robotPowerEnabled":
                                    robotPowerEnabled = frameMM.text.strip()
                                elif frameMM.tag == "internalLightsEnabled":
                                    internalLightsEnabled = frameMM.text.strip()
                                elif frameMM.tag == "externalLightsEnabled":
                                    externalLightsEnabled = frameMM.text.strip()
                                elif frameMM.tag == "fanPair":
                                    fanNum = fanPresent = ""
                                    for fan in frameMM:
                                        if fan.tag == "number":
                                            fanNum = fan.text.strip()
                                        elif fan.tag == "present":
                                            fanPresent = fan.text.strip()
                                        if (fanNum != "") and (fanPresent != ""):
                                            fanPairString = fanPairFormat. \
                                                format(ID, fanNum, fanPresent)
                                            fanPairStringList.append(fanPairString)
                                            fanNum = fanPresent = ""
                                elif frameMM.tag == "fanInFMM":
                                    fanInFMMNum = fanSpeed = ""
                                    for fan in frameMM:
                                        if fan.tag == "number":
                                            fanInFMMNum = fan.text.strip()
                                        #ToDo: The documentation shows an "on"
                                        #record, but I'v never seen it, so I'm
                                        #not looking for it.
                                        elif fan.tag == "speedInRPM":
                                            fanSpeed = fan.text.strip()
                                        if ( (fanInFMMNum != "") and
                                             (fanSpeed != "") ):
                                            fanString = fanInFMMFormat. \
                                                format(ID, fanInFMMNum, fanSpeed)
                                            fanInFMMStringList.append(fanString)
                                            fanInFMMNum = fanSpeed = ""
                                elif frameMM.tag == "powerSupplyInFMM":
                                    position = faulted = ""
                                    for powerSupply in frameMM:
                                        if powerSupply.tag == "position":
                                            position = powerSupply.text.strip()
                                        elif powerSupply.tag == "faulted":
                                            faulted = powerSupply.text.strip()
                                        if (position != "") and (faulted != ""):
                                            powerString = powerInFMMFormat. \
                                                format(ID, position, faulted)
                                            powerInFMMStringList.append(powerString)
                                            position = faulted = ""

                            print(frameMMFormat. \
                                format(ID, twentyFourVoltVoltage,
                                       fiveVoltVoltage, fanRailVoltage,
                                       switchedRailVoltage,
                                       twentyFourVoltCurrentInAmps,
                                       powerConsumedInWatts,
                                       sampleRateInSeconds, samplesTaken,
                                       temperatureInCelsius,
                                       EPMTemperatureInCelsius,
                                       frameToFrameTemperatureInCelsius,
                                       frameToFrameAttached,
                                       frameToFrameFiveVoltEnabled,
                                       fansEnabled, backSwitchOpen,
                                       filterSwitchOpen, frontSwitchOpen,
                                       safetyInterlockOpen, frameIDInfo,
                                       driveFrameNumber, switchedRailState,
                                       robotPowerEnabled,
                                       internalLightsEnabled,
                                       externalLightsEnabled))

                        # service bay control modules
                        if ceinfo.tag == "serviceBayControlModule":

                            ID = frameIDInfo = safetyDoorState = ""
                            overrideSwitch = rearAccessPanel = ""
                            sideAccessPanel = sidePanel = ""
                            robotInServiceFrame = bulkIEPresent = ""
                            bulkIEDoorOpen = bulkIEAjar = ""
                            solenoidPinPosition = bulkTAPLocation = ""

                            for service in ceinfo:
                                if service.tag == "ID":
                                    ID = service.text.strip()
                                elif service.tag == "frameIDInfo":
                                    frameIDInfo = service.text.strip()
                                elif service.tag == "overrideSwitch":
                                    overrideSwitch = service.text.strip()
                                elif service.tag == "rearAccessPanel":
                                    rearAccessPanel = service.text.strip()
                                elif service.tag == "sideAccessPanel":
                                    sideAccessPanel = service.text.strip()
                                elif service.tag == "sidePanel":
                                    sidePanel = service.text.strip()
                                elif service.tag == "robotInServiceFrame":
                                    robotInServiceFrame = service.text.strip()
                                elif service.tag == "bulkIEPresent":
                                    bulkIEPresent = service.text.strip()
                                elif service.tag == "bulkIEDoorOpen":
                                    bulkIEDoorOpen = service.text.strip()
                                elif service.tag == "bulkIEAjar":
                                    bulkIEAjar = service.text.strip()
                                elif service.tag == "solenoidPinPosition":
                                    solenoidPinPosition = service.text.strip()
                                elif service.tag == "bulkTAPLocation":
                                    bulkTAPLocation = service.text.strip()
                            serviceStringList.append( serviceFormat. \
                                format(ID, frameIDInfo, safetyDoorState,
                                       overrideSwitch, rearAccessPanel,
                                       sideAccessPanel, sidePanel,
                                       robotInServiceFrame, bulkIEPresent,
                                       bulkIEDoorOpen, bulkIEAjar,
                                       solenoidPinPosition, bulkTAPLocation))

                    if len(fanPairStringList) > 0:
                        print()
                        print(fanPairFormat. \
                            format("FrameManagementModuleID",
                                   "FanPair#",
                                   "FanPairPresent?"))
                        print(fanPairFormat. \
                            format("-------------------------",
                                   "--------",
                                   "---------------"))
                        for item in fanPairStringList:
                            print(item)

                    if len(fanInFMMStringList) > 0:
                        print()
                        print(fanInFMMFormat. \
                            format("FrameManagementModuleID",
                                   "FanNum",
                                   "FanSpeedInRPM"))
                        print(fanInFMMFormat. \
                            format("-------------------------",
                                   "------",
                                   "-------------"))
                        for item in fanInFMMStringList:
                            print(item)

                    if len(powerInFMMStringList) > 0:
                        print()
                        print(powerInFMMFormat. \
                            format("FrameManagementModuleID",
                                   "PowerSupplyPosition",
                                   "PowerSupplyFaulted?"))
                        print(powerInFMMFormat. \
                            format("-------------------------",
                                   "-------------------",
                                   "-------------------"))
                        for item in powerInFMMStringList:
                            print(item)

                    # service bay control modules
                    if len(serviceStringList) > 0:
                        print()
                        print(serviceFormat. \
                            format("ServiceBayControlModuleID", "FrameIDInfo",
                                   "SafetyDoorState", "OverrideSwitch",
                                   "RearAccessPanel", "SideAccessPanel",
                                   "SidePanel", "RobotInServiceFrame",
                                   "BulkIEPresent", "BulkIEDoorOpen",
                                   "BulkIEAjar", "SolenoidPinPosition",
                                   "BulkTAPLocation"))
                        print(serviceFormat. \
                            format("-------------------------",
                                   "-----------", #11
                                   "---------------", #15
                                   "--------------", #14
                                   "---------------", #15
                                   "---------------", #15
                                   "---------", #9
                                   "-------------------", #19
                                   "-------------", #13
                                   "--------------", #14
                                   "----------", #10
                                   "-------------------", #19
                                   "---------------")) #15
                        for item in serviceStringList:
                            print(item)

                # ECInfo component list
                if child.tag == "ECInfo":
                    for ecinfo in child:

                        # components
                        if ecinfo.tag == "component":
                            if componentHeaderPrinted == False:
                                print()
                                print(componentFormat. \
                                    format("ECComponentID", "EC",
                                           "SerialNum", "TopLevelAssemblyEC",
                                           "TopLevelAssemblySerialNum",
                                           "Date"))
                                print(componentFormat. \
                                    format("-------------------------", "--",
                                           "---------------",
                                           "------------------",
                                           "-------------------------",
                                           "----------"))
                                componentHeaderPrinted = True

                            ID = EC = serialNumber = topLevelAssemblyEC = ""
                            topLevelAssemblySerialNumber = date = ""

                            for component in ecinfo:
                                if component.tag == "ID":
                                    ID = component.text.strip()
                                elif component.tag == "EC":
                                    EC = component.text.strip()
                                elif component.tag == "serialNumber":
                                    if component.text:
                                        serialNumber = component.text.rstrip()
                                    else:
                                        serialNumber = "None"
                                elif component.tag == "topLevelAssemblyEC":
                                    topLevelAssemblyEC = component.text.strip()
                                elif component.tag == "topLevelAssemblySerialNumber":
                                    if component.text:
                                        topLevelAssemblySerialNumber = component.text.rstrip()
                                    else:
                                        topLevelAssemblySerialNumber = "None"
                                elif component.tag == "date":
                                    date = component.text.strip()
                            print(componentFormat. \
                                format(ID, EC, serialNumber, topLevelAssemblyEC,
                                       topLevelAssemblySerialNumber, date))

        except Exception as e:
            print("LibraryStatus Error: " + str(e), file=sys.stderr)
            traceback.print_exc()


    #--------------------------------------------------------------------------
    #
    # Returns the library type, serial number, component status, and engineering
    # change level information for the library that received the command.
    #
    def librarystatus2(self):

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
            print("LibraryStatus2 Error: " + str(e), file=sys.stderr)


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
            print("\nPartition List")
            print(  "--------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            for child in tree:
                if child.tag == "partitionName":
                    print(child.text.rstrip())

        except Exception as e:
            print("PartitionList Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns the list of system messages that are currently stored on the
    # library. The messages are listed in the order they were posted, beginning
    # with the most recent.
    #
    #
    def systemmessages(self):

        msgFormat = '{:6} {:19} {:11} {}'

        try:
            url  = self.baseurl + "/systemMessages.xml"
            tree = self.run_command(url)
            print("\nSystem Messages")
            print(  "---------------")
            if self.longlist:
                self.longlisting(tree, 0)
                return
            print(msgFormat. \
                format("Number", "Date", "Severity", "Message/Remedy"))
            print(msgFormat. \
                format("------", "-------------------", "-----------",
                       "--------------"))
            for child in tree:
                if child.tag == "message":

                    # initialize
                    number = severity = message = remedy = ""
                    month = day = hour = minute = second = "00"
                    year = "0000"
                    dateString = year + "-" + month + "-" + day + " " + \
                                 hour + ":" + minute + ":" + second

                    # go thru the records
                    for messageRecord in child:
                        if messageRecord.tag == "number":
                            number = messageRecord.text.rstrip()
                        elif messageRecord.tag == "severity":
                            severity = messageRecord.text.rstrip()
                        elif messageRecord.tag == "date":
                            for date in messageRecord:
                                if date.tag == "month":
                                    month = date.text.rstrip()
                                elif date.tag == "day":
                                    day = date.text.rstrip()
                                elif date.tag == "year":
                                    year = date.text.rstrip()
                        elif messageRecord.tag == "time":
                            for time in messageRecord:
                                if time.tag == "hour":
                                    hour = time.text.rstrip()
                                elif time.tag == "minute":
                                    minute = time.text.rstrip()
                                elif time.tag == "second":
                                    second = time.text.rstrip()
                        elif messageRecord.tag == "notification":
                            message = "Message: " + messageRecord.text.rstrip()
                        elif messageRecord.tag == "remedy":
                            remedy = "Remedy: " + messageRecord.text.rstrip()

                    # print it out; put remedy and message on separate lines
                    dateString = year + "-" + month + "-" + day + " " + \
                                 hour + ":" + minute + ":" + second
                    print(msgFormat.format(number, dateString, severity, message))
                    print(msgFormat.format(number, dateString, severity, remedy))

        except Exception as e:
            print("systemMessages Error: " + str(e), file=sys.stderr)


    #--------------------------------------------------------------------------
    #
    # Returns the list of the extended action and background operations
    # currently in process on the library.
    #
    # - If the library is not currently performing any extended or background
    #   operations, the command returns a page with empty parameter tags.
    # - If the library is performing any extended or background operations the
    #   command returns the following XML-formatted data:
    #
    #
    def tasklist (self):

        actionFormat = '{:25} {:14} {}'
        taskFormat   = '{:25} {:25} {}'

        try:
            url  = self.baseurl + "/taskList.xml"
            tree = self.run_command(url)
            print("\nTask List")
            print(  "---------")

            # Bail if we don't have any elements
            if len(tree) == 0:
                print("None")
                return

            # Handle long list option
            if self.longlist:
                self.longlisting(tree, 0)
                return

            # Process the elements
            taskHeaderPrinted = False
            for child in tree:
                if child.tag == "currentAsynchronousAction":
                    # There's at most one currentAsynchronousAction
                    name = status = feedbackString = ""
                    for action in child:
                        if action.tag == "name":
                            name = action.text.rstrip()
                        elif action.tag == "status":
                            status = action.text.rstrip()
                        elif action.tag == "feedbackString":
                            feedbackString = action.text.rstrip()
                    print(actionFormat. \
                        format("Name", "Status", "FeedbackString"))
                    print(actionFormat. \
                        format("-------------------------", "--------------",
                               "--------------"))
                    print(actionFormat.format(name, status, feedbackString))
                elif child.tag == "currentBackgroundTasks":
                    # There can be multiple of these
                    if (taskHeaderPrinted == False):
                        print() # newline
                        print(taskFormat. \
                            format("Name", "Description", "ExtraInfo"))
                        print(taskFormat. \
                            format("-------------------------",
                                   "-------------------------",
                                   "---------"))
                        taskHeaderPrinted = True
                    name = description = extraInformation = ""
                    for task in child:
                        if task.tag == "name":
                            name = task.text.rstrip()
                        elif task.tag == "thread":
                            for thread in task:
                                if thread.tag == "description":
                                    description = thread.text.rstrip()
                                elif thread.tag == "extraInformation":
                                    extraInformation = thread.text.rstrip()
                    print(taskFormat. \
                        format(name, description, extraInformation))
                elif child.tag == "pageNeedingProgressRequest":
                    print("\nPage Needing Progress Request")
                    print(  "-----------------------------")
                    for page in child:
                        print(page.text.rstrip)

        except Exception as e:
            print("taskList  Error: " + str(e), file=sys.stderr)


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
        help='Returns library type, serial number, component status and engineering change level information. With Headers')
    librarystatus2_parser = cmdsubparsers.add_parser('librarystatus2',
        help='Returns library type, serial number, component status and engineering change level information.')

    packagelist_parser = cmdsubparsers.add_parser('packagelist',
        help='Retrieves the name of the BlueScale package currently used by the library along with the list of packages currently stored on the memory card in the LCM.')

    partitionlist_parser = cmdsubparsers.add_parser('partitionlist',
        help='List all Spectra Logic Library partitions.')

    systemmessages_parser = cmdsubparsers.add_parser('systemmessages',
        help='Returns the list of system messages that are currently stored on the library. Most recent first.')

    tasklist_parser = cmdsubparsers.add_parser('tasklist',
        help='Returns the list of the extended action and background operations currently in process on the library.')


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
    elif args.command == "librarystatus2":
        slapi.librarystatus2()
    elif args.command == "packagelist":
        slapi.packagelist()
    elif args.command == "partitionlist":
        slapi.partitionlist()
    elif args.command == "systemmessages":
        slapi.systemmessages()
    elif args.command == "tasklist":
        slapi.tasklist()
    else:
        cmdparser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
