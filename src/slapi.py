#!/usr/bin/python3
#
# Copyright (C) 2019 Lawrence Livermore National Security, LLC
# Please see top-level LICENSE for details.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import functools
import sys
import os
import stat
import time
import pathlib
import configparser
import requests
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import xml.etree.ElementTree
import xml.dom.minidom
import traceback
import datetime
import re

class SpectraLogicLoginError(Exception):

    LoginErrorRaised = False

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class IncompatibleParameterError(Exception):

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class SpectraLogicAPI:

    #--------------------------------------------------------------------------
    #
    def __init__(self, args):
        self.server     = args.server
        self.user       = args.user
        self.passwd     = args.passwd
        self.verbose    = args.verbose
        self.insecure   = args.insecure
        self.longlist   = args.longlist
        self.loggedin   = False
        self.sessionid  = ""
        self.cookiefile = self.slapi_directory() + "/cookies.txt"
        self.cookiejar  = http.cookiejar.LWPCookieJar()
        self.load_cookie()
        self.baseurl    = "https://" + args.server + "/gf"
        if self.insecure:
            self.baseurl    = "http://" + args.server + "/gf"


    #--------------------------------------------------------------------------
    #
    def slapi_directory(self):

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


    #--------------------------------------------------------------------------
    #
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

    #--------------------------------------------------------------------------
    #
    # Creates a string of xml output as a one item per line hierarchy.
    # Similar to long_listing but going to a string instead of printing.
    # Helpful for XML error markup.
    #
    def get_all_text(self, element, inputString):

        # add the name of the element
        outputString = inputString + element.tag

        # add the text of the element; "None" if no text
        if element.text:
            outputString = outputString + ": " + element.text.rstrip()
        else:
            outputString = outputString + ": None"
        outputString = outputString + "\n"

        # recurse to the next level of elements
        for subelem in element:
            outputString = self.get_all_text(subelem, outputString)

        return(outputString)


    #--------------------------------------------------------------------------
    #
    def clear_cookie(self):
        try:
            tmpserver = self.server
            if tmpserver.find(".") == -1:
                tmpserver = tmpserver + ".local"
            for cookie in self.cookiejar:
                if cookie.domain == tmpserver:
                    self.cookiejar.clear(cookie.domain)
        except Exception as e:
            self.loggedin  = False
            self.sessionid = ""


    #--------------------------------------------------------------------------
    #
    def load_cookie(self):

        try:
            tmpserver = self.server
            if tmpserver.find(".") == -1:
                tmpserver = tmpserver + ".local"
            self.cookiejar.load(self.cookiefile, ignore_discard=True, ignore_expires=False)
            for cookie in self.cookiejar:
                if cookie.domain == tmpserver and cookie.name == "sessionID":
                    if cookie.is_expired() or self.cookie_is_old():
                        self.clear_cookie()
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
    def long_listing(self, element, level):

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
            self.long_listing(subelem, (level+1))

        sys.stdout.flush()


    #--------------------------------------------------------------------------
    #
    # This routine pretty prints the XML document to stderr if the verbose
    # flag is on.
    #
    def print_xml_document(self, xmldoc):

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


    #--------------------------------------------------------------------------
    #
    # Runs the XML command
	# Return either an XML element tree by default, or the data as a string if
	# the returnstring parameter is set to True.
    #
    def run_command(self, url, filename=None, returnstring=False):

        if filename is not None and returnstring is not False:
            raise(IncompatibleParameterError("Error: The filename and the returnstring cannot both be specified."))

        try:

            if self.verbose:
                tmpurl = url.replace(self.passwd, "*" * len(self.passwd))
                print("--------------------------------------------------", file=sys.stderr)
                print("Command: " + tmpurl, file=sys.stderr)
                print("--------------------------------------------------", file=sys.stderr)
                print("", file=sys.stderr)

            # FIXME someday...
            #
            # The libraries currently use self-signed certs Do not verify the
            # certificate for now...  Also use medium encryption cipher suite
            # At come point we should be able to completely get rid of the code
            # for setting the cipher.
            #
            # Explanations for the cipher names
            #
            # HIGH
            #
            # "High" encryption cipher suites. This currently means those with
            # key lengths larger than 128 bits, and some cipher suites with
            # 128-bit keys.
            #
            # MEDIUM
            #
            # "Medium" encryption cipher suites, currently some of those using
            # 128 bit encryption.
            #
            # LOW
            #
            # "Low" encryption cipher suites, currently those using 64 or 56
            # bit encryption algorithms but excluding export cipher suites. All
            # these cipher suites have been removed as of OpenSSL 1.1.0.
            #
            # eNULL, NULL
            #
            # The "NULL" ciphers that is those offering no encryption. Because
            # these offer no encryption at all and are a security risk they are
            # not enabled via either the DEFAULT or ALL cipher strings. Be
            # careful when building cipherlists out of lower-level primitives
            # such as kRSA or aECDSA as these do overlap with the eNULL
            # ciphers. When in doubt, include !eNULL in your cipherlist.
            #
            # aNULL
            #
            # The cipher suites offering no authentication. This is currently
            # the anonymous DH algorithms and anonymous ECDH algorithms. These
            # cipher suites are vulnerable to "man in the middle" attacks and
            # so their use is discouraged. These are excluded from the DEFAULT
            # ciphers, but included in the ALL ciphers. Be careful when
            # building cipherlists out of lower-level primitives such as kDHE
            # or AES as these do overlap with the aNULL ciphers. When in doubt,
            # include !aNULL in your cipherlist.

            #cipherstr = 'HIGH:!aNULL:!eNULL'
            cipherstr = 'MEDIUM:!aNULL:!eNULL'

            context = ssl._create_unverified_context()
            context.set_ciphers(cipherstr)

            if (filename is None):
                opener    = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.cookiejar))
                opener.addheaders.append(("Cookie", "sessionID=" + self.sessionid))
                request   = urllib.request.Request(url)
                response  = opener.open(request)
                xmldoc    = response.read()
            else:
                requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
                requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = cipherstr
                #http.client.HTTPConnection.debuglevel = 1
                #logging.basicConfig()
                #logging.getLogger().setLevel(logging.DEBUG)

                #requests_log = logging.getLogger("requests.packages.urllib3")
                #requests_log.setLevel(logging.DEBUG)
                #requests_log.propagate = True

                try:
                    headers   = { 'Cookie': 'sessionID=' + self.sessionid }
                    with open(filename, 'rb') as f:
                        params    = {'BlueScalePkg': (os.path.basename(filename), f, 'application/vnd.hp-hps')}
                        response  = requests.post(url, files=params, headers=headers, verify=False, allow_redirects=True)
                        xmldoc    = response.text
                except Exception as e:
                    raise(e)

            # If we got an error from running the command, then we will be able
            # to successfully put into a tree and check for error records.
            checkerror = True
            if returnstring:
                checkerror = False

            try:
                tree       = xml.etree.ElementTree.fromstring(xmldoc)
                checkerror = True

                # Pretty print the XML document if verbose on
                self.print_xml_document(xmldoc)

            except Exception as e:

                if returnstring:
                    # It's okay if we couldn't turn the xmldoc into a tree; means
                    # we've got some good binary data
                    checkerror = False
                else:
                    raise(e)

            # check_for_error will raise an exception if it encounters a problem
            try:
                if checkerror:
                    self.check_for_error(tree)

                if returnstring:
                    return(xmldoc)
                else:
                    return(tree)

            except SpectraLogicLoginError as e:
                try:
                    if (self.verbose):
                        print("Loginerror: Raised: " +
                            str(SpectraLogicLoginError.LoginErrorRaised),
                            file=sys.stderr)

                    # If we haven't already had a login error, then login
                    # and retry the command
                    if SpectraLogicLoginError.LoginErrorRaised == False:
                        SpectraLogicLoginError.LoginErrorRaised = True
                        if (self.verbose):
                            print("Re-issuing login", file=sys.stderr)
                        self.login()
                        if (self.verbose):
                            print("Re-running command", file=sys.stderr)
                        return(self.run_command(url, filename, returnstring))
                    else:
                        raise(e)
                except Exception as e:
                    raise(e)
            except Exception as e:
                raise(e)

        except ConnectionRefusedError as e:
            print("Connection refused: " + str(e), file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as e:
            if str(e.reason) == str('[Errno 111] Connection refused'):
                print("URL Error: " + str(e), file=sys.stderr)
                sys.exit(1)
            raise(e)
        except Exception as e:
            raise(e)

    #==========================================================================
    # DEFINE COMMAND FUNCTIONS
    #==========================================================================


    #--------------------------------------------------------------------------
    #
    # This command audits the terapack/magazine given the input partition,
    # elementType and teraPackOffset.
    #
    def audit_tera_pack(self, partition, elementType, teraPackOffset):

        itemString = "Partition '" + partition + "' " +                        \
                     "ElementType '" + elementType + "' "                      \
                     "TeraPackOffset '" + teraPackOffset + "'"

        url = self.baseurl + "/inventory.xml?action=audit" +                   \
                             "&partition=" + partition +                       \
                             "&elementType=" + elementType +                   \
                             "&TeraPackOffset=" + teraPackOffset

        try:
            # wait for an inventory command in progress to complete
            firstTime = False
            while (not self.check_command_progress("inventory", False)):
                # wait 1 seconds before retrying
                if not firstTime:
                    print("\nWaiting for pending inventory command to complete...",
                        end='')
                    firstTime = True
                print(".", end='')
                time.sleep(1)
            if firstTime:
                print()     # newline
        except Exception as e:
            raise(e)

        # audit the tera pack / magazine
        try:
            print("\nAuditing " + itemString + "...", end='')
            sys.stdout.flush()
            audittree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in audittree:
                if child.tag == "status":
                    status = child.text.rstrip()
                if child.tag == "message":
                    message = child.text.rstrip()
            if status != "OK":
                print("failure")
                raise(Exception("Failure auditing " + itemString + ": " +  \
                                message))

            # poll for audit to be done
            try:
                while (not self.check_command_progress("inventory", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
                print("OK")
                sys.stdout.flush()
            except Exception as e:
                raise(Exception("inventory audit progress Error: " + str(e)))
        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Check command progress
    # Returns True if no pending commands; False otherwise
    # verbose=True will cause messages regarding success/failure to be printed
    #
    def check_command_progress(self, command, verbose):

        try:
            url = self.baseurl + "/" + command + ".xml?progress"
            tree = self.run_command(url)
            statusRec = tree.find("status")
            messageRec = tree.find("message")
            status = statusRec.text.strip()
            message = messageRec.text.strip()
            if (status == "OK"):
                if verbose:
                    print("The '" + command +
                          "' command has no pending commands. Status=" +
                          status.strip())
                    sys.stdout.flush()
                return(True)
            elif (status == "FAILED"):
                errorText  = "Error: The '" + command + "' command FAILED\n"
                errorText += message
                raise(Exception(errorText))
            else:
                if verbose:
                    print("New commands may not be submitted. ",
                          "The '" + command +
                          "' command has a status of: ", status)
                    sys.stdout.flush()
                return(False)

        except Exception as e:
            if (self.verbose):
                print("check_command_progress Error: " + str(e), file=sys.stderr)
                traceback.print_exc()
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Check to see there's a "traces" command in progress. Wait up to waittime
    # minutes for the command to complete.
    #
    def check_for_traces_in_progress(self, waittime):

        # check for traces command in progress and wait until done
        try:
            if (not self.check_command_progress("traces", False)):
                print("There's a traces command in progress. Will wait up to "
                      + str(waittime) + " minutes retrying.", end='')
                sys.stdout.flush()
                count = 0
                while (not self.check_command_progress("traces", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    count += 1
                    # wait 4 seconds before retrying
                    time.sleep(4)
                    if (count > ((60 * waittime) / 4)):    # five minutes
                        print("\nGiving up. Retry this command later.")
                        sys.stdout.flush()
                        sys.exit(1)
                print()
        except Exception as e:
            print("traces progress Error: " + str(e), file=sys.stderr)
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Check to see there's security audit in progress
    # Returns True if security audit is running; False otherwise
    #
    def check_security_audit_in_progress(self):

        try:
            status, message = self.securityauditstatus(True)
        except Exception as e:
            if (self.verbose):
                print("check_security_audit_command_progress Error: " + str(e),
                      file=sys.stderr)
                traceback.print_exc()
            raise(e)

        if (message == "Security audit is not running."):
            return (False)
        else:
            return (True)


    #--------------------------------------------------------------------------
    #
    # Checks for system error ("error" record) or syntax error ("syntaxError"
    # record) and raises an exception if it found any; otherwise it returns
    # false. The exception will contain the system/syntax error message.
    #
    # Raises the following exceptions:
    # - Exception: system/syntax error
    # - SpectraLogicLoginError: no active session found
    #
    def check_for_error(self, tree):

        try:
            # If there aren't any records, then no errors
            if len(tree) == 0:
                return(False)

            # Check for system error
            if tree.tag == "error":
                for child in tree:
                    if (child.text.find("Error: No active session found.") >= 0):
                        raise(SpectraLogicLoginError("Error: No active session found."))
                errstr = ""
                errstr = self.get_all_text(tree, errstr)
                raise(Exception(errstr))

            # Check for syntax error
            if tree.tag == "syntaxError":
                errstr = ""
                errstr = self.get_all_text(tree, errstr)
                raise(Exception(errstr))

        except SpectraLogicLoginError as e:
            raise(e)

        except Exception as e:
            if (self.verbose):
                print("check_for_error Error: " + str(e), file=sys.stderr)
                traceback.print_exc()
            raise(e)

        return(False)


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
                self.long_listing(tree, 0)
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
            sys.stdout.flush()
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
                sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns detailed information about each of the drives in the library.
    #
    def drivelist(self, extended=False):

        if extended:
            driveFormat = '{:25} {:11} {:15} {:12} {:25} {:15} {:15} {:13} {:11} {:25} {:9} {:7} {:6} {:9} {:10} {:8} {:14} {:15}'
        else:
            driveFormat = '{:25} {:11} {:15} {:12} {:25} {:15} {:15} {:13} {:11} {:25} {:9} {:7} {:6} {:10} {:8} {:14} {:15}'

        try:
            url  = self.baseurl + "/driveList.xml?action=list"
            tree = self.run_command(url)
            print("\nDrive List")
            print("----------")
            if self.longlist:
                if extended:
                    for drive in tree:
                        for element in drive:
                            if element.tag == "ID":
                                myid = element.text.rstrip()
                                loadCount   = self.get_drive_load_count(myid)
                                newElt      = xml.etree.ElementTree.Element("loadCount")
                                newElt.text = str(loadCount)
                                drive.append(newElt)
                self.long_listing(tree, 0)
                sys.stdout.flush()
                return
            if extended:
                print(driveFormat.format("ID", "DriveStatus", "Partition",
                          "PartDriveNum", "DriveType",
                          "SerialNum", "MfrSerialNum", "DriveFirmware",
                          "DCMFirmware", "WWN", "FibreAddr",
                          "LoopNum", "Health", "LoadCount",
                          "SparedWith", "SpareFor", "SparePotential",
                          "FirmwareStaging"))
                print(driveFormat.format("-------------------------", "-----------",
                          "---------------", "------------",
                          "-------------------------", "---------------",
                          "---------------", "-------------", "-----------",
                          "-------------------------", "---------", "-------",
                          "------", "---------", "----------", "--------",
                          "--------------", "---------------"))
            else:
                print(driveFormat.format("ID", "DriveStatus", "Partition",
                          "PartDriveNum", "DriveType",
                          "SerialNum", "MfrSerialNum", "DriveFirmware",
                          "DCMFirmware", "WWN", "FibreAddr",
                          "LoopNum", "Health", "SparedWith", "SpareFor",
                          "SparePotential", "FirmwareStaging"))
                print(driveFormat.format("-------------------------",
                          "-----------", "---------------", "------------",
                          "-------------------------", "---------------",
                          "---------------", "-------------", "-----------",
                          "-------------------------", "---------", "-------",
                          "------", "----------", "--------",
                          "--------------", "---------------"))
            sys.stdout.flush()
            for drive in tree:
                myid = status = partition = paritionDriveNum = ""
                driveType = serialNum = manuSerialNum = driveFW = ""
                dcmFW = wwn = fibreAddress = loopNum = health = ""
                sparedWith = spareFor = sparePotential = ""
                firmwareStaging = ""
                loadCount = ""
                prettyWWN = ""
                for element in drive:
                    if element.tag == "ID":
                        myid = element.text.rstrip()
                        # TODO #####
                        # Getting "returned an invalid load count" when running
                        # the command while testing on NERF. So comment out for
                        # now. Todd sent email to Spectra. 10/16/18
                        # 10/17/18: Spectra believes that the problem is because
                        # the drive has never been loaded since the firmware
                        # update. So told me to load/unload.
                        # 01/18/19: problem still exists.
                        # 04/10/19: Spectra believes this is fixed in the Casle
                        # release scheduled for June/July 2019
                        if extended:
                            loadCount = self.get_drive_load_count(myid)
                    elif element.tag == "driveStatus":
                        status = element.text.rstrip()
                    elif element.tag == "partition":
                        partition = element.text.rstrip()
                    elif element.tag == "partitionDriveNumber":
                        paritionDriveNum = element.text.rstrip()
                    elif element.tag == "driveType":
                        driveType = element.text.rstrip()
                    elif element.tag == "serialNumber":
                        serialNum = ""
                        if element.text is not None:
                            serialNum = element.text.rstrip()
                    elif element.tag == "manufacturerSerialNumber":
                        manuSerialNum = element.text.rstrip()
                    elif element.tag == "driveFirmware":
                        driveFW = element.text.rstrip()
                    elif element.tag == "dcmFirmware":
                        dcmFW = element.text.rstrip()
                    elif element.tag == "wwn":
                        wwn = ""
                        if element.text is not None:
                            wwn = element.text.rstrip()
                            # make the wwn's pretty for Todd; he likes colons better
                            # than the default space delimiters.
                            prettyWWN = wwn.replace(" ", ":")
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
                           dcmFW, prettyWWN, fibreAddress, loopNum, health, loadCount,
                           sparedWith, spareFor, sparePotential,
                           firmwareStaging) )
                sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Attempts to reestablish the Ethernet connection and update the stored
    # status information for each EtherLib connection.
    #
    def etherlibrefresh(self):

        if not self.check_command_progress("etherLibStatus", True):
            raise(Exception("Will not issue etherLibStatus refresh command due \
            to pending commands."))

        try:
            url  = self.baseurl + "/etherLibStatus.xml?action=refresh"
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The etherLibStatus refresh command has been submitted: "
                      + message)
                sys.stdout.flush()

            # poll for etherLibStatus refresh to be done
            try:
                while (not self.check_command_progress("etherLibStatus", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                raise(Exception("etherLibStatus refresh progress Error: " + str(e)))

            print("\nThe etherLibStatus refresh command has completed.")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


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
                self.long_listing(tree, 0)
                return
            print(listFormat. \
                format("ID", "Target", "Connected"))
            print(listFormat. \
                format("-----", "----------", "---------"))
            sys.stdout.flush()
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
                sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Gathers the specified security audit log to the LCM.
    #
    # See getSecurityAuditLogNames to determine the names of the bzip2 files
    # currently stored on the RCM.
    #
    # Notes:
    #     * This command was added with BlueScale12.8.01.
    #     * This command is only supported on TFinity libraries.
    #
    def gathersecurityauditlog(self, filename):

        # Check for traces command in progress and wait up to 5 minutes for it
        # to be done
        try:
            self.check_for_traces_in_progress(5) #wait 5 minutes
        except Exception as e:
            print("traces progress Error: " + str(e), file=sys.stderr)
            raise(e)

        # Look for the file and see if it's been gathered
        gathered = "no"
        logName = "<invalid>"
        found = False
        try:
            url  = self.baseurl + "/traces.xml?action=getSecurityAuditLogNames"
            tree = self.run_command(url)

            # Look for all the log names
            for secAuditNames in tree:
                for files in secAuditNames:
                    logName = files.find("logName").text.rstrip()
                    if (logName == filename):
                        found = True
                        gathered = files.find("gathered").text.rstrip()
        except Exception as e:
            print("getSecurityAuditLogNames Error: " + str(e), file=sys.stderr)
            raise(e)

        # Did we find the file? If not, then can't continue.
        if not found:
            print("File '" + filename + "' not found. Cannot gather the " +
                  "specified security audit log.")
            sys.stdout.flush()
            return

        # Is the file already on the LCM (i.e. "gathered")?
        if gathered == "yes":
            print("File '" + filename + "' is already gathered to the LCM.")
            sys.stdout.flush()
            return

        # If the file hasn't been gathered (i.e. downloaded from the RCM),
        # then gather it.
        try:
            print("Gathering the security audit log for file: " + filename)
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=gatherSecurityAuditLog&name=" + filename
            tree = self.run_command(url)
        except Exception as e:
            print("gatherSecurityAuditLog Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


        # poll for gatherSecurityAuditLog to be done
        try:
            while (not self.check_command_progress("traces", False)):
                # put out an in progress 'dot'
                print(".", end='')
                sys.stdout.flush()
                # wait 4 seconds before retrying
                time.sleep(4)
            print("\nGather is complete")
            sys.stdout.flush()
        except Exception as e:
            print("traces gatherSecurityAuditLog progress Error: " + str(e),
                  file=sys.stderr)
            sys.stdout.flush()
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Generates a new AutoSupport Log (ASL) file
    #
    def generateasl(self):

        if not self.check_command_progress("autosupport", True):
            raise(Exception(
                "Will not issue generateasl command due to pending commands."))

        try:
            url  = self.baseurl + "/autosupport.xml?action=generateASL"
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The autosupport generateASL command has been submitted: " + message)
                sys.stdout.flush()

            # poll for autosupport generateASL to be done
            try:
                while (not self.check_command_progress("autosupport", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                raise(Exception("autosupport generateASL progress Error: " +  \
                                str(e)))

            print("\nThe autosupport generateASL command has completed.")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Generate a new drive trace file
    #
    # Notes:
    # - This action was added with BlueScale12.4.1.
    # - This command is not supported for TS11x0 drives.
    # - This command can only be used for LTO-5 and later generation drives.
    #
    def generatedrivetrace(self, driveID):

        # validate the drive ID
        url  = self.baseurl + "/driveList.xml?action=list"
        tree = self.run_command(url)
        foundIt = False
        for element in tree:
            for drive in element:
                if drive.tag == "ID":
                    tempDrive = drive.text.strip()
                    if (tempDrive == driveID):
                        foundIt = True

        if not foundIt:
            raise(Exception("Error: The input drive (" + driveID +
                            ") is not a valid drive."))

        if driveID.find("LTO") == -1:
            raise(Exception("Error: The input drive (" + driveID +
                  ") is not a valid LTO drive. This command only works on LTO drives."))

        if not self.check_command_progress("driveList", True):
            raise(Exception(
                "Will not issue generatedrivetrace command due to pending commands."))

        try:
            url  = self.baseurl + "/driveList.xml?action=generateDriveTraces&driveTracesDrives=" + driveID
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The driveList generateDriveTraces command has been submitted: " + message)
                sys.stdout.flush()

            # poll for driveList generateDriveTraces to be done
            try:
                while (not self.check_command_progress("driveList", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                raise(Exception(
                    "driveList generateDriveTraces progress Error: " + str(e)))

            print("\nThe driveList generateDriveTraces command has completed.")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified ASL file from the library
    # Outputs a filename in the current working directory that is the ASL file
    # name with "_" replacing spaces and ending in .zip.
    #
    def getaslfile(self, filename):

        try:
            # Replace the spaces in the file name with %20 using a urllib module
            url  = self.baseurl + "/autosupport.xml?action=getASL&name=" + urllib.parse.quote(filename)

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the ASL name except:
            # - replace spaces with underscores
            # - append with .zip since it's a zip file.
            outputFilename = filename.replace(" ","_") + ".zip"
            f = open(outputFilename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + outputFilename + "'")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the AutoSupport Log (ASL) file names currently stored
    # on the ibrary.
    #
    def getaslnames(self):

        try:
            url  = self.baseurl + "/autosupport.xml?action=getASLNames"
            tree = self.run_command(url)
            print("\nAutoSupport Log (ASL) File Names: <HardwareID Date Time>")
            print(  "--------------------------------------------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            for aslNames in tree:
                if len(aslNames) == 0:
                    print("None - Perhaps you need to generate some?")
                    sys.stdout.flush()
                    return
                for aslName in aslNames:
                    if aslName.tag == "ASLName":
                        print(aslName.text.rstrip())
                        sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieves the audit results collected by the command
    # inventory.xml?action=audit command. The audit results can only be
    # retrieved once.
    #
    # Notes:
    #     * This command is only supported on TFinity libraries.
    #     * This command was added with BlueScale12.7.00.01.
    #
    def getauditresults(self):

        listFormat = '{:8} {:6} {:10} {:6} {:7} {:17} {:19}'

        try:
            # wait for a inventory command in progress to complete
            firstTime = False
            while (not self.check_command_progress("inventory", False)):
                # wait 1 seconds before retrying
                if not firstTime:
                    print("Waiting for pending inventory command to complete...",
                        end='')
                    firstTime = True
                print(".", end='')
                time.sleep(1)
            if firstTime:
                print()     # newline
        except Exception as e:
            raise(e)

        # Get the audit results
        try:
            print("Getting the audit results...", end='')
            sys.stdout.flush()
            url = self.baseurl + "/inventory.xml?action=getAuditResults"
            tree = self.run_command(url)

            # DEBUG
            #tree = self.create_audit_results_XML_records()


            if (len(tree) == 0):
                print("None")
                sys.stdout.flush()
                return

            # parse the results
            actualList = []
            contentsMatch = "yes"
            count = 0
            expectedList = []
            for child in tree:
                elementType = child.find("elementType").text.rstrip()
                offset = child.find("offset").text.rstrip()
                barcode = child.find("barcode").text.rstrip()
                contentsMatch = child.find("contentsMatch").text.rstrip()
                for results in child:
                    if (results.tag == "expectedContents"):
                        for slot in results:
                            expectedList.append(slot)
                    if (results.tag == "actualContents"):
                        for slot in results:
                            actualList.append(slot)
            print("TeraPack (" + barcode + "):")


            # Use the magazine barcode to figure out what kind of magazine
            # we're dealing with (10 slot vs 9 slot).
            try:
                numSlots = self.get_magazine_slot_count(barcode)
            except Exception as e:
                numSlots = 0
            if (numSlots == 0):
                raise(Exception("Internal Error: Unable to get the number " +  \
                                "of slots in TeraPack '" + barcode + "'"))

            # If getAuditResults is reporting a match problem, send out a
            # message highlighting this information. When contentsMatch is "no"
            # then we should find expectedContents records.
            if (contentsMatch.lower() == "no"):
                print("\n*** The library is reporting an inventory MISMATCH " +\
                      "on this TeraPack (" + barcode + ") ***\n")
                if (len(expectedList) == 0):
                    # I don't think I want to throw an exception here because I
                    # want the audit to continue.  Instead put out error
                    # messages.
                    print("Internal Error: No expectedContents records " +     \
                          "were returned in the Audit Results even though " +  \
                          "the library reported a MISMATCH. Investigation " +  \
                          "needed.")
            else:
                print("")

            # print header
            print(listFormat.
                format("SlotType", "Offset", "MagBarcode", "Match?", "SlotNum",
                       "SlotActualBarcode", "SlotExpectedBarcode"))
            print(listFormat.
                format("--------", "------", "----------", "------",
                       "-------", "-----------------", "-------------------"))

            reportedSlotList = []
            if (contentsMatch.lower() == "no"):
                # For each slot in the autual list, look for a match in the
                # expected list.  Matching on slot number.  If found, print.
                for slot in actualList:
                    slotNumber = slot.find("number").text.rstrip()
                    slotBarcode = slot.find("barcode").text.rstrip()
                    reported = False
                    for expslot in expectedList:
                        expNumber = expslot.find("number").text.rstrip()
                        expBarcode = expslot.find("barcode").text.rstrip()
                        if (expNumber == slotNumber):
                            if (expBarcode == slotBarcode):
                                # We found a match!
                                print(listFormat.
                                    format(elementType, offset, barcode, "yes",
                                           slotNumber, slotBarcode, expBarcode))
                                sys.stdout.flush()
                            else:
                                # The barcodes don't match; report it.
                                print(listFormat.
                                    format(elementType, offset, barcode, "no",
                                           slotNumber, slotBarcode, expBarcode))
                                sys.stdout.flush()
                            reported = True
                            reportedSlotList.append(slotNumber)
                            break
                    if (not reported):
                        # We didn't find actual slot item in the expected list.
                        # This means that we encountered a new item.
                        print(listFormat.
                            format(elementType, offset, barcode, "no",
                                   slotNumber, slotBarcode, "<<NEW>>"))
                        sys.stdout.flush()
                        reportedSlotList.append(slotNumber)

                # Is there anything on the expected list that wasn't on the
                # actual list??
                for expslot in expectedList:
                    expNumber = expslot.find("number").text.rstrip()
                    expBarcode = expslot.find("barcode").text.rstrip()
                    reported = False
                    for slot in actualList:
                        slotNumber = slot.find("number").text.rstrip()
                        slotBarcode = slot.find("barcode").text.rstrip()
                        if (expNumber == slotNumber):
                            reported = True
                            break
                    if (not reported):
                        # This means that we encountered an item that went
                        # missing
                        print(listFormat.
                            format(elementType, offset, barcode, "no",
                                   expNumber, "<<MISSING>>", expBarcode))
                        sys.stdout.flush()
                        reportedSlotList.append(expNumber)

                # Now for one other case.  Lets see if every slot was reported.
                # If a slot hasn't been reported, then we need to report that!
                for i in range(1, numSlots):
                    match = False
                    for item in reportedSlotList:
                        if (item == str(i)):
                            match = True
                            break
                    if (not match):
                        print(listFormat.
                            format(elementType, offset, barcode, "no",
                                   str(i), "<<NOT REPORTED>>", "<<NOT REPORTED>>"))
                        sys.stdout.flush()
                        reportedSlotList.append(str(i))
            else:
                # No Mismatch was reported by the library. So, just print the
                # actualList.
                for slot in actualList:
                    slotNumber = slot.find("number").text.rstrip()
                    slotBarcode = slot.find("barcode").text.rstrip()
                    print(listFormat.
                        format(elementType, offset, barcode, "yes",
                               slotNumber, slotBarcode, slotBarcode))
                    sys.stdout.flush()
                    reportedSlotList.append(slotNumber)

            # Let's be paranoid and verify that:
            # - we have the expected number of slots in the actual list.
            # - the number of items reported is the number of slots
            # DKM: Don't think we need this paranoia. Commenting out for now.
            #      It could be the case that the TaraPack is rightfully not
            #      full (i.e. a cart in every slot). (TODO)
            #if (numSlots != len(actualList)):
            #    print("MISMATCH Error: library returned '" +                   \
            #          str(len(actualList)) + "' items for this TeraPack; " +   \
            #          "expected '" + str(numSlots) + "' items.")
            #if (numSlots != len(reportedSlotList)):
            #    print("MISMATCH Error: reported '" +                           \
            #          str(len(reportedSlotList)) + "' items for this TeraPack; " +  \
            #          "expected " + str(numSlots) + " items.")

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified zip file containing Controller Area Network (CAN)
    # logs from the Library Control Module (LCM).
    #
    # Outputs a filename in the current working directory that is the CAN Log
    # file name.
    #
    # The getCanLog action is only supported for libraries that are using
    # the Spectra LS module as the LCM. Issuing this command to a library that
    # uses a Spectra PC as the LCM returns an empty list.

    def getcanlog(self, filename):

        try:
            print("Getting the CAN log file '" + filename + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getCanLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the motion log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the zip files containing the Controller Area Network
    # (CAN) logs that are currently stored in the Library Control Module (LCM).
    # The CAN logs collected for each day are zipped and stored on the hard
    # drive in the LCM. Each zip filename includes the date it was created.
    #
    # The getCanLogNames command is only supported for libraries that are using
    # the Spectra LS module as the LCM. Issuing this command to a library that
    # uses a Spectra PC as the LCM returns an empty list.
    #
    def getcanlognames(self):

        try:
            url  = self.baseurl + "/traces.xml?action=getCanLogNames"
            tree = self.run_command(url)
            print("\nController Area Network (CAN) Log File Names")
            print(  "--------------------------------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            for names in tree:
                if len(names) == 0:
                    print("None - This command is only supported for libraries"+
                          " that are using the Spectra LS module as the LCM.")
                    sys.stdout.flush()
                    return
                for name in names:
                    if name.tag == "logName":
                        print(name.text.rstrip())
                        sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Using an inputed driveID (format from drivelist ID), this routine will
    # get the drive load count for the driveID. Upon success, it returns the
    # load count, otherwise, it returns the string "INVALID".
    #
    def get_drive_load_count(self, driveID):

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
    # Retrieves the last drive trace file generated by the generateDriveTraces
    # action. Upon success, a file named "drivetraces.zip" will be written to
    # the current working directory.
    #
    def getdrivetraces(self):

        try:
            url  = self.baseurl + "/driveList.xml?action=getDriveTraces&driveTracesGetType=download"

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            f = open('drivetraces.zip', 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: 'drivetraces.zip'")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified zip file containing kernel logs from the Library
    # Control Module (LCM).
    #
    # Outputs a filename in the current working directory that is the Kernel
    # Log file name.
    #
    # The getKernelLog command is only supported for libraries that are using
    # the Spectra LS module as the LCM. Issuing this command to a library that
    # uses a Spectra PC as the LCM returns an empty list.

    def getkernellog(self, filename):

        try:
            print("Getting the kernel log file '" + filename + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getKernelLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the motion log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the zip files containing the kernel logs that are
    # currently stored in the Library Control Module (LCM). The kernel logs
    # collected for each day are zipped and stored on the hard drive in the
    # LCM. Each zip filename includes the date it was created.
    #
    # The getKernelLogNames command is only supported for libraries that are
    # using the Spectra LS module as the LCM. Issuing this command to a library
    # that uses a Spectra PC as the LCM returns an empty list.
    #
    def getkernellognames(self):

        try:
            url  = self.baseurl + "/traces.xml?action=getKernelLogNames"
            tree = self.run_command(url)
            print("\nKernel Log File Names")
            print(  "---------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            for names in tree:
                if len(names) == 0:
                    print("None - This command is only supported for libraries"+
                          " that are using the Spectra LS module as the LCM.")
                    sys.stdout.flush()
                    return
                for name in names:
                    if name.tag == "logName":
                        print(name.text.rstrip())
                        sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns the number of slots in the magazine based on the magazine's
    # barcode.
    #
    # The TeraPack barcodes are different between LTO TeraPacks and TS11x0
    # TeraPacks. The first 2 letters will differ and will always be the same
    # for the Magazine type.
    #    - LTO TeraPacks/magazine barcode start with a "LU"
    #    - TS11x0 TeraPacks/magazine barcode start with a "JU"
    # Cleaning TeraPacks also have a unique barcode as well for each media
    # type.
    #    - LTO cleaning tape TeraPacks/magazine barcode start with a "CL"
    #    - TS11x0 cleaning tape TeraPacks/magazines barcode start with a "CJ"
    #
    # So....since
    #    - LTO    TaraPacks/magazines have 10 slots.
    #    - TS11x0 TaraPacks/magazines have  9 slots.
    # Then:
    #    - 10 slots in an LTO TeraPack/magazine with "LU"
    #    - 10 slot LTO cleaning TeraPack/magazine with "CL"
    #    -  9 slots in a TS11x0 TeraPack/magazine with "JU"
    #    -  9 slots TS11x0 cleaning TeraPack/magazine with "CJ"
    #
    # Returns 0 upon exception
    #
    def get_magazine_slot_count(self, barcode):

        try:
            if (barcode.startswith("LU")):
                return(10)
            elif (barcode.startswith("CL")):
                return(10)
            elif (barcode.startswith("JU")):
                return(9)
            elif (barcode.startswith("CJ")):
                return(9)
        except Exception as e:
            print("get_magazine_slot_count Error: " + str(e), file=sys.stderr)
            return(0)


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified Motion Log file from the library.
    # Outputs a filename in the current working directory that is the Motion
    # Log file name.
    #
    # NOTE: This API is not documented in the June 2017 (version K) of the
    # Spectra XML reference document.  Got the information from SpectraLogic
    # support.
    #
    def getmotionlogfile(self, filename):

        # check for traces command in progress and wait until done
        try:
            if (not self.check_command_progress("traces", False)):
                print("There's a traces command in progress." +
                      "Will wait up to 5 minutes retrying.")
                sys.stdout.flush()
                count = 0
                while (not self.check_command_progress("traces", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    count += 1
                    # wait 4 seconds before retrying
                    time.sleep(4)
                    if (count > ((60 * 5) / 4)):    # five minutes
                        print("\nGiving up. Retry this command later.")
                        sys.stdout.flush()
                        sys.exit(1)
                print()
        except Exception as e:
            print("traces progress Error: " + str(e), file=sys.stderr)
            raise(e)


        # getFullMotionLogNames
        try:
            # Check to see if the file has been gathered (i.e. downloaded from
            # RCM)
            print("Checking to see if the file needs to be gathered..." +
                  "i.e. downloaded from RCM")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getFullMotionLogNames"
            tree = self.run_command(url)

            for child in tree:
                if len(child) == 0:
                    # None
                    raise(Exception("Error: No motion log files exist"))

                foundIt = False;
                if child.tag == "motionLogNames":
                    for item in child:
                        if item.tag == "File":
                            logName = gathered = ""
                            for fileEntry in item:
                                if fileEntry.tag == "logName":
                                    logName = fileEntry.text.rstrip()
                                elif fileEntry.tag == "gathered":
                                    gathered = fileEntry.text.rstrip()
                            if logName == filename:
                                # found it!
                                foundIt = True;
                                break
                if not foundIt:
                    raise(Exception("Error: File not found. File=" + filename))

        except Exception as e:
            print("getFullMotionLogNames Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


        # gatherFullMotionLog
        try:
            # If the file hasn't been gathered (i.e. downloaded from the RCM),
            # then gather it.
            if gathered == "no":
                print("Gathering the full motion log for file: " + filename)
                sys.stdout.flush()
                url  = self.baseurl + "/traces.xml?action=gatherFullMotionLog&name=" + filename
                tree = self.run_command(url)
        except Exception as e:
            print("gatherFullMotionLog Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


        # poll for gatherFullMotionLog to be done
        try:
            while (not self.check_command_progress("traces", False)):
                # put out an in progress 'dot'
                print(".", end='')
                sys.stdout.flush()
                # wait 4 seconds before retrying
                time.sleep(4)
            print("\nGather is complete")
            sys.stdout.flush()
        except Exception as e:
            print("traces gatherFullMotionLog progress Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


        # getFullMotionLog
        try:
            print("Getting the full motion log file '" + filename + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getFullMotionLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the motion log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            print("getmotionlogfile Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the Motion Log file names currently stored on the
    # library.
    #
    # NOTE: This API is not documented in the June 2017 (version K) of the
    # Spectra XML reference document.  Got the information from SpectraLogic
    # support.
    #
    def getmotionlognames(self):

        fmt = '{:42} {:9}'

        try:
            url  = self.baseurl + "/traces.xml?action=getFullMotionLogNames"
            tree = self.run_command(url)
            print("\nMotion Log File Names")
            print(  "---------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            print(fmt.format("LogFileName", "Gathered?"))
            print(fmt.format("------------------------------------------",
                             "---------"))
            sys.stdout.flush()

            for child in tree:
                if len(child) == 0:
                    print("None")
                    sys.stdout.flush()
                    return
                if child.tag == "motionLogNames":
                    for item in child:
                        if item.tag == "File":
                            logName = gathered = ""
                            for fileEntry in item:
                                if fileEntry.tag == "logName":
                                    logName = fileEntry.text.rstrip()
                                elif fileEntry.tag == "gathered":
                                    gathered = fileEntry.text.rstrip()
                            print(fmt.format(logName, gathered))
                            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified zip file containing Quad Interface Processor (QIP)
    # logs from the Library Control Module (LCM).
    #
    # Outputs a filename in the current working directory that is the QIP Log
    # file name.
    #
    # The getQIPLog action is only supported for libraries that are using
    # the Spectra LS module as the LCM. Issuing this command to a library that
    # uses a Spectra PC as the LCM returns an empty list.
    #
    # Note: Informed 11/2018 that this is deprecated.
    def getqiplog(self, filename):

        try:
            print("Getting the QIP log file '" + filename + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getQIPLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the QIP log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            raise


    #--------------------------------------------------------------------------
    #
    # Returns a list of the zip files containing the Quad Interface Processor
    # (QIP) logs that are currently stored in the Library Control Module (LCM).
    # The QIP logs collected for each day are zipped and stored on the hard
    # drive in the LCM. Each zip filename includes the date it was created.
    #
    # The getQIPLogNames command is only supported for libraries that are using
    # the Spectra LS module as the LCM. Issuing this command to a library that
    # uses a Spectra PC as the LCM returns an empty list.
    #
    # Note: Informed 11/2018 that this is deprecated.
    def getqiplognames(self):

        try:
            url  = self.baseurl + "/traces.xml?action=getQIPLogNames"
            tree = self.run_command(url)
            print("\nQuad Interface Processor (QIP) Log File Names")
            print(  "---------------------------------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            for names in tree:
                if len(names) == 0:
                    print("None - This command is only supported for libraries"+
                          " that are using the Spectra LS module as the LCM.")
                    sys.stdout.flush()
                    return
                for name in names:
                    if name.tag == "logName":
                        print(name.text.rstrip())
                        sys.stdout.flush()

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Retrieves the specified bzip2 Security Audit Log file from the library.
    # This command will verify that the specified Security Audit Log file
    # exists in the Robotics Control Module (RCM) and/or the Library Control
    # Module (LCM). If it's missing from the RCM, then nothing can be done.
    # If it's missing from the LCM, then it will download (i.e. gathered) from
    # the RCM to the LCM). Next, it will pull it from the LCM and  store it in
    # the current working directory.
    #
    # Outputs a filename in the current working directory that is the Security
    # Audit Log file name.
    #
    # Notes:
    #     * This command was added with BlueScale12.8.01.
    #     * This command is only supported on TFinity libraries.
    #
    def getsecurityauditlogfile(self, filename):

        # Function gathersecurityauditlog does a number of steps to validate
        # the filename and gather the security audit log.  These steps include:
        #   - Check for traces command in progress and wait up to 5 minutes for
        #     it to be done
        #   - Look for the file and see if it's been gathered
        #   - Did we find the file? If not, then can't continue.
        #   - Is the file already on the LCM (i.e. "gathered")? If not,
        #     downloaded it from the RCM using gatherSecurityAuditLog.
        #   - poll for gatherSecurityAuditLog to be done
        try:
            self.gathersecurityauditlog(filename)
        except Exception as e:
            print("gathersecurityauditlog Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)

        # now get the security audit log
        try:
            print("Getting the Security Audit log file '" + filename + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?action=getSecurityAuditLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the binary data to a file in the current working directory.
            # The name of the file is the same as the motion log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            print("getsecurityauditlogfile Error: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)


    #--------------------------------------------------------------------------
    #
    # The getsecurityauditlognames command returns a list of the security audit
    # logs on the Robotics Control Modules (RCM) with an attribute to indicate
    # which ones are also gathered and present on the Library Control Module
    # (LCM). The LCM keeps no more than five security audit logs.
    #
    # There are two types of security audit logs: securityAuditInterim and
    # securityAudit.
    #     * securityAuditInterim.serial_number.YYYY-MM-DDThhmmss.sss.bz2
    #       Contains the logs collected between security audits. This includes
    #       information such as doors being opened.
    #     * securityAudit.serial_number.YYYY-MM-DDThhmmss.sss.bz2
    #       Contains security audit logs. This includes information such as
    #       missing TeraPack magazines or tapes in unexpected slots.
    #     * The log name for both types of logs contains the serial number of
    #       the library on which the security audit ran.
    #     * The log name contains a date (YYYY-MM-DDThhmmss.sss) which for an
    #       interim security audit indicates the time and date the last audit
    #       ended and for a security audit indicates the time and date that the
    #       audit began.
    #           YYYY is the year,
    #           MM is the two-digit month,
    #           DD is the two-digit day,
    #           hh is the 24-hour hour,
    #           mm is the minute, and
    #           ss.sss is the seconds and milliseconds.
    #
    # Notes:
    #     * This command was added with BlueScale12.8.01.
    #     * This command is only supported on TFinity libraries.
    #
    def getsecurityauditlognames(self):

        fmt = '{:60} {:7}'

        # check for traces command in progress and wait up to 5 minutes for it
        # to be done
        try:
            self.check_for_traces_in_progress(5) #wait 5 minutes
        except Exception as e:
            print("traces progress Error: " + str(e), file=sys.stderr)
            raise(e)

        try:
            url  = self.baseurl + "/traces.xml?action=getSecurityAuditLogNames"
            tree = self.run_command(url)
            print("\nSecurity Audit Log Names")
            print(  "------------------------")
            sys.stdout.flush()
            if self.longlist:
                self.long_listing(tree, 0)
                return

            print(fmt.format("LogName", "On LCM?"))
            print(fmt.format(
                "-----------------------------------------------------------",
                "-------"))
            sys.stdout.flush()

            # Look for all the log names
            for secAuditNames in tree:
                for files in secAuditNames:
                    logName = files.find("logName").text.rstrip()
                    gathered = files.find("gathered").text.rstrip()
                    print(fmt.format(logName, gathered))
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns the status of all TeraPack Access Ports (TAP)s.
    #
    def gettapstate(self):

        fmt = '{:10} {:6} {:9} {:15} {:14} {:18} {:14}'
        tapDevices = ["mainTop", "mainBottom", "leftBulk", "rightBulk"]
        tapDrawerCount = 14

        print("\nTeraPack Access Ports Status")
        print(  "----------------------------")

        if not self.longlist:
            print(fmt. \
                format("TAPDevice", "Drawer", "DoorOpen", "MagazinePresent",
                       "MagazineSeated", "MagazineType", "RotaryPosition"))
            print(fmt. \
                format("----------", "------", "---------",
                       "---------------", "--------------",
                       "------------------", "--------------"))
            sys.stdout.flush()

        # build a url for each tapdevice/drawer combination
        for device in tapDevices:                   # for each TAP device type
            for i in range(1, tapDrawerCount+1):    # for each drawer
                doorOpen = magazinePresent = magazineSeated = "<unknown>"
                magazineType = rotaryPosition = "<unknown>"

                # For the mainTop and mainBottom parameters, the value for
                # drawerNumber is always 1.
                if ( ((device == "mainTop") or (device == "mainBottom"))
                       and
                     (i > 1) ):
                    continue

                try:
                    url  = self.baseurl + \
                           "/mediaExchange.xml?action=getTAPState&TAPDevice=" + \
                           device + "&drawerNumber=" + str(i)
                    tree = self.run_command(url)
                except Exception as e:
                    # It appears that we get an exception if a particular
                    # device/drawer combination isn't present in our system.
                    # This is not an error. Continue to the next item.
                    print(fmt. \
                        format(device, str(i), doorOpen, magazinePresent,
                               magazineSeated, magazineType, rotaryPosition))
                    sys.stdout.flush()
                    continue

                # Perhaps when a device/drawer combination isn't present in our
                # system, we'll get no items.  Check for that and if so, just
                # move onto the next one.
                if len(tree) == 0:
                    print(fmt. \
                        format(device, str(i), doorOpen, magazinePresent,
                               magazineSeated, magazineType, rotaryPosition))
                    sys.stdout.flush()
                    continue

                if self.longlist:
                    self.long_listing(tree, 0)
                    return

                if tree.tag == "mediaExchange":
                    for child in tree:
                        if child.tag == "doorOpen":
                            doorOpen = child.text.rstrip()
                        if child.tag == "magazinePresent":
                            magazinePresent = child.text.rstrip()
                        if child.tag == "magazineSeated":
                            magazineSeated = child.text.rstrip()
                        if child.tag == "magazineType":
                            magazineType = child.text.rstrip()
                        if child.tag == "rotaryPosition":
                            rotaryPosition = child.text.rstrip()
                    print(fmt. \
                        format(device, str(i), doorOpen, magazinePresent,
                               magazineSeated, magazineType, rotaryPosition))
                    sys.stdout.flush()


    #--------------------------------------------------------------------------
    #
    # Retrieves the ASCII formatted data for the type of trace specified by the
    # command.
    #
    # Outputs a filename in the current working directory that contains the
    # trace data in ASCII format.
    #
    # Output filename format: command_YYYY-MM-DD_<unique number starting at 1>
    #
    # Valid Commands:
    #     Action, AutoDriveClean, AutoSupport, BackgroundClient, CAN,
    #     Connection, Encryption, Error, EtherLib, Event, Geometry, GPIO, HHM,o
    #     HydraExit, Initialization, Inventory, Kernel, Lock, LogicalLibrary,
    #     Message, MLM, Motion, MotionInventory, MotionOptions, MotionRestart1,
    #     MotionRestart2, PackageUpdate, Pools, SNMP, WebServer
    #
    # Note: the following commands have been deprecated:
    #     DEPRECATED: QIP:[QIP ID]
    #     DEPRECATED: QIPDump:[QIP ID]
    #
    def gettrace(self, traceType, force=False):

        choices=['Action', 'AutoDriveClean', 'AutoSupport', 'BackgroundClient',
                 'CAN', 'Connection', 'Encryption', 'Error', 'EtherLib',
                 'Event', 'Geometry', 'GPIO', 'HHM', 'HydraExit',
                 'Initialization', 'Inventory', 'Kernel', 'Lock',
                 'LogicalLibrary', 'Message', 'MLM', 'Motion',
                 'MotionInventory', 'MotionOptions', 'MotionRestart1',
                 'MotionRestart2', 'PackageUpdate', 'Pools', 'SNMP',
                 'WebServer']

        found = False
        for choice in choices:
            if (traceType == choice.lower()):
                found = True
                break
        if (not found):
            raise(Exception("Error: Invalid trace type '" + traceType + "'"))


        try:
            print("Getting the trace data for '" + choice + "'")
            sys.stdout.flush()
            url  = self.baseurl + "/traces.xml?traceType=" + choice

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command(url, returnstring=True)

            # Write the data to a file in the current working directory.
            filename = choice
            if force == False:
                # The name of the file is the same as the trace type with an
                # underscore and the date appended to it along with a unique
                # sequential number. (e.g. CAN_2018-11-13_2)
                from datetime import date
                filename = choice + "_" + str(date.today())
                count = 1
                findUniqueName = True
                while True:
                    tempFilename = filename + "_" + str(count)
                    if (os.path.exists(tempFilename)):
                        count = count + 1
                        continue
                    else:
                        filename = tempFilename
                        break
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")
            sys.stdout.flush()

        except Exception as e:
            print("gettrace (" + choice + ") Error: " + str(e),
                  file=sys.stderr)
            sys.stdout.flush()
            raise(e)


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
                self.long_listing(tree, 0)
                return
            print(counterFormat. \
                format("CounterName", "SubType", "Value",
                       "Unit", "Reminder", "Severity",
                       "DefThresh", "CurThresh", "PostedDate"))
            print(counterFormat. \
                format("-------------------", "---------------", "------",
                       "------", "-------------------------", "--------",
                       "---------", "---------", "----------"))
            sys.stdout.flush()
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
                            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # For a specified partition, this command will compare the database
    # inventory of each TeraPack magazine to the inventory discovered by a
    # barcode scan of the magazine. In the event of a mismatch, the inventory
    # database is updated with the results of the scan, It inventories all
    # partitions
    #
    # Notes:
    #   1) Calls verfiyMagazineBarcodes to check all magazine barcodes against
    #      the stored inventory.
    #   2) Calls physInventory to get each magazine to inventory.
    #   3) This command is only supported on TFinity libraries.
    #   4) This command was added with BlueScale12.7.00.01.
    #   4) Important: The offset values given by phyInventory.xml are
    #                 one-based. The TeraPackOffset required by
    #                 inventory.xml?action=audit is zero-based. You must
    #                 subtract 1 from the offset value before supplying it
    #                 as a TeraPackOffset.
    #
    def inventoryaudit(self):

        # Don't start an inventory if one is currently in progress
        if not self.check_command_progress("inventory", True):
            raise(Exception(
                "Will not issue inventoryaudit command due to pending inventory command."))

        # First get a list of all the paritions
        try:
            url  = self.baseurl + "/partitionList.xml"
            partitionTree = self.run_command(url)
        except Exception as e:
            raise(e)

        if len(partitionTree) == 0:
            raise(Exception("Error: paritionList is reporting 0 paritions"))

        # Next (big step) we need to verify magazine barcodes
        try:
            self.verifymagazinebarcodes()
        except Exception as e:
            raise(e)

        # Wait a few more minutes before issuing the partition command
        # Testing has shown problems with issuing the physInventory too soon
        # after verify_magazine_barcode has completed
        print("Pausing 3 minutes before issuing physInventory...", end='')
        sys.stdout.flush()
        seconds = 60*3
        while (seconds > 0):
            print(".", end='')
            sys.stdout.flush()
            time.sleep(1)
            seconds -= 1
        print()
        sys.stdout.flush()

        numExceptions = 0


        # For each partition, use the physInventory list to get each magazine
        # to audit
        try:
            for paritionName in partitionTree:
                if (paritionName.tag != "partitionName"):
                    continue;
                partition = paritionName.text.strip()
                url  = self.baseurl + \
                       "/physInventory.xml?action=list&partition=" + partition
                tree = self.run_command(url)

                for part in tree:
                    for pool in part:
                        if (pool.tag == "storage"):
                            elementType = "storage"
                        elif (pool.tag == "entryExit"):
                            elementType = "IE"
                        if (pool.tag != "name"):    # storage or IE
                            for magazine in pool:
                                if (magazine.tag == "magazine"):
                                    # Important: The offset values given by
                                    # phyInventory.xml are one-based. The
                                    # TeraPackOffset required by
                                    # inventory.xml?action=audit is zero-based.
                                    # You must subtract 1 from the offset value
                                    # before supplying it as a TeraPackOffset.
                                    offset = int(magazine.find("offset").text.rstrip())
                                    teraPackOffset = offset - 1

                                    itemString = "Partition '" + partition + "' " +\
                                                 "elementType '" + elementType +   \
                                                 "' TeraPackOffset '" +            \
                                                 str(teraPackOffset)
                                    try:
                                        self.audit_tera_pack(partition,
                                                             elementType,
                                                             str(teraPackOffset))
                                        # get the results of the audit
                                        self.getauditresults()

                                    except Exception as e:
                                        # continue to the next item unless we've had
                                        # too many of these exceptions
                                        if (numExceptions > 10):
                                            raise(Exception("Error: too many " +   \
                                                "consecutive audit errors. " +     \
                                                "Bailing!"))
                                        else:
                                            numExceptions += 1


        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Lists all storage slots, entry/exit slots, and drives for all partitions.
    # - For each slot and drive, the list indicates whether or not it is full.
    # - For each occupied slot or drive, the list also indicates the barcode
    #   information of the cartridge and whether or not the cartridge is queued
    #   for eject.
    #
    def inventoryall(self):

        # First get a list of all the paritions
        try:
            url  = self.baseurl + "/partitionList.xml"
            partitionTree = self.run_command(url)
        except Exception as e:
            raise(e)

        if len(partitionTree) == 0:
            raise(Exception("Error: paritionList is reporting 0 paritions"))

        # For each partition print the inventory.
        try:
            header = True
            for paritionName in partitionTree:
                if (paritionName.tag != "partitionName"):
                    continue;
                partition = paritionName.text.strip()
                self.inventorylist(partition, header)
                header = False

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Lists all storage slots, entry/exit slots, and drives in the specified
    # partition.
    # - For each slot and drive, the list indicates whether or not it is full.
    # - For each occupied slot or drive, the list also indicates the barcode
    #   information of the cartridge and whether or not the cartridge is queued
    #   for eject.
    #
    def inventorylist(self, partition, header=True):

        listFormat = '{:15} {:13} {:6} {:6} {:10} {:6} {:4}'

        try:
            url       = self.baseurl + "/inventory.xml?action=list&partition=" + partition
            tree      = self.run_command(url)
            if header:
                print("\nInventory List")
                print("--------------")
                sys.stdout.flush()
            if self.longlist:
                self.long_listing(tree, 0)
                return
            for part in tree:
                if header:
                    print(listFormat.
                        format("Partition", "SlotType", "ID", "Offset",
                               "Barcode", "Queued", "Full"))
                    print(listFormat.
                        format("---------------", "-------------", "------",
                               "------", "----------", "------", "----"))
                    sys.stdout.flush()
                for elt in part:
                    if elt.tag != "name":
                        myid = ""
                        offset = ""
                        barcode = ""
                        isqueued = ""
                        full = ""
                        mediaPool = elt.tag.rstrip()
                        for slot in elt:
                            if slot.tag == "id":
                                myid = slot.text.rstrip()
                            elif slot.tag == "offset":
                                offset = slot.text.rstrip()
                            elif slot.tag == "barcode":
                                barcode = slot.text.strip()
                            elif slot.tag == "isQueued":
                                isqueued = slot.text.rstrip()
                            elif slot.tag == "full":
                                full = slot.text.rstrip()
                        print(listFormat. \
                            format(partition, mediaPool, myid, offset, barcode,
                                   isqueued, full))
                        sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the current library settings.
    #
    def librarysettingslist(self):

        topHdrFormat = '{:115} {}'
        hdrFormat    = '{:162} {}'
        listFormat   = '{:11} {:23} {:19} {:26} {:32} {:7} {:13} {:14} {:9} {:9} {:11} {:9}'

        try:
            url  = self.baseurl + "/librarySettings.xml?action=list"
            tree = self.run_command(url)
            print("\nLibrary Settings")
            print(  "----------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            if (len(tree) == 0):
                print("None")
                sys.stdout.flush()
                return

            # Printer header labels
            print(topHdrFormat. \
                format("", "-------------------------------- SNMPSettings --------------------------------"))
            print(hdrFormat.format("", "------- TrapDestination -------"))
            print(listFormat. \
                format("LibraryName", "AutoLogoutTimeoutInMins",
                       "OnlineAccessEnabled", "DrivePerfMonitoringEnabled",
                       "AutoPowerUpAfterPowerFailEnabled", "Enabled",
                       "SystemContact", "SystemLocation", "Community",
                       "Community", "Description", "IPAddress"))
            print(listFormat. \
                format("-----------", "-----------------------",
                       "-------------------", "--------------------------",
                       "--------------------------------", "-------",
                       "-------------", "--------------", "---------",
                       "---------", "-----------", "---------"))

            # Get top level settings
            libraryName = autoLogoutTimeoutInMinutes = onlineAccessEnabled = ""
            drivePerformanceMonitoringEnabled = ""
            automaticPowerUpAfterPowerFailureEnabled = ""

            libraryNameRec = tree.find("libraryName")
            if ( (libraryNameRec is not None) and (len(libraryNameRec) > 0) ):
                libraryName = libraryNameRec.text.strip()

            autoLogoutTimeoutInMinutesRec = tree.find("autoLogoutTimeoutInMinutes")
            if ( (autoLogoutTimeoutInMinutesRec is not None) and
                 (len(autoLogoutTimeoutInMinutesRec) > 0) ):
                autoLogoutTimeoutInMinutes = autoLogoutTimeoutInMinutesRec.text.strip()

            onlineAccessEnabledRec = tree.find("onlineAccessEnabled")
            if ( (onlineAccessEnabledRec is not None) and 
                 (len(onlineAccessEnabledRec) > 0) ):
                onlineAccessEnabled = onlineAccessEnabledRec.text.strip()

            drivePerformanceMonitoringEnabledRec = tree.find(
                "drivePerformanceMonitoringEnabled")
            if ( (drivePerformanceMonitoringEnabledRec is not None) and
                 (len(drivePerformanceMonitoringEnabledRec) > 0) ):
                drivePerformanceMonitoringEnabled = drivePerformanceMonitoringEnabledRec.text.strip()

            automaticPowerUpAfterPowerFailureEnabledRec = tree.find(
                "automaticPowerUpAfterPowerFailureEnabled")
            if ( (automaticPowerUpAfterPowerFailureEnabledRec is not None) and
                 (len(automaticPowerUpAfterPowerFailureEnabledRec) > 0) ):
                automaticPowerUpAfterPowerFailureEnabled = automaticPowerUpAfterPowerFailureEnabledRec.text.strip()

            community = trapCommunity = trapDescription = trapIPAddress = ""
            for child in tree:

                if child.tag == "SNMPSettings":

                    enabledRec = child.find("enabled")
                    if enabledRec is not None:
                        enabled = enabledRec.text.strip()
                    else:
                        enabled = ""

                    # systemContact is an odd nut since it might have a record
                    # with no string/text attached
                    systemContactRec = child.find("systemContact")
                    if systemContactRec is not None:
                        if systemContactRec.text:
                            systemContact = systemContactRec.text.strip()
                        else:
                            systemContact = "None"
                    else:
                        systemContact = ""

                    # systemLocation is an odd nut since it might have a record
                    # with no string/text attached
                    systemLocationRec = child.find("systemLocation")
                    if systemLocationRec is not None:
                        if systemLocationRec.text:
                            systemLocation = systemLocationRec.text.strip()
                        else:
                            systemLocation = "None"
                    else:
                        systemLocation = ""

                    for setting in child:
                        if setting.tag == "community":
                            community = setting.text.strip()
                            trapCommunity = trapDescription = trapIPAddress = ""
                            print(listFormat. \
                                format(libraryName, autoLogoutTimeoutInMinutes,
                                       onlineAccessEnabled,
                                       drivePerformanceMonitoringEnabled,
                                       automaticPowerUpAfterPowerFailureEnabled,
                                       enabled, systemContact, systemLocation,
                                       community, trapCommunity,
                                       trapDescription, trapIPAddress))
                        # TODO: I wasn't able to test trapDestination 11/26/18
                        if setting.tag == "trapDestination":
                            for trap in setting:
                                if trap.tag == "community":
                                    trapCommunity = trap.text.strip()
                                if trap.tag == "description":
                                    trapDescription = trap.text.strip()
                                if trap.tag == "ipAddress":
                                    trapIPAddress = trap.text.strip()
                            community = ""
                            print(listFormat. \
                                format(libraryName, autoLogoutTimeoutInMinutes,
                                       onlineAccessEnabled,
                                       drivePerformanceMonitoringEnabled,
                                       automaticPowerUpAfterPowerFailureEnabled,
                                       enabled, systemContact, systemLocation,
                                       community, trapCommunity,
                                       trapDescription, trapIPAddress))

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Returns the library type, serial number, component status, and engineering
    # change level information for the library that received the command. With
    # headers.
    #
    def librarystatus(self):

        topFormat = '{:11} {:11} {:9} {:20}'
        robotFormat = '{:6} {:9} {:15} {:12} {:19} {:28} {:23} {:32} {:11} {:13} {:14} {:17}'
        moveFormat  = '{:15} {:12} {:12} {:12} {:20} {:19}'
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
        componentFormat = '{:25} {:4} {:15} {:18} {:25} {:10}'

        try:
            url  = self.baseurl + "/libraryStatus.xml"
            tree = self.run_command(url)
            print("\nLibrary Status")
            print("--------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return

            # top level stuff
            libraryType      = tree.find("libraryType")
            railPowerOn      = tree.find("railPowerOn")
            serialNumber     = tree.find("serialNumber")
            uptimeSecondsStr = tree.find("libraryUpTimeSeconds")
            uptimeSeconds    = datetime.timedelta(seconds=int(uptimeSecondsStr.text.strip()))
            print()
            print(topFormat. \
                format("LibraryType", "RailPowerOn", "SerialNum", "Uptime"))
            print(topFormat. \
                format("-----------", "-----------", "---------", "--------------------"))
            print(topFormat. \
                format(libraryType.text.strip(),
                       railPowerOn.text.strip(),
                       serialNumber.text.strip(),
                       str(uptimeSeconds)))
            sys.stdout.flush()

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
                        sys.stdout.flush()
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
                    sys.stdout.flush()

                # excessiveMoveFailures list
                # NOTE: wasn't able to test on NERF Tfinity as it
                # currently doesn't have any excessiveMoveFailures
                if child.tag == "excessiveMoveFailures":
                    print("\nExcessive Move Failures:")
                    print(moveFormat. \
                        format("Partition", "Source", "Destination",
                               "NumFailures", "LastSenseInfo",
                               "LastFailedMoveTime"))
                    print(moveFormat. \
                        format("---------------", "------------", "------------",
                               "------------", "--------------------",
                               "-------------------"))
                    sys.stdout.flush()
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
                    sys.stdout.flush()

                # controllerEnvironmentInfo list
                if child.tag == "controllerEnvironmentInfo":
                    for ceinfo in child:

                        # controllers
                        if ceinfo.tag == "controller":
                            if controllerHeaderPrinted == False:
                                print()
                                print(controllerFormat. \
                                    format("ControllerID", "TempInCelsius",
                                           "PortALinkUp", "PortBLinkUp",
                                           "FailoverStatus"))
                                print(controllerFormat. \
                                    format("-------------------------",
                                           "-------------", "-----------",
                                           "-----------", "--------------"))
                                sys.stdout.flush()
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
                            sys.stdout.flush()

                        # drive control modules
                        if ceinfo.tag == "driveControlModule":
                            if driveCMHeaderPrinted == False:
                                print()
                                print(driveCMFormat. \
                                    format("DriveControlModuleID", "12VoltVoltage",
                                           "5VoltVoltage", "FanCurrentInAmps",
                                           "TempInCelsius"))
                                print(driveCMFormat. \
                                    format("-------------------------",
                                           "-------------", "------------",
                                           "----------------", "---------------"))
                                sys.stdout.flush()
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
                            sys.stdout.flush()

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
                                sys.stdout.flush()
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
                            sys.stdout.flush()

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
                                sys.stdout.flush()
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
                                            sys.stdout.flush()
                                            position = faulted = ""
                                            origPosition = origFaulted = ""


                        # fan control modules
                        # NOTE: wasn't able to test on NERF Tfinity as it
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
                                sys.stdout.flush()
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
                                sys.stdout.flush()

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
                                sys.stdout.flush()

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
                                sys.stdout.flush()
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
                                        #TODO: The documentation shows an "on"
                                        #record, but I've never seen it, so I'm
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
                            sys.stdout.flush()

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
                        sys.stdout.flush()
                        for item in fanPairStringList:
                            print(item)
                            sys.stdout.flush()

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
                        sys.stdout.flush()
                        for item in fanInFMMStringList:
                            print(item)
                            sys.stdout.flush()

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
                        sys.stdout.flush()
                        for item in powerInFMMStringList:
                            print(item)
                            sys.stdout.flush()

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
                        sys.stdout.flush()
                        for item in serviceStringList:
                            print(item)
                            sys.stdout.flush()

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
                                    format("-------------------------", "----",
                                           "---------------",
                                           "------------------",
                                           "-------------------------",
                                           "----------"))
                                sys.stdout.flush()
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
                            sys.stdout.flush()

        except Exception as e:
            raise(e)


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
                self.long_listing(tree, 0)
                return
            for child in tree:
                if ( (child.tag == "robot") or
                     (child.tag == "excessiveMoveFailures") ):
                    print(child.tag + ":", end='')
                    for item in child:
                        print(" ", end='')
                        print(item.tag, item.text, sep='=', end='')
                    print() #newline
                    sys.stdout.flush()
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
                            sys.stdout.flush()
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
                                    sys.stdout.flush()
                                else:
                                    print(item.tag, item.text, sep='=', end='')
                            print() #newline
                            sys.stdout.flush()
                elif (child.tag == "ECInfo"):
                    for component in child:
                        print(child.tag, component.tag, sep=': ', end='')
                        for item in component:
                            print(item.tag, item.text, sep='=', end='')
                            print(" ", end='')
                        print() #newline
                        sys.stdout.flush()
                else:
                    print(child.tag, child.text, sep=': ')
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


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
                self.clear_cookie()
                os.umask(0o077)
                self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)

        except Exception as e:
            raise(e)


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
        self.clear_cookie()
        os.umask(0o077)
        self.cookiejar.save(self.cookiefile, ignore_discard=True, ignore_expires=False)


    #--------------------------------------------------------------------------
    #
    # Returns a list of the current Media Lifecycle Management (MLM) settings.
    #
    def mlmsettings(self):

        toptopHdrFormat = '{:264} {}'
        topHdrFormat = '{:264} {:10} {:10} {:10} {:10} {:10} {:10} {:10}'
        hdrFormat = '{:10} {:19} {:33} {:30} {:35} {:30} {:20} {:30} {:23} {:25} {:10} {:10} {:10} {:10} {:10} {:10} {:10} {:34}'

        try:
            url  = self.baseurl + "/MLMSettings.xml?action=list"
            tree = self.run_command(url)
            print("\nMedia Lifecycle Management (MLM) Settings")
            print(  "-----------------------------------------")

            if self.longlist:
                self.long_listing(tree, 0)
                return

            if (len(tree) == 0):
                print("None")
                sys.stdout.flush()
                return

            print(toptopHdrFormat.format("",
                "----------------------------PostScanTapeBlackout----------------------------"))
            print(topHdrFormat. \
                format("","Sunday", "Monday", "Tuesday", "Wednesday",
                       "Thursday", "Friday", "Saturday"))
            print(hdrFormat. \
                format("MLMEnabled", "NonMLMAlertsEnabled",
                       "LoadCountDiscrepancyAlertsEnabled",
                       "NonMLMLibraryLoadAlertsEnabled",
                       "MinCleaningPassesBeforeWarningCount",
                       "MaxTapeLoadsBeforeWarningCount",
                       "AutoDiscoveryEnabled",
                       "AutoDiscoveryIdleWaitInMinutes",
                       "BroadcastBaseConversion", "BroadcastMegabitPerSecond",
                       "Start Stop", "Start Stop", "Start Stop", "Start Stop",
                       "Start Stop", "Start Stop", "Start Stop",
                       "NoncertifiedMAMBarcodeWriteEnabled"))
            print(hdrFormat. \
                format("----------", "-------------------",
                       "---------------------------------",
                       "------------------------------",
                       "-----------------------------------",
                       "------------------------------",
                       "--------------------",
                       "------------------------------",
                       "-----------------------", "-------------------------",
                       "----- ----", "----- ----", "----- ----", "----- ----",
                       "----- ----", "----- ----", "----- ----",
                       "----------------------------------"))
            sys.stdout.flush()

            if tree.tag == "MLMSettings":
                MLMEnabled = nonMLMAlertsEnabled = ""
                loadCountDiscrepancyAlertsEnabled = ""
                nonMLMLibraryLoadAlertsEnabled = ""
                minCleaningPassesBeforeWarningCount = ""
                maxTapeLoadsBeforeWarningCount = autoDiscoveryEnabled = ""
                autoDiscoveryIdleWaitInMinutes = broadcastBaseConversion = ""
                broadcastMegabitPerSecond = sunday = monday = tuesday = ""
                wednesday = thursday = friday = saturday = start = stop = ""
                noncertifiedMAMBarcodeWriteEnabled = ""
                for child in tree:
                    if child.tag == "MLMEnabled":
                        MLMEnabled = child.text.rstrip()
                    elif child.tag == "nonMLMAlertsEnabled":
                        nonMLMAlertsEnabled = child.text.rstrip()
                    elif child.tag == "loadCountDiscrepancyAlertsEnabled":
                        loadCountDiscrepancyAlertsEnabled = child.text.rstrip()
                    elif child.tag == "nonMLMLibraryLoadAlertsEnabled":
                        nonMLMLibraryLoadAlertsEnabled = child.text.rstrip()
                    elif child.tag == "minCleaningPassesBeforeWarningCount":
                        minCleaningPassesBeforeWarningCount = child.text.rstrip()
                    elif child.tag == "maxTapeLoadsBeforeWarningCount":
                        maxTapeLoadsBeforeWarningCount = child.text.rstrip()
                    elif child.tag == "autoDiscoveryEnabled":
                        autoDiscoveryEnabled = child.text.rstrip()
                    elif child.tag == "autoDiscoveryIdleWaitInMinutes":
                        autoDiscoveryIdleWaitInMinutes = child.text.rstrip()
                    elif child.tag == "broadcastBaseConversion":
                        broadcastBaseConversion = child.text.rstrip()
                    elif child.tag == "broadcastMegabitPerSecond":
                        broadcastMegabitPerSecond = child.text.rstrip()
                    elif child.tag == "postScanTapeBlackout":
                        for day in child:
                            if day.tag == "sunday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                sunday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "monday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                monday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "tuesday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                tuesday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "wednesday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                wednesday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "thursday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                thursday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "friday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                friday = '{:5} {:4}'.format(start, stop)
                            elif day.tag == "saturday":
                                for hours in day:
                                    if hours.tag == "start":
                                        start = hours.text.rstrip()
                                    elif hours.tag == "stop":
                                        stop = hours.text.rstrip()
                                saturday = '{:5} {:4}'.format(start, stop)
                    elif child.tag == "noncertifiedMAMBarcodeWriteEnabled":
                        noncertifiedMAMBarcodeWriteEnabled = child.text.rstrip()
                print(hdrFormat. \
                    format(MLMEnabled, nonMLMAlertsEnabled,
                           loadCountDiscrepancyAlertsEnabled,
                           nonMLMLibraryLoadAlertsEnabled,
                           minCleaningPassesBeforeWarningCount,
                           maxTapeLoadsBeforeWarningCount,
                           autoDiscoveryEnabled,
                           autoDiscoveryIdleWaitInMinutes,
                           broadcastBaseConversion, broadcastMegabitPerSecond,
                           sunday, monday, tuesday, wednesday, thursday,
                           friday, saturday, start, stop,
                           noncertifiedMAMBarcodeWriteEnabled))
                sys.stdout.flush()

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Returns a list of all active option keys currently entered in the library.
    #
    def optionkeyslist(self):

        listFormat = '{:30} {:60} {:12} {:14}'
        totalchambers = 0

        try:
            url  = self.baseurl + "/optionKeys.xml?action=list"
            tree = self.run_command(url)
            print(listFormat.format("Option Key", "Description", "Action", "Days Remaining"))
            print(listFormat. \
                format("----------",
                       "-----------",
                       "------",
                       "--------------"))
            for optionkey in tree:
                keyvalue = description = action = daysremaining = ""
                for item in optionkey:
                    if item.tag == "keyValue":
                        keyvalue = item.text.rstrip()
                    elif item.tag == "description":
                        description = item.text.rstrip()
                    elif item.tag == "action":
                        action = item.text.rstrip()
                    elif item.tag == "action":
                        action = item.text.rstrip()
                    elif item.tag == "daysRemaining":
                        daysremaining = item.text.rstrip()

                # Match a line like:
                # Capacity License: 995 Chambers
                match = re.search("Capacity License:\s+(\d+)\s+Chambers", description)
                if match:
                    newchambers   = match.group(1)
                    if action == "ADD":
                        totalchambers = totalchambers + int(newchambers)
                    elif action == "OVERWRITE":
                        totalchambers = int(newchambers)
                print(listFormat.format(keyvalue, description, action, daysremaining))
                sys.stdout.flush()

            print("")
            print("Total Licensed Chambers: " + str(totalchambers))
            sys.stdout.flush()
                    

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Display the current firmware version installed on individual components
    # in the library along with the firmware version included in the currently
    # installed BlueScale package version.
    #
    # Note: This action was added with BlueScale12.7.02.
    #
    def packagedisplay(self, packagename):

        headerFormat = '{:35} {:23} {:26}'
        listFormat = '{:25} {:15} {:15} {:13}'

        # Use the package name to get the details.  Note: XML documentation
        # dated June 2017 is missing information about needing the package
        # argument for the displayPackageDetails action.
        try:

            if packagename is None:
                raise(Exception("displaypackagedetails: please specify package name"))

            url  = self.baseurl + "/package.xml?action=displayPackageDetails&package=" + packagename
            tree = self.run_command(url)
            print("\nPackage Details")
            print(  "----------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return
            if len(tree) == 0:
                print("None")
                return

            # top level stuff
            packageName = tree.find("packageName")
            allComponentsUpToDate = tree.find("allComponentsUpToDate")
            allComponentsFullyStaged = tree.find("allComponentsFullyStaged")
            print()
            print(headerFormat. \
                format("PackageName", "AllComponentsUpToDate?",
                       "AllComponentsFullyStaged?"))
            print(headerFormat. \
                format("----------------------------------",
                       "-----------------------",
                       "--------------------------"))
            print(headerFormat. \
                format(packageName.text.strip(),
                       allComponentsUpToDate.text.strip(),
                       allComponentsFullyStaged.text.strip()))
            sys.stdout.flush()
            headersPrinted = False

            for pkg in tree:
                if pkg.tag == "component":
                    if not headersPrinted:
                        print()
                        print(listFormat. \
                            format("ComponentName", "CurrentVersion",
                                "PackageVersion", "FullyStaged?"))
                        print(listFormat. \
                            format("-------------------------",
                                   "---------------",
                                   "---------------",
                                   "-------------"))
                        sys.stdout.flush()
                        headersPrinted = True

                    name = currentVersion = packageVersion = fullyStaged = ""
                    for component in pkg:
                        if component.tag == "name":
                            name = component.text.rstrip()
                        elif component.tag == "currentVersion":
                            currentVersion = component.text.rstrip()
                        elif component.tag == "packageVersion":
                            packageVersion = component.text.rstrip()
                        elif component.tag == "fullyStaged":
                            fullyStaged = component.text.rstrip()
                    print(listFormat. \
                        format(name, currentVersion, packageVersion,
                               fullyStaged))
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


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
                self.long_listing(tree, 0)
                return
            sys.stdout.flush()
            for child in tree:
                if child.tag == "current":
                    for element in child:
                        if element.tag == "name":
                            print("Currently Running", element.text.rstrip(), sep=(': '))
                            sys.stdout.flush()
                if child.tag == "list":
                    print("Currently Stored on Library:", end='')
                    sys.stdout.flush()
                    for element in child:
                        if element.tag == "name":
                            print(" " + element.text.rstrip(), end='')
                    print()
                    sys.stdout.flush()

        except Exception as e:
            raise(e)

    def packageprogress(self):

        try:

            url  = self.baseurl + "/package.xml?progress"
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status != "OK" and status != "ACTIVE":
                raise(Exception("Failure issuing progress command: " + message))

            print(message)

        except Exception as e:
            raise(e)

    def packagestage(self, packagename):

        try:
            if (packagename is None):
                raise(Exception("packagestage: please provide a package name."))

            url  = self.baseurl + "/package.xml?action=stagePackage&package=" + packagename
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status != "OK":
                raise(Exception("Failure issuing stagePackage command: " + message))

            print(message)

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # The command performs multiple XML commands to update the library BlueScale
    # software.
    #
    def packageupdate(self, packagename):

        # First transfer the BlueScale package to the library using the
        # packageupload command.
        try:
            if (packagename is None):
                raise(Exception("packageupdate: please provide a package name."))

            url  = self.baseurl + "/package.xml?action=update&package=" + packagename + "&autoFinish"
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status != "OK":
                raise(Exception("Failure issuing update command: " + message))

            print(message)

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # The command performs multiple XML commands to update the library BlueScale
    # software.
    #
    def packageupload(self, filename):

        # First transfer the BlueScale package to the library using the
        # package_upload command.
        try:
            filename = os.path.abspath(filename)
            if os.path.exists(filename) == False:
                raise(Exception(filename + " does not exist."))
            if os.path.isfile(filename) == False:
                raise(Exception(filename + " is not a file."))
            if not filename.endswith(".hps"):
                raise(Exception(filename + " is not a valid .hps file."))

            url  = self.baseurl + "/packageUpload.xml"
            tree = self.run_command(url, filename=filename)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
            if status != "OK":
                raise(Exception("Failure issuing packageUpload command"))

            print("Successfully uploaded package: " + os.path.basename(filename))

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Returns a list of all the partitions configured in the library.
    #
    # **NOTE** This command is different from "partition.xml?action=list"
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
                self.long_listing(tree, 0)
                return
            sys.stdout.flush()
            for child in tree:
                if child.tag == "partitionName":
                    print(child.text.rstrip())
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieve a list of all occupied magazine and cartridge locations in all
    # the partitions. The list includes the offset value for each occupied
    # magazine and slot, as well as the barcodes of the magazines and
    # cartridges, if available.
    #
    # Note: Empty locations are not included in the list, but can be identified
    #       by the gaps in the offset values returned by the command.
    #
    def physinventoryall(self):

        # First get a list of all the paritions
        try:
            url  = self.baseurl + "/partitionList.xml"
            partitionTree = self.run_command(url)
        except Exception as e:
            raise(e)

        if len(partitionTree) == 0:
            raise(Exception("Error: paritionList is reporting 0 paritions"))

        # For each partition print the inventory.
        try:
            header = True
            for paritionName in partitionTree:
                if (paritionName.tag != "partitionName"):
                    continue;
                partition = paritionName.text.strip()
                self.physinventorylist(partition, header)
                header = False

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Retrieve a list of all occupied magazine and cartridge locations in the
    # specified partition. The list includes the offset value for each occupied
    # magazine and slot, as well as the barcodes of the magazines and
    # cartridges, if available.
    #
    # Note: Empty locations are not included in the list, but can be identified
    #       by the gaps in the offset values returned by the command.
    #
    def physinventorylist(self, partition, header=True):

        topHdrFormat = '{:26} {}'
        listFormat = '{:15} {:9} {:6} {:7} {:5} {:7} {:6} {:6} {:11}'

        try:
            url  = self.baseurl + "/physInventory.xml?action=list&partition=" + partition
            tree = self.run_command(url)
            if header:
                print("\nPhysical Inventory List")
                print(  "-----------------------")
                sys.stdout.flush()
            if self.longlist:
                self.long_listing(tree, 0)
                return
            for part in tree:
                if header:
                    print(topHdrFormat.format("",
                        "----------------------Magazine-----------------------"))
                    print(listFormat.
                        format("Partition", "MediaPool", "Offset", "Barcode",
                               "Frame", "TapeBay", "Drawer", "Slot", "SlotBarcode"))
                    print(listFormat.
                        format("---------------", "---------", "------", "-------",
                               "-----", "-------", "------", "------",
                               "-----------"))
                    sys.stdout.flush()

                mediaPool = ""
                for pool in part:
                    if ( (pool.tag == "storage") or
                         (pool.tag == "entryExit") ):
                        mediaPool = pool.tag.rstrip()
                        for magazine in pool:
                            if (magazine.tag == "magazine"):
                                offset = magazine.find("offset").text.rstrip()
                                barcode = magazine.find("barcode").text.rstrip()
                                frameNumber = magazine.find("frameNumber").text.rstrip()
                                tapeBayNumber = magazine.find("tapeBayNumber").text.rstrip()
                                drawerNumber = magazine.find("drawerNumber").text.rstrip()
                                slotNumber = slotBarcode = ""
                                slotList = magazine.findall("slot")
                                if not slotList:
                                    print(listFormat.
                                        format(partition, mediaPool, offset,
                                               barcode, frameNumber,
                                               tapeBayNumber, drawerNumber,
                                               slotNumber, slotBarcode))
                                else:
                                    for slot in slotList:
                                        slotNumber = slot.find("number").text.rstrip()
                                        slotBarcode = slot.find("barcode").text.rstrip()
                                        print(listFormat.
                                            format(partition, mediaPool, offset,
                                                   barcode, frameNumber,
                                                   tapeBayNumber, drawerNumber,
                                                   slotNumber, slotBarcode))

        except Exception as e:
            raise(e)



    #--------------------------------------------------------------------------
    #
    # Displays the status of all the Robotics Control Modules (RCM)
    #
    # Notes from June 2017 XML reference document:
    # - This action was added with BlueScale12.6.45.5.
    # - If the library is not able to communicate with the RCM, the command
    #   returns a syntax error indicating an invalid id.
    # - A list of all RCMs the library can communicate with can be found in the
    #   ECInfo section of the response to the libraryStatus.xml command without
    #   any parameters. RCM component identifiers are preceded with "RCM
    #   Spectra PC"
    #
    def rcmstatuslist(self):

        rcmFormat = '{:10} {:13} {:12} {:12} {:14}'


        # First we need to get a list of RCM IDs.  This isn't so obvious.
        # A list of all RCMs the library can communicate with can be found in
        # the ECInfo section of the response to the libraryStatus.xml command
        # without any parameters. RCM component identifiers are preceded with
        # "RCM Spectra PC"
        try:
            url  = self.baseurl + "/libraryStatus.xml"
            tree = self.run_command(url)
            if len(tree) == 0:
                raise(Exception("Error: Problem getting the libraryStatus list"))
            ecInfo = tree.find("ECInfo")
            if len(ecInfo) == 0:
                raise(Exception("Error: Problem getting the libraryStatus ECInfo element"))
            components = ecInfo.findall("component")
            if len(components) == 0:
                raise(Exception("Error: Problem getting the libraryStatus ECInfo component list"))
            rcmList = []
            name = ""
            for component in components:
                for element in component:
                    if (element.tag == "ID"):
                        name = element.text.rstrip()
                        if "RCM Spectra PC" in name:
                            rcmList.append(name)
            if len(rcmList) == 0:
                raise(Exception("Error: Couldn't find any RCM entries"))

        except Exception as e:
            print("rcmstatuslist Error getting RCM IDs: " + str(e), file=sys.stderr)
            sys.stdout.flush()
            raise(e)

        # Next get the rcmstatus for each RCM
        try:

            print("\nRCM Status")
            print(  "----------")
            sys.stdout.flush()

            if not self.longlist:
                print(rcmFormat. \
                    format("RCM ID", "OverallStatus", "LoglibStatus",
                        "MotionStatus", "RepeaterStatus"))
                print(rcmFormat. \
                    format("----------", "-------------", "------------",
                           "------------", "--------------"))
                sys.stdout.flush()

            overallStatus = loglibStatus = motionStatus = repeaterStatus = ""

            for rcmIDfull in rcmList:

                # The RCMStatus action just wants the FR[integer]/RCM portion
                # of the ID. So strip off the prefix.
                rcmIDsplit = rcmIDfull.split("RCM Spectra PC: ")
                try:
                    rcmID = rcmIDsplit[1]
                except Exception as e:
                    raise(Exception(
                        "Error: Problem parsing the RCM ID: " + rcmIDfull))

                url  = self.baseurl + "/libraryStatus.xml?action=RCMStatus&id=" + rcmID
                tree = self.run_command(url)
                if self.longlist:
                    self.long_listing(tree, 0)
                    continue

                for child in tree:
                    if child.tag == "RCMStatus":
                        for rcmstatus in child:
                            if rcmstatus.tag == "ID":
                                myid = rcmstatus.text.rstrip()
                            if rcmstatus.tag == "overallStatus":
                                overallStatus = rcmstatus.text.rstrip()
                            if rcmstatus.tag == "loglibStatus":
                                loglibStatus = rcmstatus.text.rstrip()
                            if rcmstatus.tag == "motionStatus":
                                motionStatus = rcmstatus.text.rstrip()
                            if rcmstatus.tag == "repeaterStatus":
                                repeaterStatus = rcmstatus.text.rstrip()
                    print(rcmFormat. \
                        format(myid, overallStatus, loglibStatus, motionStatus,
                               repeaterStatus))
                    sys.stdout.flush()


        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Resets the specified drive by power cycling it.
    #
    # Input: driveID as reported by driveList.xml
    #
    def resetdrive(self, driveID):

        # validate the drive ID
        url  = self.baseurl + "/driveList.xml?action=list"
        tree = self.run_command(url)
        foundIt = False
        for element in tree:
            for drive in element:
                if drive.tag == "ID":
                    tempDrive = drive.text.strip()
                    if (tempDrive == driveID):
                        foundIt = True

        if not foundIt:
            raise(Exception("Error: The input drive (" + driveID +
                            ") is not a valid drive."))

        if not self.check_command_progress("driveList", True):
            raise(Exception(
                "Will not issue resetDrive command due to pending commands."))

        try:
            url  = self.baseurl + "/driveList.xml?action=resetDrive&driveName=" + driveID
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The driveList resetDrive command has been submitted: " + 
                      message)
                sys.stdout.flush()

            # poll for driveList resetDrive to be done
            try:
                while (not self.check_command_progress("driveList", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                raise(Exception("driveList resetDrive progress Error: " + str(e)))

            print("\nThe driveList resetDrive command has completed.")
            sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Resets the specified Hardware Health Monitoring (HHM) counter to zero. A
    # counter is typically reset to zero following the completion of the
    # regularly scheduled standard maintenance of the component.
    #
    # Input:
    #   counter: the HHM counter to reset
    #   subType: the name of the subtype counter to be reset
    #            Valid values: Trip1, Trip2, None
    #   robot:   the robot number string containing the HHM counter to reset
    #            Valid values: "1" or "2"
    #
    # Caution:
    #     Do not run this command unless you are specifically directed to do
    #     so by Spectra Logic Support. Changing the counter values can result
    #     in components not receiving regularly scheduled maintenance when it
    #     is due.
    # Notes:
    #  1) Only one subType counter of one HMM counter can be reset in each
    #     resetCounterData command. To reset multiple counters, you must issue
    #     separate commands.
    #  2) The following syntax is for a TFinity library. The syntax for other
    #     libraries does not include the robot parameter.
    #  3) This command corresponds to the HHM: Set Counters advanced utility in
    #     the BlueScale user interface.
    #
    # Valid Values to reset:
    #    Horizontal Axis, Vertical Axis, Picker Axis, Rotational Axis,
    #    Magazine Axis, Toggle Axis, Side Axis, Drive to Drive Move,
    #    Drive to Slot Move, Slot to Slot Move, Slot to Drive Move,
    #    TAP In Move, TAP Out Move.
    #
    def resethhmcounter(self, counter, subType, robot):

        choices=['Horizontal Axis', 'Vertical Axis', 'Picker Axis',
                 'Rotational Axis', 'Magazine Axis', 'Toggle Axis',
                 'Side Axis', 'Drive to Drive Move', 'Drive to Slot Move',
                 'Slot to Slot Move', 'Slot to Drive Move', 'TAP In Move',
                 'TAP Out Move']

        subTypeChoices=['Trip1', 'Trip2', 'None']

        robotChoices=['1', '2']

        # Validate the counter choice
        found = False
        for choice in choices:
            if (counter == choice.lower()):
                found = True
                break
        if (not found):
            raise(Exception("Error: Invalid counter '" + counter + "'"))

        # Validate the subType choice
        found = False
        for subTypeChoice in subTypeChoices:
            if (subType == subTypeChoice.lower()):
                found = True
                break
        if (not found):
            raise(Exception("Error: Invalid counter subType '" + subType + "'"))

        # Validate the robot choice
        found = False
        for robotChoice in robotChoices:
            if (robot == robotChoice.lower()):
                found = True
                break
        if (not found):
            raise(Exception("Error: Invalid robot number '" + robot + "'"))


        try:
            print("Resetting HHM counter '" + choice + \
                  "' subType '" + subTypeChoice + \
                  "' for Robot " + robotChoice)
            sys.stdout.flush()

            # Replace the spaces in the url options with %20
            url = self.baseurl + "/HHMData.xml?action=resetCounterData&type="+ \
                  urllib.parse.quote(choice) +                                 \
                  "&subType=" + urllib.parse.quote(subTypeChoice) +            \
                  "&robot=Robot%20" + robotChoice

            tree = self.run_command(url)
            for data in tree:
                status = data.find("status")
                message = data.find("message")
                print("Status: " + status.text.rstrip())
                print("Message: " + message.text.rstrip())
                sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Move the robot to/from the service bay based on the action parameter.
    # The acion parameter may be one of "progress", "toservicebay", or
    # "fromservicebay"
    #
    # The robot being moved is specified as "1" (the left robot) or "2" (the
    # right robot) when facing the front of the library.
    #
    # The caller may choose to poll to wait for the operation to complete.
    #
    def robotservice(self, action, robot, poll=None):

        try:
            url  = self.baseurl + "/robotService.xml?"

            if action.lower() == "progress":
                url = url + "progress"
            elif action.lower() == "fromservicebay":
                url = url + "action=returnFromService&"
            elif action.lower() == "toservicebay":
                url = url + "action=sendToService&"
            else:
                raise(Exception("Error: Invalid robotservice action " + action))

            if action.lower() == "fromservicebay" or action.lower() == "toservicebay":
                if (robot is not None) and (robot == "1" or robot == "2"):
                    url = url + "robot=" + robot
                else:
                    raise(Exception("Error: Invalid robotservice robot number"))

            tree = self.run_command(url)
            status  = None
            message = None
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                if child.tag == "message":
                    message = child.text.rstrip()
 
            if action.lower() == "progress" or poll is None:
                print(f"Status: {status}")
                print(f"Message: {message}")
                sys.stdout.flush()
            else:
                # poll for robotservice to complete
                try:
                    while (not self.check_command_progress("robotService", False)):
                        # put out an in progress 'dot'
                        print(".", end='')
                        sys.stdout.flush()
                        # wait 1 seconds before retrying
                        time.sleep(poll)
                except Exception as e:
                    raise(Exception("robotservice progress Error: " + str(e)))

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Begins a Security Audit which is a physical audit of the entire library.
    #
    # Use the securityAudit.xml command to have a TFinity library check all
    # TeraPack magazines to make sure that the expected tapes are in them.
    #
    # Notes:
    #   - The securityAudit.xml command was added with BlueScale 12.8.01.
    #   - The securityAudit.xml command cannot run while another command that
    #     makes the robot(s) unavailable, such as verifyMagazineBarcodes, is
    #     running.
    #
    def securityaudit(self):

        try:
            # Don't start a security audit if one is currently in progress
            if self.check_security_audit_in_progress():
                raise(Exception(
                    "Will not issue securityaudit command due to pending " +
                    "securityaudit command."))

            # Cannot do a security audit during verifyMagazineBarcodes
            if not self.check_command_progress("utils", True):
                raise(Exception(
                    "Will not issue securityaudit command due to pending " +
                    "utils command."))
        except Exception as e:
            raise(e)

        print("Starting physical security audit...")
        sys.stdout.flush()
        try:
            url  = self.baseurl + "/securityAudit.xml?action=start"
            tree = self.run_command(url)
            try:
                self.check_for_error(tree)

                # get the immediate response
                status = "OK"
                for child in tree:
                    if child.tag == "status":
                        status = child.text.rstrip()
                    if child.tag == "message":
                        message = child.text.rstrip()
                if status != "OK":
                    #TODO: wondering if we should abort security audit
                    #      (i.e. perhaps it actually started?)
                    raise(Exception("Failure starting physical security audit" +
                                    " : status=" + status + " : " + message))
            except Exception as e:
                #TODO: wondering if there are cases where we should abort
                #security audit (i.e. perhaps it actually started)?
                raise(Exception("Error issuing securityAudit command: " +
                                 str(e)))

        except Exception as e:
            raise


    #--------------------------------------------------------------------------
    #
    # Stops a currently in-progress Security Audit (physical audit) of the
    # library.
    #
    # Note: The securityAudit.xml command was added with BlueScale 12.8.01.
    #
    def securityauditabort(self):

        print("Aborting physical security audit...")
        sys.stdout.flush()
        try:
            url  = self.baseurl + "/securityAudit.xml?action=abort"
            tree = self.run_command(url)
            try:
                self.check_for_error(tree)

                # get the immediate response
                status = "OK"
                for child in tree:
                    if child.tag == "status":
                        status = child.text.rstrip()
                    if child.tag == "message":
                        message = child.text.rstrip()
                if status != "OK":
                    raise(Exception("Failure aborting physical security audit" +
                                    " : status=" + status + " : " + message))
            except Exception as e:
                raise(Exception("Error issuing securityAudit abort command: " +
                                 str(e)))

        except Exception as e:
            raise


    #--------------------------------------------------------------------------
    #
    # Determine the progress of a Security Audit (physical audit) of the
    # library.
    #
    # Returns two strings:
    #     status    indicates the status of the security audit
    #               (e.g. FAILURE, OK, etc)
    #     message   The message about the state/progress of the security audit
    #               (e.g. Security audit is not running.)
    # Indicating the status/progress of the security audit.
    #
    # If quiet=False, then prints the "<status> :: <message> to stdout
    #
    # Notes:
    #     * The securityAudit.xml command was added with BlueScale 12.8.01.
    #     * A return message of "Security audit is not running." indicates that
    #       the security audit is not running.
    #
    def securityauditstatus(self, quiet):

        try:
            url  = self.baseurl + "/securityAudit.xml?action=status"
            tree = self.run_command(url)

            status = "OK"
            message = "<invalid>"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                if child.tag == "message":
                    message = child.text.rstrip()
            else:
                if not quiet:
                    print(status + " :: " + message)
                    sys.stdout.flush()
                return(status, message)

        except Exception as e:
            raise


    #--------------------------------------------------------------------------
    #
    # Every 5 seconds poll the securityaudit status until the audit is not
    # running or reports a failure status.
    #
    def securityauditmonitor(self, sleep):
        try:
            status = "OK"
            while (status != "FAILURE"):
                status, message = self.securityauditstatus(True) # quiet
                print(str(datetime.datetime.now()) +
                      " :: " + status + " :: " + message)
                sys.stdout.flush()
                if (message == "Security audit is not running."):
                    break
                time.sleep(sleep)   # sleep before next poll

        except Exception as e:
            raise


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
                self.long_listing(tree, 0)
                return
            print(msgFormat. \
                format("Number", "Date", "Severity", "Message/Remedy"))
            print(msgFormat. \
                format("------", "-------------------", "-----------",
                       "--------------"))
            sys.stdout.flush()
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
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


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
                sys.stdout.flush()
                print("None")
                return

            # Handle long list option
            if self.longlist:
                self.long_listing(tree, 0)
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
                    sys.stdout.flush()
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
                        sys.stdout.flush()
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
                    sys.stdout.flush()
                elif child.tag == "pageNeedingProgressRequest":
                    print("\nPage Needing Progress Request")
                    print(  "-----------------------------")
                    print(child.text.rstrip())
                    sys.stdout.flush()

        except Exception as e:
            raise(e)


    #--------------------------------------------------------------------------
    #
    # Runs the advanced utility to check all magazine barcodes against the
    # stored inventory. Any moved or added magazine is pulled and its tapes are
    # scanned.
    #
    # Notes:
    #     * This command is supported on T200, T380, T680, T950, and TFinity
    #       libraries.
    #     * This utility only verifies the inventory of tapes within magazines
    #       that were moved or added since the last inventory.
    #     * The verification process takes 5 to 10 minutes per frame plus 1
    #       minute for each magazine that was moved or added since the last
    #       inventory.
    #     * During the verification process the robot(s) is unavailable.
    #     * This command was added with BlueScale12.6.41.
    #
    def verifymagazinebarcodes(self):

        try:
            url = self.baseurl + "/utils.xml?action=verifyMagazineBarcodes"

            # wait for a utils command in progress to complete
            firstTime = False
            while (not self.check_command_progress("utils", False)):
                # wait 1 seconds before retrying
                if not firstTime:
                    print("Waiting for pending utils command to complete...",
                        end='')
                    firstTime = True
                print(".", end='')
                time.sleep(1)
            if firstTime:
                print()     # newline
        except Exception as e:
            raise(e)

        # Verify magazine barcodes
        try:
            print("The verifyMagazineBarcode utility only verifies the",
                  "inventory of tapes within magazines that were moved or",
                  "added since the last inventory.")
            print("The verification process takes 5 to 10 minutes per frame",
                  "plus 1 minute for each magazine that was moved or added",
                  "since the last inventory.")
            print("\n*** During the verification process the robot(s) is",
                  "unavailable. ***")
            print("\n" + str(datetime.datetime.now()) + "\n")
            sys.stdout.flush()
            print("\nVerifying magazine barcodes...", end='')
            sys.stdout.flush()
            tree = self.run_command(url)

            # get the immediate response
            status = "OK"
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                if child.tag == "message":
                    message = child.text.rstrip()
            if status != "OK":
                print("failure")
                raise(Exception("Failure verifying magazine barcode : " +  \
                                message))
            # poll for utils to be done
            try:
                while (not self.check_command_progress("utils", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 3 seconds before retrying (this is a slow command)
                    time.sleep(3)
                print("OK")
                sys.stdout.flush()
            except Exception as e:
                raise(Exception(
                    "Verify magazine barcodes utils progress Error: " + str(e)))

        except Exception as e:
            raise(e)

        print("\n" + str(datetime.datetime.now()) + "\n")
        sys.stdout.flush()

#==============================================================================
# This area defines some routines for unit testing

    #--------------------------------------------------------------------------
    #
    # This routine will return an ElementTree for testing getAuditResults XML
    # (the audit results for one TeraPack).
    #
    def create_audit_results_XML_records(self):

        try:
            inventory = xml.etree.ElementTree.Element("inventory")

            auditResults = xml.etree.ElementTree.SubElement(inventory, "auditResults")

            elementType = xml.etree.ElementTree.SubElement(auditResults, "elementType")
            elementType.text = "storage"

            offset = xml.etree.ElementTree.SubElement(auditResults, "offset")
            offset.text = "1"

            magbarcode = xml.etree.ElementTree.SubElement(auditResults, "barcode")
            #magbarcode.text = "CL0123X" # LTO (10 slots)
            magbarcode.text = "CJ0123X" # TS11xx (9 slots)

            contentsMatch = xml.etree.ElementTree.SubElement(auditResults, "contentsMatch")
            contentsMatch.text = "no"

            expectedContents = xml.etree.ElementTree.SubElement(auditResults, "expectedContents")

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "1"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN001LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "2"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN002LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "3"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN003LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "4"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN004LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "5"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN005LX"

            #slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            #number = xml.etree.ElementTree.SubElement(slot, "number")
            #number.text = "6"
            #barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN006LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "7"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN007LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "8"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN008LX"
            #barcode.text = "CLNXX8LX"

            #slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            #number = xml.etree.ElementTree.SubElement(slot, "number")
            #number.text = "9"
            #barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN009LX"

            slot = xml.etree.ElementTree.SubElement(expectedContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "10"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN010LX"

            actualContents = xml.etree.ElementTree.SubElement(auditResults, "actualContents")

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "1"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN001LX"
            barcode.text = "CLNBADLX"

            #slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            #number = xml.etree.ElementTree.SubElement(slot, "number")
            #number.text = "2"
            #barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN002LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "3"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN003LX"

            #slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            #number = xml.etree.ElementTree.SubElement(slot, "number")
            #number.text = "4"
            #barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN004LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "5"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN005LX"

            #slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            #number = xml.etree.ElementTree.SubElement(slot, "number")
            #number.text = "6"
            #barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            #barcode.text = "CLN006LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "7"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN007LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "8"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN008LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "9"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN009LX"

            slot = xml.etree.ElementTree.SubElement(actualContents, "slot")
            number = xml.etree.ElementTree.SubElement(slot, "number")
            number.text = "10"
            barcode = xml.etree.ElementTree.SubElement(slot, "barcode")
            barcode.text = "CLN010LX"

        except Exception as e:
            raise(Exception("create_audit_results_XML_records Error creating XML"))

        return(inventory)


def check_range(arg, minval, maxval):

    try:
        value = int(arg)
    except ValueError as err:
       raise argparse.ArgumentTypeError(str(err))

    if value < minval or value > maxval:
        raise(argparse.ArgumentTypeError(f"Sleep argument expected to be between {minval} and {maxval} inclusive."))

    return value


#==============================================================================
def main():

    cmdparser     = argparse.ArgumentParser(description='Spectra Logic TFinity API Tool.')
    cmdsubparsers = cmdparser.add_subparsers(title="commands", dest="command")

    cmdparser.add_argument('--version', '-V', action='version', version='%(prog)s @VERSION@')

    cmdparser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                           help='Increase the verbosity for the output.')

    cmdparser.add_argument('--longlist', '-l', dest='longlist', action='store_true',
                           help='Format the output as a long listing; one     \
                           attribute per line. Easier for the human eye; but  \
                           difficult to parse.')

    cmdparser.add_argument('--insecure', '-i', dest='insecure', action='store_true',
                           help='Talk to library over http:// instead of https://')

    cmdparser.add_argument('--config', '-c', dest='configfile', nargs='?',
                           type=argparse.FileType('r'), default='/etc/slapi.conf',
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
        help='Returns controller status, type, firmware, and failover and     \
              port information.')

    drivelist_parser = cmdsubparsers.add_parser('drivelist',
        help='Returns detailed information about each of the drives in the    \
              library.')
    drivelist_parser.add_argument('--extended', '-e', action='store_true',
                                  help='Get extended information for each drive.')

    etherlibrefresh_parser = cmdsubparsers.add_parser('etherlibrefresh',
        help='Attempts to reestablish the Ethernet connection and update the  \
              stored status information for each EtherLib connection.')

    etherlibstatus_parser = cmdsubparsers.add_parser('etherlibstatus',
        help='Retrieve status of the library EtherLib connections.')

    gathersecurityauditlog_parser = cmdsubparsers.add_parser(
        'gathersecurityauditlog',
        help='Retrieves the specified Security Audit Log file from the library.')
    gathersecurityauditlog_parser.add_argument('filename', action='store',
        help='Security Audit Log file')

    generateasl_parser = cmdsubparsers.add_parser('generateasl',
        help='Generates a new AutoSupport Log (ASL) file')

    generatedrivetrace_parser = cmdsubparsers.add_parser('generatedrivetrace',
        help='Generates a new drive trace file. Only supported on LTO.')
    generatedrivetrace_parser.add_argument('driveID', action='store',
        help='LTO Drive ID')

    getaslfile_parser = cmdsubparsers.add_parser('getaslfile',
        help='Retrieves the specified AutoSupport Log (ASL) file from the     \
              library.')
    getaslfile_parser.add_argument('filename', action='store',
        help='AutoSupport Log file')

    getaslnames_parser = cmdsubparsers.add_parser('getaslnames',
        help='Returns a list of the AutoSupport Log (ASL) file names          \
              currently stored on the library.')

    getauditresults_parser = cmdsubparsers.add_parser('getauditresults',
        help='Retrieves the audit results collected by the command            \
              inventory.xml?action=audit command. The audit results can only  \
              be retrieved once. Note: inventoryaudit calls this for you.')

    getcanlog_parser = cmdsubparsers.add_parser('getcanlog',
        help='Retrieves the specified zip file containing Controller Area     \
              Network (CAN) logs from the Library Control Module (LCM).')
    getcanlog_parser.add_argument('filename', action='store',
        help='Controller Area Network (CAN) Log file')

    getcanlognames_parser = cmdsubparsers.add_parser('getcanlognames',
        help='Returns a list of the zip files containing the Controller Area  \
              Network (CAN) logs that are currently stored in the Library     \
              Control Module (LCM). The CAN logs collected for each day are   \
              zipped and stored on the hard drive in the LCM. Each zip        \
              filename includes the date it was created.')

    getdrivetraces_parser = cmdsubparsers.add_parser('getdrivetraces',
        help='Returns the last drive trace file generated by the              \
              generateDriveTraces action. The command returns a ZIP file in   \
              your cwd. Only supported on LTO.')

    getkernellog_parser = cmdsubparsers.add_parser('getkernellog',
        help='Retrieves the specified zip file containing kernel logs from    \
              the Library Control Module (LCM).')
    getkernellog_parser.add_argument('filename', action='store',
        help='Kernel Log file')

    getkernellognames_parser = cmdsubparsers.add_parser('getkernellognames',
        help='Returns a list of the zip files containing the kernel logs that \
              are currently stored in the Library Control Module (LCM). The   \
              kernel logs collected for each day are zipped and stored on the \
              hard drive in the LCM. Each zip filename includes the date it   \
              was created.')

    getmotionlogfile_parser = cmdsubparsers.add_parser('getmotionlogfile',
        help='Retrieves the specified Motion Log file from the library.')
    getmotionlogfile_parser.add_argument('filename', action='store',
        help='Motion Log file')

    getmotionlognames_parser = cmdsubparsers.add_parser('getmotionlognames',
        help='Returns a list of the Motion Log file names currently stored on the library.')

    getqiplog_parser = cmdsubparsers.add_parser('getqiplog',
        help='Retrieves the specified zip file containing Quad Interface      \
              Processor (QIP) logs from the Library Control Module (LCM).')
    getqiplog_parser.add_argument('filename', action='store',
        help='Controller Area Network (CAN) Log file')

    getqiplognames_parser = cmdsubparsers.add_parser('getqiplognames',
        help='Returns a list of the zip files containing the Quad Interface   \
              Processor (QIP) logs that are currently stored in the Library   \
              Control Module (LCM). The QIP logs collected for each day are   \
              zipped and stored on the hard drive in the LCM. Each zip        \
              filename includes the date it was created.')

    getsecurityauditlogfile_parser = cmdsubparsers.add_parser(
        'getsecurityauditlogfile',
        help='Retrieves the specified bzip2 Security Audit Log file from the  \
              library. This command will verify that the specified Security   \
              Audit Log file exists in the Robotics Control Module (RCM)      \
              and the Library Control Module (LCM). If it is missing from     \
              the RCM, then nothing can be done. If it is missing from the    \
              LCM, then it will download (i.e. gathered) from the RCM to the  \
              LCM). Next, it will pull it from the LCM and store it in the    \
              current working directory.')
    getsecurityauditlogfile_parser.add_argument('filename', action='store',
        help='Security Audit Log file')

    getsecurityauditlognames_parser = cmdsubparsers.add_parser(
        'getsecurityauditlognames',
        help='Returns a list of the security audit logs on the Robotics       \
              Control Modules (RCM) with an attribute to indicate             \
              which ones are also gathered and present on the Library         \
              Control Module (LCM). The LCM keeps no more than five           \
              security audit logs. There are two types of security            \
              audit logs: securityAuditInterim and securityAudit. The         \
              securityAuditInterim contains the logs collected between        \
              security audits. This includes information such as doors        \
              being opened. The securityAudit contains security audit         \
              logs. This includes information such as missing TeraPack        \
              magazines or tapes in unexpected slots. The log name            \
              for both types of logs contains the serial number of the        \
              library on which the security audit ran. The log name for       \
              an interim security audit includes a date/time indicating       \
              when the last audit ended; and, for a security audit the        \
              date/time indicates when the audit began.')

    gettapstate_parser = cmdsubparsers.add_parser('gettapstate',
        help='Returns the status of all TeraPack Access Ports (TAP)s.')

    gettrace_parser = cmdsubparsers.add_parser('gettrace',
        help='Returns the ASCII formatted data for the type of trace          \
              specified by the command.')
    gettrace_parser.add_argument('--force', '-f', action='store_true',
                                 help='Overwrite the previous trace')
    gettrace_parser.add_argument('gettrace',
        action='store',
        type=str.lower,
        choices=['action', 'autodriveclean', 'autosupport', 'backgroundclient',
                 'can', 'connection', 'encryption', 'error', 'etherlib',
                 'event', 'geometry', 'gpio', 'hhm', 'hydraexit',
                 'initialization', 'inventory', 'kernel', 'lock',
                 'logicallibrary', 'message', 'mlm', 'motion',
                 'motioninventory', 'motionoptions', 'motionrestart1',
                 'motionrestart2', 'packageupdate', 'pools', 'snmp',
                 'webserver'])

    hhmdata_parser = cmdsubparsers.add_parser('hhmdata',
        help='Returns a report showing the current data for all of the        \
              Hardware Health Monitoring (HHM) counters for the library.')

    inventoryaudit_parser = cmdsubparsers.add_parser('inventoryaudit',
        help='For each partition, this command compares the database inventory \
              of each TeraPack magazine to the inventory discovered by a       \
              barcode scan of the magazine. In the event of a mismatch, the    \
              inventory database is updated with the results of the scan,')

    inventoryall_parser = cmdsubparsers.add_parser('inventoryall',
        help='Lists all storage slots, entry/exit slots, and drives for all    \
              partitions.')

    inventorylist_parser = cmdsubparsers.add_parser('inventorylist',
        help='Lists all storage slots, entry/exit slots, and drives in the    \
              specified partition.')
    inventorylist_parser.add_argument('partition', action='store',
        help='Spectra Logic Partition')

    librarysettingslist_parser = cmdsubparsers.add_parser('librarysettingslist',
        help='Returns a list of the current library settings.')

    librarystatus_parser = cmdsubparsers.add_parser('librarystatus',
        help='Returns library type, serial number, component status and       \
              engineering change level information. With Headers')
    librarystatus2_parser = cmdsubparsers.add_parser('librarystatus2',
        help='Returns library type, serial number, component status and       \
              engineering change level information.')

    mlmsettings_parser = cmdsubparsers.add_parser('mlmsettings',
        help='Returns a list of the current Media Lifecycle Management (MLM)  \
              settings.')

    optionkeys_parser = cmdsubparsers.add_parser('optionkeys',
        help='optionkeys command help')
    optionkeys_subparser    = optionkeys_parser.add_subparsers(title="subcommands", dest="subcommand")
    optionkeys_list_parser  = optionkeys_subparser.add_parser('list', help='Returns a list of all active option keys' +
                                                                      'currently entered in the library')

    package_parser = cmdsubparsers.add_parser('package',
        help='package command help.')
    package_subparser       = package_parser.add_subparsers(title="subcommands", dest="subcommand")
    package_list_parser     = package_subparser.add_parser('list', help='Retrieves the name of the BlueScale packages ' +
                                                                   'stored on the memory card in the LCM')
    package_display_parser  = package_subparser.add_parser('display', help='Display details for the specified package')
    package_display_parser.add_argument('packagename', action='store', help='Name of the package to display')
    package_progress_parser = package_subparser.add_parser('progress', help='Update the library to the specified package')
    package_stage_parser    = package_subparser.add_parser('stage', help='Stage the specified package for update')
    package_stage_parser.add_argument('packagename', action='store', help='Name of the package to stage')
    package_update_parser   = package_subparser.add_parser('update', help='Update the library to the specified package')
    package_update_parser.add_argument('packagename', action='store', help='Name of the package to update the library to')
    package_upload_parser   = package_subparser.add_parser('upload', help='Upload the package file to the memory card on the LCM')
    package_upload_parser.add_argument('filename', action='store', help='BlueScale Software and Library Firmware package file')

    partitionlist_parser = cmdsubparsers.add_parser('partitionlist',
        help='List all Spectra Logic Library partitions.')

    physinventoryall_parser = cmdsubparsers.add_parser('physinventoryall',
        help='Retrieve a list of all occupied magazine and cartridge          \
              locations in all partitions. The list includes the              \
              offset value for each occupied magazine and slot, as well as    \
              the barcodes of the magazines and cartridges, if available.')

    physinventorylist_parser = cmdsubparsers.add_parser('physinventorylist',
        help='Retrieve a list of all occupied magazine and cartridge          \
              locations in the specified partition. The list includes the     \
              offset value for each occupied magazine and slot, as well as    \
              the barcodes of the magazines and cartridges, if available.')
    physinventorylist_parser.add_argument('partition', action='store',
        help='Spectra Logic Partition')

    rcmstatuslist_parser = cmdsubparsers.add_parser('rcmstatuslist',
        help='Displays the status of all the Robotics Control Modules (RCM).')

    resetdrive_parser = cmdsubparsers.add_parser('resetdrive',
        help='Resets the specified drive by power cycling it.')
    resetdrive_parser.add_argument('driveID', action='store', help='Drive ID')

    resethhmcounter_parser = cmdsubparsers.add_parser('resethhmcounter',
        help='Resets the specified Hardware Health Monitoring (HHM) counter to\
              zero. A counter is typically reset to zero following the        \
              completion of the regularly scheduled standard maintenance of   \
              the component.')
    resethhmcounter_parser.add_argument('resethhmcounter',
        action='store',
        type=str.lower,
        choices=['horizontal axis', 'vertical axis', 'picker axis',
                 'rotational axis', 'magazine axis', 'toggle axis',
                 'side axis', 'drive to drive move', 'drive to slot move',
                 'slot to slot move', 'slot to drive move', 'tap in move',
                 'tap out move'])
    resethhmcounter_parser.add_argument('subType',
        action='store',
        type=str.lower,
        choices=['trip1', 'trip2', 'none'])
    resethhmcounter_parser.add_argument('robot',
        action='store',
        type=str.lower,
        choices=['1', '2'])

    robotservice_parser = cmdsubparsers.add_parser('robotservice',
        help='Send robot to/from service bay.')
    robotservice_sleep_checkrange    = functools.partial(check_range, minval=5, maxval=120)
    robotservice_subparser           = robotservice_parser.add_subparsers(title="subcommands", dest="subcommand")
    robotservice_progress_parser     = robotservice_subparser.add_parser('progress', help='Get the progress of the robot service command')
    robotservice_toservicebay_parser = robotservice_subparser.add_parser('toservicebay', help='Send robot to the service bay')
    robotservice_toservicebay_parser.add_argument('--sleep',
        help="Set the polling interval in seconds",
        default=None,
        required=False,
        type=robotservice_sleep_checkrange)
    robotservice_toservicebay_parser.add_argument('robot',
        action='store',
        type=str.lower,
        default=None,
        choices=['1', '2'],
        help='Left robot (1) or right robot (2) when facing the front of the library.')
    robotservice_fromservicebay_parser = robotservice_subparser.add_parser('fromservicebay', help='Get robot from the service bay')
    robotservice_fromservicebay_parser.add_argument('--sleep',
        help="Set the polling interval in seconds",
        default=None,
        required=False,
        type=robotservice_sleep_checkrange)
    robotservice_fromservicebay_parser.add_argument('robot',
        action='store',
        type=str.lower,
        default=None,
        choices=['1', '2'],
        help='Left robot (1) or right robot (2) when facing the front of the library.')

    securityaudit_parser = cmdsubparsers.add_parser('securityaudit',
        help='securityaudit command help')
    securityaudit_subparser = securityaudit_parser.add_subparsers(
        title="subcommands",
        dest="subcommand")
    securityaudit_abort_parser = securityaudit_subparser.add_parser('abort',
        help='Stops a currently in-progress Security Audit (physical audit)   \
              of the library. This command was added with BlueScale 12.8.01.')
    securityaudit_monitor_parser = securityaudit_subparser.add_parser('monitor',
        help='Every 5 seconds poll the securityaudit status until the audit   \
              is not running or reports failure. You can also use --sleep with \
              poll time in seconds after the monitor keyword')
    securityaudit_monitor_parser.add_argument('--sleep', help="Set the polling \
              interval in seconds", default=5, required=False, type=int)
    securityaudit_start_parser = securityaudit_subparser.add_parser('start',
        help='Begin a Security Audit which is a physical audit of the entire  \
              library. This command was added with BlueScale 12.8.01.')
    securityaudit_status_parser = securityaudit_subparser.add_parser('status',
        help='Determine the progress of a Security Audit (physical audit) of  \
              the library. This command was added with BlueScale 12.8.01.')

    systemmessages_parser = cmdsubparsers.add_parser('systemmessages',
        help='Returns the list of system messages that are currently stored   \
              on the library. Most recent first.')

    tasklist_parser = cmdsubparsers.add_parser('tasklist',
        help='Returns the list of the extended action and background          \
              operations currently in process on the library.')

    verifymagazinebarcodes_parser = cmdsubparsers.add_parser(
        'verifymagazinebarcodes',
        help='***USE WITH CAUTION***ROBOTS UNAVAILABLE FOR A LONG TIME WHILE     \
              COMMAND RUNS***   \
              Runs the advanced utility to check all magazine barcodes against \
              the stored inventory. Any moved or added magazine is pulled and  \
              its tapes are scanned. This utility only verifies the inventory  \
              of tapes within magazines that were moved or added since the     \
              last inventory. The verification process takes 5 to 10 minutes   \
              per frame plus 1 minute for each magazine that was moved or      \
              added since the last inventory.')

    args = cmdparser.parse_args()

    if args.configfile is not None and args.configfile.name is not None:

        if args.configfile.name == "":
            raise(Exception("Error: CONFIGFILE not specified"))

        cfgparser = configparser.ConfigParser()
        cfgparser.read(args.configfile.name)

        try:
            config = cfgparser[args.server]
        except Exception as e:
            config = cfgparser["DEFAULT"]

        try:
            if args.user is None:
                if config.get("username"):
                    args.user   = config["username"]
            if args.passwd is None:
                if config.get("password"):
                    args.passwd = config["password"]
            if args.insecure is None or args.insecure == False:
                if config.get("insecure"):
                    args.insecure = config["insecure"]
            if args.verbose is None or args.verbose == False:
                if config.get("verbose"):
                    args.verbose = config["verbose"]

        except Exception as e:
            print(str(e))
            cmdparser.print_help()
            sys.exit(1)

    try:
        if args.server is None or args.server == "":
            raise(Exception("Error: SERVER not specified"))
        if args.user is None or args.user == "":
            raise(Exception("Error: USER not specified"))
        if args.passwd is None or args.passwd == "":
            raise(Exception("Error: PASSWD not specified"))
    except Exception as e:
        print(str(e))
        sys.exit(1)

    slapi = SpectraLogicAPI(args)

    try:
        if args.command is None:
            cmdparser.print_help()
            sys.exit(1)
        elif args.command == "controllerslist":
            slapi.controllerslist()
        elif args.command == "drivelist":
            slapi.drivelist(args.extended)
        elif args.command == "etherlibrefresh":
            slapi.etherlibrefresh()
        elif args.command == "etherlibstatus":
            slapi.etherlibstatus()
        elif args.command == "gathersecurityauditlog":
            slapi.gathersecurityauditlog(args.filename)
        elif args.command == "generateasl":
            slapi.generateasl()
        elif args.command == "generatedrivetrace":
            slapi.generatedrivetrace(args.driveID)
        elif args.command == "getaslfile":
            slapi.getaslfile(args.filename)
        elif args.command == "getaslnames":
            slapi.getaslnames()
        elif args.command == "getauditresults":
            slapi.getauditresults()
        elif args.command == "getcanlog":
            slapi.getcanlog(args.filename)
        elif args.command == "getcanlognames":
            slapi.getcanlognames()
        elif args.command == "getdrivetraces":
            slapi.getdrivetraces()
        elif args.command == "getkernellog":
            slapi.getkernellog(args.filename)
        elif args.command == "getkernellognames":
            slapi.getkernellognames()
        elif args.command == "getmotionlogfile":
            slapi.getmotionlogfile(args.filename)
        elif args.command == "getmotionlognames":
            slapi.getmotionlognames()
        elif args.command == "getqiplog":
            slapi.getqiplog(args.filename)
        elif args.command == "getqiplognames":
            slapi.getqiplognames()
        elif args.command == "getsecurityauditlogfile":
            slapi.getsecurityauditlogfile(args.filename)
        elif args.command == "getsecurityauditlognames":
            slapi.getsecurityauditlognames()
        elif args.command == "gettapstate":
            slapi.gettapstate()
        elif args.command == "gettrace":
            slapi.gettrace(args.gettrace, args.force)
        elif args.command == "hhmdata":
            slapi.hhmdata()
        elif args.command == "inventoryaudit":
            slapi.inventoryaudit()
        elif args.command == "inventoryall":
            slapi.inventoryall()
        elif args.command == "inventorylist":
            slapi.inventorylist(args.partition)
        elif args.command == "librarysettingslist":
            slapi.librarysettingslist()
        elif args.command == "librarystatus":
            slapi.librarystatus()
        elif args.command == "librarystatus2":
            slapi.librarystatus2()
        elif args.command == "mlmsettings":
            slapi.mlmsettings()
        elif args.command == "optionkeys":
            if args.subcommand is None or args.subcommand == "list":
                slapi.optionkeyslist()
            else:
                raise(Exception("optionkeys: Unknown option " + args.subcommand))
        elif args.command == "package":
            if args.subcommand is None or args.subcommand == "list":
                slapi.packagelist()
            elif args.subcommand == "display":
                slapi.packagedisplay(args.packagename)
            elif args.subcommand == "progress":
                slapi.packageprogress()
            elif args.subcommand == "update":
                slapi.packageupdate(args.packagename)
            elif args.subcommand == "upload":
                slapi.packageupload(args.filename)
            elif args.subcommand == "stage":
                slapi.packagestage(args.packagename)
            else:
                raise(Exception("package: Unknown option " + args.subcommand))
        elif args.command == "partitionlist":
            slapi.partitionlist()
        elif args.command == "physinventoryall":
            slapi.physinventoryall()
        elif args.command == "physinventorylist":
            slapi.physinventorylist(args.partition)
        elif args.command == "rcmstatuslist":
            slapi.rcmstatuslist()
        elif args.command == "resetdrive":
            slapi.resetdrive(args.driveID)
        elif args.command == "resethhmcounter":
            slapi.resethhmcounter(args.resethhmcounter,
                                  args.subType,
                                  args.robot)
        elif args.command == "robotservice":
            if args.subcommand is None or args.subcommand == "progress":
                slapi.robotservice(action="progress", robot=None, poll=None)
            else:
                slapi.robotservice(action=args.subcommand, robot=args.robot, poll=args.sleep)
        elif args.command == "securityaudit":
            if args.subcommand is None or args.subcommand == "start":
                slapi.securityaudit()
            elif args.subcommand == "abort":
                slapi.securityauditabort()
            elif args.subcommand == "monitor":
                slapi.securityauditmonitor(args.sleep)
            elif args.subcommand == "status":
                slapi.securityauditstatus(False)
            else:
                raise(Exception("securityaudit: Unknown option " + args.subcommand))
        elif args.command == "systemmessages":
            slapi.systemmessages()
        elif args.command == "tasklist":
            slapi.tasklist()
        elif args.command == "verifymagazinebarcodes":
            slapi.verifymagazinebarcodes()
        else:
            cmdparser.print_help()
            sys.exit(1)
    except Exception as e:
        fullcommand = args.command
        if hasattr(args, "subcommand") and args.subcommand is not None:
            fullcommand = args.command + " " + args.subcommand
        print("Command '" + fullcommand + "': " + str(e), file=sys.stderr)
        #if (args.verbose):
            #traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
