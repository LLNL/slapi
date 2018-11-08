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
    # Returns an XML element tree
    #
    def run_command(self, url):

        try:

            if self.verbose:
                print("--------------------------------------------------", file=sys.stderr)
                print("Command: " + url, file=sys.stderr)
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

            context = ssl._create_unverified_context()
            #context.set_ciphers('HIGH:!aNULL:!eNULL')
            context.set_ciphers('MEDIUM:!aNULL:!eNULL')

            opener    = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.cookiejar))
            opener.addheaders.append(("Cookie", "sessionID=" + self.sessionid))
            request   = urllib.request.Request(url)
            response  = opener.open(request)
            xmldoc    = response.read()
            tree      = xml.etree.ElementTree.fromstring(xmldoc)

            # Pretty print the XML document if verbose on
            self.print_xml_document(xmldoc)

            # check_for_error will raise an exception if it encounters a problem
            try:
                self.check_for_error(tree)
                return(tree)
            except SpectraLogicLoginError as e:
                try:
                    if (self.verbose):
                        print("Loginerror: Raised: " +
                            str(SpectraLogicLoginError.LoginErrorRaised),
                            file=sys.stderr)

                    if SpectraLogicLoginError.LoginErrorRaised == False:
                        SpectraLogicLoginError.LoginErrorRaised = True
                        if (self.verbose):
                            print("Re-issuing login")
                        self.login()
                        if (self.verbose):
                            print("Re-running command")
                        return(self.run_command(url))
                    else:
                        raise(e)
                except Exception as e:
                    raise(e)
            except Exception as e:
                raise(e)

        except Exception as e:
            raise(e)

    #--------------------------------------------------------------------------
    #
    # Runs the XML command
    # Returns the data as a string
    #
    def run_command_string(self, url):

        try:

            if self.verbose:
                print("--------------------------------------------------", file=sys.stderr)
                print("Command: " + url, file=sys.stderr)
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

            context = ssl._create_unverified_context()
            #context.set_ciphers('HIGH:!aNULL:!eNULL')
            context.set_ciphers('MEDIUM:!aNULL:!eNULL')

            opener    = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.cookiejar))
            opener.addheaders.append(("Cookie", "sessionID=" + self.sessionid))
            request   = urllib.request.Request(url)
            response  = opener.open(request)
            xmldoc    = response.read()

            # If we got an error from running the command, then we will be able
            # to successfully put into a tree and check for error records.
            checkerror = False
            try:
                tree = xml.etree.ElementTree.fromstring(xmldoc)
                checkerror = True

                # Pretty print the XML document if verbose on
                self.print_xml_document(xmldoc)

            except Exception as e:
                # It's okay if we couldn't turn the xmldoc into a tree; means
                # we've got some good binary data
                checkerror = False

            if checkerror:
                try:
                    self.check_for_error(tree)
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
                            self.login()
                            return(self.run_command_string(url))
                        else:
                            raise(e)
                    except Exception as e:
                        raise(e)
                except Exception as e:
                    raise(e)

            else:
                # Return the data as a string
                return(xmldoc)

        except Exception as e:
            raise(e)


    #==========================================================================
    # DEFINE COMMAND FUNCTIONS
    #==========================================================================


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
            status = statusRec.text.strip()
            if (status == "OK"):
                if verbose:
                    print("The '", command,
                          "' command has no pending commands. Status=", status)
                return(True)
            elif (status == "FAILED"):
                errorText = "Error: The '" + command + "' command FAILED"
                raise(Exception(errorText))
            else:
                if verbose:
                    print("New commands may not be submitted. ",
                          "The '", command,
                          "' command has a status of: ", status)
                return(False)

        except Exception as e:
            if (self.verbose):
                print("check_command_progress Error: " + str(e), file=sys.stderr)
                traceback.print_exc()
            raise(e)


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
            raise(Exception(e))

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
            if (self.verbose):
                traceback.print_exc()


    #--------------------------------------------------------------------------
    #
    # Display the current firmware version installed on individual components
    # in the library along with the firmware version included in the currently
    # installed BlueScale package version.
    #
    # Note: This action was added with BlueScale12.7.02.
    #
    def displaypackagedetails(self):

        headerFormat = '{:35} {:23} {:26}'
        listFormat = '{:25} {:15} {:15} {:13}'

        # first get the list of packages and find the currently running package
        try:
            url  = self.baseurl + "/package.xml?action=list"
            tree = self.run_command(url)
            if len(tree) == 0:
                raise(Exception("Error: No packages exist"))
            currentPackage = tree.find("current")
            if len(currentPackage) == 0:
                raise(Exception("Error: Unable to find currently running package element"))
            name = currentPackage.find("name")
            if name is None:
                raise(Exception("Error: Unable to get the currently running package name"))
            pgkName = name.text.strip()
        except Exception as e:
            print("Problem getting the currently running package name.")
            print("displayPackageDetails Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()
            return

        # Use the package name to get the details.  Note: XML documentation
        # dated June 2017 is missing information about needing the package
        # argument for the displayPackageDetails action.
        try:
            url  = self.baseurl + "/package.xml?action=displayPackageDetails&package=" + pgkName
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

        except Exception as e:
            print("displayPackageDetails Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
                self.long_listing(tree, 0)
                print("\ngetDriveLoadCount:");
                for drive in tree:
                    for element in drive:
                        if element.tag == "ID":
                            myid = element.text.rstrip()
                            print("  drive:")
                            print("    ID: " + myid);
                            loadCount = self.get_drive_load_count(myid)
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
                prettyWWN = ""
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
                        loadCount = self.get_drive_load_count(myid)

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

        except Exception as e:
            print("DriveList Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            if (self.verbose):
                traceback.print_exc()


    #--------------------------------------------------------------------------
    #
    # Generates a new AutoSupport Log (ASL) file
    #
    def generateasl(self):

        if not self.check_command_progress("autosupport", True):
            print("Will not issue generateasl command due to pending commands.")
            return

        try:
            url  = self.baseurl + "/autosupport.xml?action=generateASL"
            tree = self.run_command(url)

            # get the immediate response
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The autosupport generateASL command has been submitted: " + message)

            # poll for autosupport generateASL to be done
            try:
                while (not self.check_command_progress("autosupport", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                print("autosupport generateASL progress Error: " + str(e), file=sys.stderr)

            print("\nThe autosupport generateASL command has completed.")

        except Exception as e:
            print("generateasl Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            print("Error: The input drive (" + driveID + ") is not a valid drive.")
            return

        if driveID.find("LTO") == -1:
            print("Error: The input drive (" + driveID +
                  ") is not a valid LTO drive. This command only works on LTO drives.")
            return

        if not self.check_command_progress("driveList", True):
            print("Will not issue generatedrivetrace command due to pending commands.")
            return

        try:
            url  = self.baseurl + "/driveList.xml?action=generateDriveTraces&driveTracesDrives=" + driveID
            tree = self.run_command(url)

            # get the immediate response
            for child in tree:
                if child.tag == "status":
                    status = child.text.rstrip()
                elif child.tag == "message":
                    message = child.text.rstrip()
            if status == "OK":
                print("The driveList generateDriveTraces command has been submitted: " + message)

            # poll for driveList generateDriveTraces to be done
            try:
                while (not self.check_command_progress("driveList", False)):
                    # put out an in progress 'dot'
                    print(".", end='')
                    sys.stdout.flush()
                    # wait 1 seconds before retrying
                    time.sleep(1)
            except Exception as e:
                print("driveList generateDriveTraces progress Error: " + str(e), file=sys.stderr)

            print("\nThe driveList generateDriveTraces command has completed.")

        except Exception as e:
            print("generatedrivetrace Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            xmldoc = self.run_command_string(url)

            # Write the data to a file in the current working directory.
            # The name of the file is the same as the ASL name except:
            # - replace spaces with underscores
            # - append with .zip since it's a zip file.
            outputFilename = filename.replace(" ","_") + ".zip"
            f = open(outputFilename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + outputFilename + "'")

        except Exception as e:
            print("getaslfile Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
                    return
                for aslName in aslNames:
                    if aslName.tag == "ASLName":
                        print(aslName.text.rstrip())

        except Exception as e:
            print("getaslnames Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            xmldoc = self.run_command_string(url)

            # Write the data to a file in the current working directory.
            f = open('drivetraces.zip', 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: 'drivetraces.zip'")

        except Exception as e:
            print("getdrivetraces Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


    #--------------------------------------------------------------------------
    #
    # Retrieves the specified Motion Log file from the library
    # Outputs a filename in the current working directory that is the Motion
    # Log file name.
    #
    # NOTE: This API is not documented in the June 2017 (version K) of the
    # Spectra XML reference document.  Got the information from SpectraLogic
    # support.
    #
    def getmotionlogfile(self, filename):

        # check for traces commands in progress and wait until done
        try:
            if (not self.check_command_progress("traces", False)):
                print("There's a traces command in progress." +
                      "Will wait up to 5 minutes retrying.")
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
                        return
                print()
        except Exception as e:
            print("traces progress Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()
            return


        # getFullMotionLogNames
        try:
            # Check to see if the file has been gathered (i.e. downloaded from
            # RCM)
            print("Checking to see if the file needs to be gathered..." +
                  "i.e. downloaded from RCM")
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
                    print("Error: File not found. File=" + filename)
                    return

        except Exception as e:
            print("getFullMotionLogNames Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()
            return


        # gatherFullMotionLog
        try:
            # If the file hasn't been gathered (i.e. downloaded from the RCM),
            # then gather it.
            if gathered == "no":
                print("Gathering the full motion log for file: " + filename)
                url  = self.baseurl + "/traces.xml?action=gatherFullMotionLog&name=" + filename
                tree = self.run_command(url)
        except Exception as e:
            print("gatherFullMotionLog Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()
            return


        # poll for gatherFullMotionLog to be done
        try:
            while (not self.check_command_progress("traces", False)):
                # put out an in progress 'dot'
                print(".", end='')
                sys.stdout.flush()
                # wait 4 seconds before retrying
                time.sleep(4)
            print("\nGather is complete")
        except Exception as e:
            print("traces gatherFullMotionLog progress Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()
            return


        # getFullMotionLog
        try:
            print("Getting the full motion log file.")
            url  = self.baseurl + "/traces.xml?action=getFullMotionLog&name=" + filename

            # Call the run command wrapper that returns a string
            xmldoc = self.run_command_string(url)

            # Write the data to a file in the current working directory.
            # The name of the file is the same as the motion log name
            f = open(filename, 'wb')
            f.write(xmldoc)
            f.close()

            print("Successfully created: '" + filename + "'")

        except Exception as e:
            print("getmotionlogfile Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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

            for child in tree:
                if len(child) == 0:
                    print("None")
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

        except Exception as e:
            print("getmotionlognames Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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

        # build a url for each tapdevice/drawer combination
        for device in tapDevices:                   # for each TAP device type
            for i in range(1, tapDrawerCount+1):    # for each drawer
                doorOpen = magazinePresent = magazineSeated = "<unknown>"
                magazineType = rotaryPosition = "<unknown>"
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
                    continue

                # Perhaps when a device/drawer combination isn't present in our
                # system, we'll get no items.  Check for that and if so, just
                # move onto the next one.
                if len(tree) == 0:
                    print(fmt. \
                        format(device, str(i), doorOpen, magazinePresent,
                               magazineSeated, magazineType, rotaryPosition))
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
            if (self.verbose):
                traceback.print_exc()


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
            print("\nInventory List")
            print("--------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return
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
            if (self.verbose):
                traceback.print_exc()


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
                self.long_listing(tree, 0)
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
                # NOTE: wasn't able to test on NERF Tfinity as it
                # currently doesn't have any excessiveMoveFailures
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
            if (self.verbose):
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
            if (self.verbose):
                traceback.print_exc()


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
            if (self.verbose):
                traceback.print_exc()


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

        except Exception as e:
            print("MLMSettings Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            if (self.verbose):
                traceback.print_exc()


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
            for child in tree:
                if child.tag == "partitionName":
                    print(child.text.rstrip())

        except Exception as e:
            print("PartitionList Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
    def physinventorylist(self, partition):

        topHdrFormat = '{:19} {}'
        listFormat = '{:8} {:9} {:6} {:7} {:5} {:7} {:6} {:6} {:11}'

        try:
            url  = self.baseurl + "/physInventory.xml?action=list&partition=" + partition
            tree = self.run_command(url)
            print("\nPhysical Inventory List")
            print(  "-----------------------")
            if self.longlist:
                self.long_listing(tree, 0)
                return
            for part in tree:
                print(topHdrFormat.format("",
                    "----------------------Magazine-----------------------"))
                print(listFormat.
                    format("Parition", "MediaPool", "Offset", "Barcode",
                           "Frame", "TapeBay", "Drawer", "Slot", "SlotBarcode"))
                print(listFormat.
                    format("--------", "---------", "------", "-------",
                           "-----", "-------", "------", "------",
                           "-----------"))

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
                                for element in magazine:
                                    if (element.tag == "slot"):
                                        for slot in element:
                                            if (slot.tag == "number"):
                                                slotNumber = slot.text.rstrip()
                                            if (slot.tag == "barcode"):
                                                slotBarcode = slot.text.rstrip()
                                        print(listFormat.
                                            format(partition, mediaPool, offset,
                                                barcode, frameNumber,
                                                tapeBayNumber, drawerNumber,
                                                slotNumber, slotBarcode))

        except Exception as e:
            print("physinventorylist Error: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()



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
            if (self.verbose):
                traceback.print_exc()
            return

        # Next get the rcmstatus for each RCM
        try:

            print("\nRCM Status")
            print(  "----------")

            if not self.longlist:
                print(rcmFormat. \
                    format("RCM ID", "OverallStatus", "LoglibStatus",
                        "MotionStatus", "RepeaterStatus"))
                print(rcmFormat. \
                    format("----------", "-------------", "------------",
                           "------------", "--------------"))

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


        except Exception as e:
            print("rcmstatuslist Error getting RCM Status: " + str(e), file=sys.stderr)
            if (self.verbose):
                traceback.print_exc()


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
            if (self.verbose):
                traceback.print_exc()


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
            if (self.verbose):
                traceback.print_exc()


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

    displaypackagedetails_parser = cmdsubparsers.add_parser('displaypackagedetails',
        help='Display the current firmware version installed on individual components in the library along with the firmware version included in the currently installed BlueScale package version.')

    drivelist_parser = cmdsubparsers.add_parser('drivelist',
        help='Returns detailed information about each of the drives in the library.')

    etherlibstatus_parser = cmdsubparsers.add_parser('etherlibstatus',
        help='Retrieve status of the library EtherLib connections.')

    generateasl_parser = cmdsubparsers.add_parser('generateasl',
        help='Generates a new AutoSupport Log (ASL) file')

    generatedrivetrace_parser = cmdsubparsers.add_parser('generatedrivetrace',
        help='Generates a new drive trace file')
    generatedrivetrace_parser.add_argument('driveID', action='store', help='LTO Drive ID')

    getaslfile_parser = cmdsubparsers.add_parser('getaslfile',
        help='Retrieves the specified AutoSupport Log (ASL) file from the library.')
    getaslfile_parser.add_argument('filename', action='store', help='AutoSupport Log file')

    getaslnames_parser = cmdsubparsers.add_parser('getaslnames',
        help='Returns a list of the AutoSupport Log (ASL) file names currently stored on the library.')

    gettapstate_parser = cmdsubparsers.add_parser('gettapstate',
        help='Returns the status of all TeraPack Access Ports (TAP)s.')

    getmotionlogfile_parser = cmdsubparsers.add_parser('getmotionlogfile',
        help='Retrieves the specified Motion Log file from the library.')
    getmotionlogfile_parser.add_argument('filename', action='store', help='Motion Log file')

    getmotionlognames_parser = cmdsubparsers.add_parser('getmotionlognames',
        help='Returns a list of the Motion Log file names currently stored on the library.')

    getdrivetraces_parser = cmdsubparsers.add_parser('getdrivetraces',
        help='Returns the last drive trace file generated by the generateDriveTraces action. The command returns a ZIP file in your cwd.')

    hhmdata_parser = cmdsubparsers.add_parser('hhmdata',
        help='Returns a report showing the current data for all of the Hardware Health Monitoring (HHM) counters for the library.')

    inventorylist_parser = cmdsubparsers.add_parser('inventorylist',
        help='List inventory for the specified partition.')
    inventorylist_parser.add_argument('partition', action='store', help='Spectra Logic Partition')

    librarystatus_parser = cmdsubparsers.add_parser('librarystatus',
        help='Returns library type, serial number, component status and engineering change level information. With Headers')
    librarystatus2_parser = cmdsubparsers.add_parser('librarystatus2',
        help='Returns library type, serial number, component status and engineering change level information.')

    mlmsettings_ackagelist_parser = cmdsubparsers.add_parser('mlmsettings',
        help='Returns a list of the current Media Lifecycle Management (MLM) settings.')

    packagelist_parser = cmdsubparsers.add_parser('packagelist',
        help='Retrieves the name of the BlueScale package currently used by the library along with the list of packages currently stored on the memory card in the LCM.')

    partitionlist_parser = cmdsubparsers.add_parser('partitionlist',
        help='List all Spectra Logic Library partitions.')

    physinventorylist_parser = cmdsubparsers.add_parser('physinventorylist',
        help='Retrieve a list of all occupied magazine and cartridge locations in the specified partition. The list includes the offset value for each occupied magazine and slot, as well as the barcodes of the magazines and cartridges, if available.')
    physinventorylist_parser.add_argument('partition', action='store', help='Spectra Logic Partition')

    rcmstatuslist_parser = cmdsubparsers.add_parser('rcmstatuslist',
        help='Displays the status of all the Robotics Control Modules (RCM).')

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
    elif args.command == "displaypackagedetails":
        slapi.displaypackagedetails()
    elif args.command == "drivelist":
        slapi.drivelist()
    elif args.command == "etherlibstatus":
        slapi.etherlibstatus()
    elif args.command == "generateasl":
        slapi.generateasl()
    elif args.command == "generatedrivetrace":
        slapi.generatedrivetrace(args.driveID)
    elif args.command == "getaslfile":
        slapi.getaslfile(args.filename)
    elif args.command == "getaslnames":
        slapi.getaslnames()
    elif args.command == "getdrivetraces":
        slapi.getdrivetraces()
    elif args.command == "getmotionlogfile":
        slapi.getmotionlogfile(args.filename)
    elif args.command == "getmotionlognames":
        slapi.getmotionlognames()
    elif args.command == "gettapstate":
        slapi.gettapstate()
    elif args.command == "hhmdata":
        slapi.hhmdata()
    elif args.command == "inventorylist":
        slapi.inventorylist(args.partition)
    elif args.command == "librarystatus":
        slapi.librarystatus()
    elif args.command == "librarystatus2":
        slapi.librarystatus2()
    elif args.command == "mlmsettings":
        slapi.mlmsettings()
    elif args.command == "packagelist":
        slapi.packagelist()
    elif args.command == "partitionlist":
        slapi.partitionlist()
    elif args.command == "physinventorylist":
        slapi.physinventorylist(args.partition)
    elif args.command == "rcmstatuslist":
        slapi.rcmstatuslist()
    elif args.command == "systemmessages":
        slapi.systemmessages()
    elif args.command == "tasklist":
        slapi.tasklist()
    else:
        cmdparser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
