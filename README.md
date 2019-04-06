# SLAPI

SLAPI is a command-line tool that communicates with Spectra Logic tape
libraries using their XML command reference.  This provides a simple way to
administer and monitor Spectra Logic tape libraries in large data centers.

Getting Started
----------------

In order to use SLAPI, you must have python3 installed on your system.  On RHEL
distributions, it would be simplest to ensure your systems have the EPEL
repository enabled.  Our RHEL7-based systems have python34 installed.  

    $ yum install python34-requests
    <snip>
    ===============================================================================
     Package                      Arch          Version          Repository   Size
    ===============================================================================
    Installing:
     python34-requests            noarch        2.12.5-3.el7     epel         110 k
    Installing for dependencies:
     python34-chardet             noarch        2.3.0-5.el7      epel         237 k
     python34-idna                noarch        2.7-2.el7        epel         108 k
     python34-pysocks             noarch        1.6.8-6.el7      epel          30 k
     python34-six                 noarch        1.11.0-3.el7     epel          33 k
     python34-urllib3             noarch        1.19.1-5.el7     epel         132 k

    Transaction Summary
    ===============================================================================
    Install  1 Package (+5 Dependent packages)
    <snip>

Documentation
----------------

Currently the documentation for SLAPI is provided with the help option.

    $ slapi --help

Contributing
----------------
See CONTRIBUTING.md


Release
----------------

SPDX-License-Identifier: GPL-2.0-or-later

LLNL-CODE-769480
