#!/usr/bin/perl
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

use Cwd;
use File::Copy;
use File::Path;
use File::Spec;
use File::Basename;
use File::Temp qw/ tempfile tempdir /;
use Getopt::Long;
use strict;

my $topdir    = "";
my $sourcedir = "";
my $specfile  = "";
my $packagename = "";
my $packageversion = "";
my $packagerelease = "";
my $dist = "";
my $scmtype = "";
my $scmurl = "";
my $start = "";
my $end = "";
my $buildsource = "";
my $snapshot = "";
my $target = "";
my $os = `uname`; chomp($os);

sub parse_args
{
    GetOptions("s|source=s"   => \$sourcedir,
               "f|specfile=s" => \$specfile,
               "n|name=s"     => \$packagename,
               "v|version=s"  => \$packageversion,
               "r|release=s"  => \$packagerelease,
               "b|builddir=s" => \$topdir,
               "scmtype=s"    => \$scmtype,
               "scmurl=s"     => \$scmurl,
               "target=s"     => \$target,
               "buildsource"  => \$buildsource,
               "snapshot"     => \$snapshot);

    if (!$sourcedir && !$scmtype)
    {
        print(STDERR "Source directory needs to be set.\n");
        exit(-1);
    }
    elsif ($sourcedir && $scmtype)
    {
        print(STDERR "Please only specify one of sourcedir or scmtype.\n");
        exit(-1);
    }
    elsif ((! -e $sourcedir || ! -d $sourcedir) && !$scmtype)
    {
        print(STDERR "$sourcedir needs to be set to an existing directory.\n");
        exit(-1);
    }
    elsif ($scmtype && !$scmurl)
    {
        print(STDERR "Please specify scmurl.\n");
        exit(-1);
    }

    if (!$specfile && !$scmtype)
    {
        print(STDERR "Specfile needs to be set.\n");
        exit(-1);
    }
    elsif ($specfile && $scmtype)
    {
        print(STDERR "Please only specify one of specfile or scmtype.\n");
        exit(-1);
    }
    elsif ((! -e $specfile || ! -f $specfile) && !$scmtype)
    {
        print(STDERR "$sourcedir needs to be set to an existing file.\n");
        exit(-1);
    }

    # set sourcedir to absolute path
    $sourcedir = File::Spec->rel2abs($sourcedir);

    # Try to get the version information from the VERSION and VERSION_IBM files
    if (!$packageversion)
    {
        $packageversion = `cat VERSION`; chomp($packageversion);
    }
    if (!$packagerelease)
    {
        $packagerelease = `cat RELEASE`; chomp($packagerelease);
    }

    # Ensure that packagename and such are properly set
    if (basename($sourcedir) =~ m#^(\S+)-(\S+)-?(\S+)?#)
    {
        if (!$packagename)
        {
            $packagename = $1;
        }
        if (!$packageversion)
        {
            $packageversion = $2;
        }
        if (!$packagerelease)
        {
            $packagerelease = $3;
        }
    }
    if (!$packagename || !$packageversion)
    {
        print(STDERR "Package Name or Version is not set.\n");
        exit(-1);
    }
    if (!$packagerelease)
    {
        print(STDERR "Package Release is not set.\n");
        exit(-1);
    }

    # For now set our default topdir to $HOME
    # since our local disk is deadly slow.
    if (!$topdir || ! -e $topdir)
    {
        # Build in /scratch if it exists...
        # Otherwise try to build in /var/tmp
        if ( -e "/scratch" )
        {
            mkdir("/scratch/$ENV{USER}");
            $topdir = "/scratch/$ENV{USER}/build";
        }
        else
        {
            mkdir("/var/tmp/$ENV{USER}");
            $topdir = "/var/tmp/$ENV{USER}/build";
        }
        mkdir($topdir);

        if ($snapshot)
        {
            $topdir .= "/build-${packagename}-${packageversion}";
            mkdir($topdir);
        }
        else
        {
            $topdir = tempdir("$topdir/build-$ENV{USER}.XXXXXXXX");
        }
    }
    else
    {
        if ($snapshot)
        {
            $topdir = "$topdir/build-${packagename}-${packageversion}";
            mkdir($topdir);
        }
        else
        {
            $topdir = tempdir("$topdir/build-$ENV{USER}.XXXXXXXX");
        }
    }
    print("Setting builddir to: ${topdir}\n");

    if ($snapshot)
    {
        $dist = `date +'%Y%m%d%H%M%S'`; chomp($dist);
        $dist = ".$ENV{USER}.$dist";
    }
    
    print("NAME: $packagename\n");
    print("VERSION: $packageversion\n");
    print("RELEASE: $packagerelease\n");
    print("DIST: $dist\n");
}

sub create_tmp_structure
{
    mkdir("$topdir/BUILD");
    mkdir("$topdir/RPMS");
    mkdir("$topdir/SOURCES");
    mkdir("$topdir/SPECS");
    mkdir("$topdir/SRPMS");
}

sub build_tarball
{
    my $tar = `which tar`; chomp($tar);
    my $gzip = `which gzip`; chomp($gzip);
    my $rsync = `which rsync`; chomp($rsync);
    my $svn = `which svn`; chomp($svn);
    my $git = `which git`; chomp($git);
    my $dirname = "";
    my $fullpathtosource = "";
    my $savedir = "";
    my $cmd = "";
    my $rc = 0;

    if (!$tar)
    {
        print(STDERR "tar is not in your path.\n");
        exit(-1);
    }

    if (!$gzip)
    {
        print(STDERR "gzip is not in your path.\n");
        exit(-1);
    }

    if (!$rsync)
    {
        print(STDERR "rsync is not in your path.\n");
        exit(-1);
    }

    if ($scmtype eq "git")
    {
        if (!$git)
        {
            print(STDERR "git is not in your path.\n");
            exit(-1);
        }
        if (!$scmurl)
        {
            print(STDERR "scmurl not specified.\n");
            exit(-1);
        }

        $savedir = getcwd();
        chdir($topdir);
        $cmd = "$git clone --branch ${packagename}-${packageversion}-${packagerelease} ${scmurl} ${packagename}-${packageversion}";
        print("$cmd\n");
        $rc = system("$cmd");
        $rc = $rc >> 8;
        if ($rc != 0)
        {
            print(STDERR "Problem copying source to temp directory.\n");
            exit(-1);
        }

        # Copy the specfile outside of tree
        # This assumes that the specfile is named ${packagename}.spec
        # e.g hpss.spec
        my $fromspec = "";
        $fromspec = "${topdir}/${packagename}-${packageversion}/specs/${packagename}.spec";
        $specfile = "${topdir}/${packagename}.spec";
        if (! -e "$fromspec")
        {
            print(STDERR "$fromspec does not exist.\n");
            exit(-1);
        }
        copy($fromspec, $specfile);
    }
    elsif ($scmtype eq "svn")
    {
        if (!$svn)
        {
            print(STDERR "svn is not in your path.\n");
            exit(-1);
        }
        if (!$scmurl)
        {
            print(STDERR "scmurl not specified.\n");
            exit(-1);
        }

        $savedir = getcwd();
        chdir($topdir);
        $cmd = "$svn co $scmurl/tags/${packagename}-${packageversion}-${packagerelease} ${packagename}-${packageversion}";
        print("$cmd\n");
        $rc = system("$cmd");
        $rc = $rc >> 8;
        if ($rc != 0)
        {
            print(STDERR "Problem copying source to temp directory.\n");
            exit(-1);
        }

        # Copy the specfile outside of tree
        # This assumes that the specfile is named ${packagename}.spec
        # e.g hpss.spec
        my $fromspec = "";
        $fromspec = "${topdir}/${packagename}-${packageversion}/specs/${packagename}.spec";
        $specfile = "${topdir}/${packagename}.spec";
        if (! -e "$fromspec")
        {
            print(STDERR "$fromspec does not exist.\n");
            exit(-1);
        }
        copy($fromspec, $specfile);
    }
    else
    {
        # Recursively copy the source to the temp directory
        $cmd = "$rsync -PrptLz --delete --exclude=.svn --exclude=.pc --exclude=RPMS --exclude=*.rpm " . "$sourcedir/" . " ${topdir}/${packagename}-${packageversion}";
        print("$cmd\n");
        $rc = system("$cmd");
        $rc = $rc >> 8;
        if ($rc != 0)
        {
            print(STDERR "Problem copying source to temp directory.\n");
            exit(-1);
        }
        $savedir = getcwd();
        chdir($topdir);
    }

    $dirname = "${packagename}-${packageversion}";
    $rc = system("$tar chvf $dirname.tar $dirname");
    $rc = $rc >> 8;
    chdir($savedir);
    if ($rc != 0)
    {
        print(STDERR "Problem generating tarball.\n");
        exit(-1);
    }

    print("Placing $dirname.tar in ${topdir}/SOURCES\n");
    move("${topdir}/$dirname.tar", "${topdir}/SOURCES");
}

sub build_specfile
{
    my $tmpspec = "${topdir}/SPECS/" . basename($specfile);
    my $rc = 0;
    
    if(!open(SPECIN, "<", $specfile))
    {
        print(STDERR "Could not open: $specfile for reading.\n");
        exit(-1);
    }

    if(!open(SPECOUT, ">", $tmpspec))
    {
        print(STDERR "Could not open: $tmpspec for writing.\n");
        exit(-1);
    }

    while(my $line = <SPECIN>)
    {
        if ($line =~ m#^\s*Name:#)
        {
            print(SPECOUT "Name:       $packagename\n");
        }
        elsif ($line =~ m#^\s*Version:#)
        {
            print(SPECOUT "Version:    $packageversion\n");
        }
        elsif ($line =~ m#^\s*Release:#)
        {
            print(SPECOUT "Release:    $packagerelease$dist\%\{\?dist\}\n");
        }
        else
        {
            print(SPECOUT "$line");
        }
    }

    close(SPECIN);
    close(SPECOUT);
}

sub build_rpm
{
    my $rpm = "";
    my $extra = "";
    my $cmd = "";
    my $rc = 0;

    $rpm = `which rpmbuild`; chomp($rpm);
    if (!$rpm)
    {
	$rpm = `which rpm`; chomp($rpm);
	if (!$rpm)
	{
	    print(STDERR "rpm is not in your path.\n");
	    exit(-1);
	}
    }

    if ($snapshot)
    {
        $extra .= "--define \'snapshot  1\' ";
    }

    if ($buildsource)
    {
        $extra .= "--define \'buildsource 1\' "
    }

    if ($target)
    {
        $extra .= "--target \'$target\' ";
    }

    $cmd = "$rpm -bb --define \'_topdir ${topdir}\' ${extra} ${topdir}/SPECS/" . basename($specfile);
    print("$cmd\n");
    $rc = system("$cmd");
    $rc = $rc >> 8;
    if ($rc != 0)
    {
        print(STDERR "Problem building rpm(s).\n");
        exit(-1);
    }
}

sub copy_rpms
{
    my $dir;
    my $file;

    # Copy SRPMS
    foreach $file (<${topdir}/SRPMS/*>)
    {
        print("$file\n");
        chmod(0644, $file);
        move($file, ".");
    }

    # Copy RPMS
    foreach $dir (<${topdir}/RPMS/*>)
    {
        foreach $file (<$dir/*>)
        {
            print("$file\n");
            chmod(0644, $file);
            move($file, ".");
        }
    }
}

sub remove_tree
{
    if (!$snapshot)
    {
        rmtree($topdir);
    }
}

######
# Main
######
$start = `date`; chomp($start);
print("START TIME: $start\n");
parse_args();
create_tmp_structure();
build_tarball();
build_specfile();
build_rpm();
copy_rpms();
remove_tree();
$end = `date`; chomp($end);
print("END TIME: $end\n");
