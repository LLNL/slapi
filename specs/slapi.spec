Name:
Version:
Release:
Summary:       Utility that talks to Spectra Logic libraries.
License:       GPLv2+
Group:         System Environment/Base
Source:        %{name}-%{version}.tar
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root
ExclusiveArch: x86_64
BuildRequires: python(abi) >= 3.4
Requires:      python(abi) >= 3.4
Requires:      python34-requests

%define __spec_install_post /usr/lib/rpm/brp-compress || :
%define debug_package %{nil}

%description
This is a tool that talks to the Spectra Logic tape libraries using their XML API.

%prep
%setup -q

%build
umask 002

# Only do the make if this is not a snapshot build
%if %{?snapshot:0}%{!?snapshot:1}
cd src
sh ./autogen.sh
%configure
make -s
%endif

%install
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

mkdir -p ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p ${RPM_BUILD_ROOT}%{_sbindir}
mkdir -p ${RPM_BUILD_ROOT}%{_libdir}
mkdir -p ${RPM_BUILD_ROOT}%{_includedir}

# AIX make does not like -C so actually
# change into this directory here.
cd src || exit -1
DESTDIR="${RPM_BUILD_ROOT}" make install
cd .. || exit -1
 
%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root,0755)
%dir %{_datadir}/doc/%{name}
%doc %{_datadir}/doc/%{name}/AUTHORS
%doc %{_datadir}/doc/%{name}/COPYING
%doc %{_datadir}/doc/%{name}/INSTALL
%doc %{_datadir}/doc/%{name}/NEWS
%doc %{_datadir}/doc/%{name}/README
%{_bindir}/slapi

%changelog
* Fri Dec 28 2018 Herb Wartens <wartens2@llnl.gov>              - 0.1-1alpha
- Initial slapi package
