Name:
Version:
Release:
Summary:       Utility that talks to Spectra Logic libraries.
License:       LLNL
Group:         System Environment/Base
Source:        %{name}-%{version}.tar
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root
ExclusiveArch: x86_64
Requires:      python(abi) = 3.4
Requires:      python34-requests

%define __spec_install_post /usr/lib/rpm/brp-compress || :
%define debug_package %{nil}
%define hpss_prefix /hpss

%description
This is a tool that talks to the Spectra Logic libraries using their XML API.

%prep
%setup -q

%build
umask 002

# Only do the make if this is not a snapshot build
%if %{?snapshot:0}%{!?snapshot:1}
make -S
%endif

%install
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

mkdir -p ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p ${RPM_BUILD_ROOT}%{_sbindir}
mkdir -p ${RPM_BUILD_ROOT}%{_libdir}
mkdir -p ${RPM_BUILD_ROOT}%{_includedir}
 
# Install products for rpms
cp -p -R -L src/slapi.py                             ${RPM_BUILD_ROOT}%{_bindir}/slapi

# Properly set permissions
find ${RPM_BUILD_ROOT}              -type d | xargs chmod 0755
find ${RPM_BUILD_ROOT}              -type f | xargs chmod +X,u+rw,g+r,g-w,o+r,o-w,-s

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root,0755)
%{_bindir}/slapi

%changelog
* Fri Dec 28 2018 Herb Wartens <wartens2@llnl.gov>              - 0.1-1alpha
- Initial slapi package
