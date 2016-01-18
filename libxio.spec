%bcond_with devel_mode
%bcond_without kmod
%define debug_package %{nil}

Name:    libxio
Version: 1.6
Release: 2%{?dist}
Summary: Accelio - The Open Source I/O, Message, and RPC Acceleration Library

Group:   System Environment/Libraries
License: GPLv2 or BSD
Url:     http://www.accelio.org/
Source:  http://github.com/accelio/accelio/archive/v%{version}.tar.gz

BuildRequires: autoconf, libtool
BuildRequires: numactl-devel, libaio-devel, libibverbs-devel, librdmacm-devel
%if %{with kmod}
BuildRequires: kernel-devel
%endif

%description
Accelio provides an easy-to-use, reliable, scalable,
and high performance data/message delivery middleware
that maximizes the efficiency of modern CPU and NIC hardware
and that reduces time-to-market of new scale-out applications.


%package devel
Summary: Development files for the libxio library
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release} libibverbs-devel%{?_isa}

%description devel
Development files for the libxio library.

%if 0%{with kmod}
%package kmod
Summary: Accelio Kernel Modules
Group: System Environment/Libraries

%description kmod
Accelio Kernel Modules
%endif


%prep
%setup -q -n accelio-%{version}

%build
./autogen.sh

%configure \
	--disable-static \
%if 0%{with kmod}
	--enable-kernel-module \
%endif
%if 0%{without devel_mode}
	--enable-stat-counters=no \
	--enable-extra-checks=no \
%endif

make %{?_smp_mflags}


%install
make DESTDIR=%{buildroot} install

# remove unpackaged files from the buildroot
find %{buildroot} -name '*.la' -exec rm -f {} ';'


%files
%if 0%{without kmod}
%{_bindir}/*
%{_libdir}/libxio.so*
%{_libdir}/libraio.so*
%endif
%doc AUTHORS COPYING README

%files devel
%if 0%{with kmod}
/opt/*
%else
%{_includedir}/*
%endif

%if 0%{with kmod}
%files kmod
/lib/modules/*
%endif

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%if 0%{with kmod}
%post kmod
depmod -a

%postun kmod
depmod -a
%endif


%changelog
* Fri Jan 15 2016 Vladislav Odintsov <odivlad@gmail.com> 1.6-2
- Added devel mode build (enabled perfcounters and extra checks)
- Added support for kernel module build

* Tue Nov 17 2015 Mikhail Ushanov <gm.mephisto@gmail.com> 1.6-1
- Bump version accelio to 1.6

* Tue Nov 17 2015 Mikhail Ushanov <gm.mephisto@gmail.com> 1.5-1
- Initial spec file
