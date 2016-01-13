%define _muser vzmig
%define _mhome /var/lib/%{_muser}

%define _basename vzmigrate
%{?coverage:%define _coverage %{coverage}}
%{!?coverage:%define _coverage 0}

Summary: @PRODUCT_NAME_LONG@ migrate utility
%if %_coverage
Name:	%{_basename}-coverage
Provides: %{_basename}
Obsoletes: %{_basename}
%else
Name:   %{_basename}
%endif
Version: 6.1.0
Release: 88
Vendor: Parallels, Inc.
License: Parallels
Group: System Environment/Kernel
Source: vzmigrate.tar.bz2
ExclusiveOS: Linux
BuildRoot: %{_tmppath}/%{_basename}-%{version}-root
BuildRequires: libfiu libfiu-devel
BuildRequires: vzmodules-devel >= 2.4.20-021stab022
BuildRequires: perl >= 5.6.0
BuildRequires: libvzctl >= 6.1.0-139 libvzctl-devel >= 6.1.0-139
BuildRequires: openssl-devel >= 0.9.8b
BuildRequires: libvzsock >= 5.0.0-5
BuildRequires: libvzsock-devel >= 5.0.0-5
%ifarch ia64
BuildRequires: ia64_syscall
%endif
BuildRequires: ploop-devel >= 6.1.0-75
BuildRequires: ploop-lib >= 6.1.0-75
BuildRequires: prlcompress-devel >= 7.0.0-1
BuildRequires: libuuid-devel
Requires: vzmodules >= 2.4.20-021stab022
Requires: rsync-static >= 2.5.7
Requires: perl >= 5.6.0
Requires: vzctl >= 6.1.0-119
Requires: libvzctl >= 6.1.0-139
Requires: vztt >= 6.0.9-60, vztt-lib >= 6.0.9-60
Requires: vzquota >= 6.0.1-3
Requires: tar
Requires: pmigrate
Requires: prlcompress-lib >= 7.0.0-1
Requires: ploop-lib >= 6.1.0-75
Provides: pmigrate.c2c

%description
This utility can be used to migrate Containers between physical servers running the Parallels
Containers software.

%package fault_injection
Summary: @PRODUCT_NAME_LONG@ migrate utility builded with libfiu
Group: System Environment/Kernel
Provides: %{_basename}
Obsoletes: %{_basename}
Conflicts: %{_basename}

%description fault_injection
This utility can be used to migrate Containers between physical servers running the Parallels
Containers software.


%prep
%setup -n vzmigrate
%build
%if %_coverage
CFLAGS="-fprofile-arcs -ftest-coverage" \
	CXXFLAGS="-fprofile-arcs -ftest-coverage" \
	make LGCOV="-lgcov -lgssapi_krb5 -lidn"
%else
CFLAGS="$RPM_OPT_FLAGS" make
%endif

%install
rm -rf $RPM_BUILD_ROOT
make PREFIX=$RPM_BUILD_ROOT install
%if %_coverage
mkdir -p ${RPM_BUILD_ROOT}/%_builddir/%{_basename}
cp -a * ${RPM_BUILD_ROOT}/%_builddir/%{_basename}
%endif
make clean
CFLAGS="$RPM_OPT_FLAGS" make FIU_ENABLE=yes
for binary in vzmsrc vzmdest vzmpipe vzmd vzmigrate; do
	install -m 755 ${binary} ${RPM_BUILD_ROOT}/%{_sbindir}/${binary}_fiu
done

%post fault_injection
/usr/sbin/userdel -rf %{_muser} >/dev/null 2>&1 || /bin/true
/usr/sbin/useradd -r -d %{_mhome} -s %{_sbindir}/vzmpipe %{_muser}	|| [ $? -eq 9 ]
mkdir -p %{_mhome}/.ssh
:

%postun fault_injection
for binary in vzmsrc vzmdest vzmpipe vzmd vzmigrate; do
	rm -f %{_sbindir}/${binary}
done
if [ $1 -eq 0 ]; then
	/usr/sbin/userdel -r %{_muser} >/dev/null 2>&1 || /bin/true
fi
:

%posttrans fault_injection
for binary in vzmsrc vzmdest vzmpipe vzmd vzmigrate; do
	ln -s ${binary}_fiu %{_sbindir}/${binary}
done

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(755,root,root) %{_sbindir}/vzmsrc
%attr(755,root,root) %{_sbindir}/vzmdest
%attr(755,root,root) %{_sbindir}/vzmd
%attr(644,root,root) %{_mandir}/man8/vzmigrate.8.*
%attr(644,root,root) %{_mandir}/man8/vzmlocal.8.*
%attr(644,root,root) %{_mandir}/man8/vzmsrc.8.*
%{_mandir}/man8/vzmdest.8.*
%{_mandir}/man8/vzmdestmpl.8.*
%{_sbindir}/vzmigrate
%{_sbindir}/vzmlocal
%{_sbindir}/vzmdestmpl
%{_datadir}/pmigrate/pmigrate.c2c
%attr(755,root,root) %{_sbindir}/vzmpipe
%attr(644,root,root) %{_mandir}/man8/vzmpipe.8.*
%if %_coverage
%{_builddir}/%{_basename}
%endif

%files fault_injection
%defattr(-,root,root)
%attr(755,root,root) %{_sbindir}/*_fiu
%attr(644,root,root) /usr/share/%{_basename}/fiu.all
{_datadir}/pmigrate/pmigrate.c2c

%post 
/usr/sbin/userdel -rf %{_muser} >/dev/null 2>&1 || /bin/true
/usr/sbin/useradd -r -d %{_mhome} -s %{_sbindir}/vzmpipe %{_muser}	|| [ $? -eq 9 ]
mkdir -p %{_mhome}/.ssh
:
%postun
if [ $1 -eq 0 ]; then
	/usr/sbin/userdel -r %{_muser} >/dev/null 2>&1 || /bin/true
fi
:

%changelog
* Thu Nov 10 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-192
- do not fail on template migration if template is not cached
  (https://jira.sw.ru/browse/PSBM-10158)

* Mon Sep  5 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-88
- to forbid to send vzevents in ps mode
  (https://jira.sw.ru/browse/PSBM-9463)

* Wed Aug 24 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-85
- do not lock target CT for CT rename via MigrateStateLocal::h_copy_local_cp()
  and MigrateStateCommon::h_rename() (https://jira.sw.ru/browse/PVCA-660)

* Mon Aug 15 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-84
- if tar exited with retcode 1, show warning and continue
  (https://jira.sw.ru/browse/PCLIN-29957)
- to allow migrate any types of CT exclude temporary
  (https://jira.sw.ru/browse/PSBM-9154)

* Fri Aug 12 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-82
- use only rsync on dst side for vzmsrc v. 3.0
  (https://jira.sw.ru/browse/PSBM-9143)

* Fri Aug  5 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-81
- fix vzmiterind start on ps mode
  (https://jira.sw.ru/browse/PSBM-9045)

* Wed Aug  3 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-80
- do not lock private area on target for shared private onr gfs/gfs2
  (https://jira.sw.ru/browse/PCLIN-29890)

* Wed Aug  3 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-79
- fix for gfs2 (https://jira.sw.ru/browse/PCLIN-29883)

* Thu Jul 28 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-78
- do not start tar if nothing to sync in template area
  (https://jira.sw.ru/browse/PSBM-8930)

* Wed Jul 27 2011 Konstantin Volckov <wolf@parallels.com> 5.0.0-76
- Redirect userdel output to /dev/null, see #PSBM-8869

* Wed Jul 27 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-75
- to start CT memory migration just before suspend
  (https://jira.sw.ru/browse/PCLIN-29787)

* Tue Jul 26 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-74
- for CPT operations on dst size will set context id as target CTID
  (https://jira.sw.ru/browse/PCLIN-29802)

* Tue Jul 19 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-74
- try IPv4 and IPv6 for ssh port forwarding (https://jira.sw.ru/browse/PCLIN-29747)

* Mon Jul 18 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-72
- disk space check for std-template CT fixed (https://jira.sw.ru/browse/PCLIN-29739)

* Tue Jul 12 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-69
- to forbid online migration from 3.0 (https://jira.sw.ru/browse/PCLIN-29679)
- tar & rsync command line fixed for template area migration
  (https://jira.sw.ru/browse/PCLIN-29625)

* Mon Jul 11 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-68
- do not randomize crontab jobs on migration, do it for clone only
  (https://jira.sw.ru/browse/PCLIN-29642)
- private area cleanup on failure fixed (https://jira.sw.ru/browse/PCLIN-29620)

* Fri Jul  8 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-66
- --new-uuid internal option was added (https://jira.sw.ru/browse/PSBM-8804)

* Thu Jul  7 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-64
- to use source CTID as context ID for vzctl chpt commands on target
  (ttps://jira.sw.ru/browse/PSBM-8791)

* Wed Jul  6 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-62
- option check fixed (https://jira.sw.ru/browse/PCLIN-29580)

* Mon Jul  4 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-61
- adjust timeout for template migration (https://jira.sw.ru/browse/PCLIN-29431)
- do not call sudo if it is not need (https://jira.sw.ru/browse/PSBM-8694)
- support of iscsi-based storages switched-off

* Wed Jun 15 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-60
- load config of CT with shared private on target
  https://jira.sw.ru/browse/PCLIN-29435
- cleanup on CPT failure fixed (https://jira.sw.ru/browse/PCLIN-29407)

* Tue Jun 14 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-59
- do not touch shared dump file of suspended CT (https://jira.sw.ru/browse/PCLIN-29433)
  ported from 4.7

* Fri May 26 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-55
- do not reject slm-only containers (https://jira.sw.ru/browse/PCLIN-29285)

* Wed May 25 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-53
- --lazy option removed (https://jira.sw.ru/browse/PCLIN-29133)

* Wed May 25 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-52
- to create dump directory for new CT private area (https://jira.sw.ru/browse/PCLIN-29204)

* Wed May 25 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-51
- check of post-create result was added (https://jira.sw.ru/browse/PCLIN-29205)

* Mon May 23 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-50
- 'sudo' was mode fixed

* Wed Apr 27 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-49
- custom timeout fixed (https://jira.sw.ru/browse/PSBM-6034)

* Thu Apr 21 2011 Konstantin Volckov <wolf@parallels.com> 5.0.0-48
- Added function that checks is given hostname/IP assigned to any
  interface on localhost, see #PSBM-7330

* Fri Apr 15 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-46
- ignore iscsi service start error
  https://jira.sw.ru/browse/PSBM-7737
* Wed Apr 13 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-45
- kernel modules check and loading at dst node added
  https://jira.sw.ru/browse/PSBM-7314

* Mon Mar 21 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-41
- send sigterm to all processes in group, https://jira.sw.ru/browse/PSBM-7430

* Wed Jan 28 2011 Serguei Krasnov <krasnov@parallels.com> 5.0.0-35
- iSCSI-based CT migration was added https://jira.sw.ru/browse/PSBM-250

* Sat Dec 25 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-27
- keep-dst option was added (do not remove source CT), https://jira.sw.ru/browse/PSBM-4996

* Thu Dec 16 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-26
- vzmigrate fixed for IPv6 addresses (https://jira.sw.ru/browse/PCLIN-28682)

* Thu Dec  2 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-23
- sync template area and copy cache on EZ OS template migration were added in ps-mode
  https://jira.sw.ru/browse/PSBM-209

* Thu Nov 18 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-22
- ps-mode for vzmtemplate fixed

* Tue Nov 16 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-21
- use vzctl_config_t struct before vzctl_conf_close() (https://jira.sw.ru/browse/PCLIN-28550)

* Tue Nov 16 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-20
- to use absolute path for vzfsutil (https://jira.sw.ru/browse/PSBM-5044)

* Fri Nov 12 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-19
- requires fixed
- repeated vzsock_close_conn() fixed (https://jira.sw.ru/browse/PCLIN-28107)
- to forbid 4.6->4.0 online migration (https://jira.sw.ru/browse/PCLIN-28082)

* Wed Oct 27 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-18
- 'parallels server' mode was added (https://jira.sw.ru/browse/PSBM-210)

* Tue Oct 19 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-17
- CPT image version test added for online migration https://jira.sw.ru/browse/PCLIN-28073

* Wed Oct 13 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-16
- new vzmigrate retcodes into man page were added (https://jira.sw.ru/browse/PCLIN-27744)
- 'action script' error description fixed (https://jira.sw.ru/browse/PCLIN-27817)

* Thu Sep 30 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-15
- "new name" option parsing fixed (https://jira.sw.ru/browse/PCLIN-27852)

* Tue Aug 31 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-14
- EZ ostemplate migration fixed (#484979)
- ez app template name parsing fixed (#483798)

* Thu Aug 19 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-12
- to open swap channel on first step, as in 4.0 (#483576)
- do not use -F option of vzdqload for migration to 4.0
- vzdqload options fixed (#483730)
- release increated

* Tue Aug 10 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-2
- debug level redefenition fixed (#482832)

* Thu Aug  5 2010 Serguei Krasnov <krasnov@parallels.com> 5.0.0-1
- version increased
- ssh options parsing fixed (#482702)
 
* Tue Jul 27 2010 Konstantin Volckov <wolf@parallels.com> 4.6.0-18
- Call vzdqdump and vzdqload with -F parameter, see BUG #479469

* Thu Jul 15 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-17
- wrong dependence on vzrsync fixed

* Fri Jun 25 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-16
- old syntax for CT private & root fixed at vzmigrate (#479540)

* Wed Jun 23 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-15
- eztemplates migration fixed (#479480)
- man page fixed (for non-root user, #477487)

* Wed Jun 23 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-14
- error on shared nfs private migration fixed (#476994)
- CT quota migration fixed for shared CT case (#477230)

* Thu May 27 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-13
- --nodeps & --keeper options (as with optional optarg) fixed at vzmigrate

* Thu May 27 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-12
- to migrate vzfs3 containers via rsync only (#475567)
- tracker/hashtable.c fixed (#118685)
- option processing fixed (#475641)

* Thu May 27 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-11
- rsync timeout increased for large containers

* Thu May 20 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-10
- --skiplock option added, backported from 4.0  (#426812)
- script /etc/sysconfig/vz-scripts/vps.clone will
  execute for local clone, backported from 4.0  (#427065)

* Thu May 20 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-9
- 'sudo' feature added

* Thu May 13 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-8
- skip disk space check if _global_ vzquota is off (#466603)

* Wed May  5 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-7
- skip disk space check if vzquota is off (#466603)

* Tue Apr 27 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-6
- available inodes check for reiserfs fixed (#472684)

* Fri Apr  9 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-5
- use vzrsync instead of rsync-static

* Wed Mar 24 2010 Evgeny Sokolov <evg@parallels.com> 4.6.0-4
- skip copy ez template area for -f, --nodeps option
- added special key "template_area_sync" for skip coping

* Mon Mar 22 2010 Serguei Krasnov <krasnov@parallels.com> 4.6.0-3
- IPv6 support was added

* Mon Dec 07 2009 Serguei Krasnov <krasnov@parallels.com> 4.6.0-2
- typos in vzmigrate description fixed (ticket #829729)

* Fri Aug 07 2009 Konstantin Bukharov <bkb@parallels.com> 4.0.1-22
- Change error code for vzquota retcodes 6,10,11 from MIG_ERR_SYSTEM
 to MIG_ERR_DISKSPACE which allows to ignore them using -f/--nodeps=disk_space (#438639)
- -f/--nodeps option is now documented for vzmlocal

* Mon Aug 03 2009 Lygin Andrey <andrl@parallels.com> 4.0.1-21
- Added setting product type used in vzlic (vzmdest and vzmd).

* Wed Jul 22 2009 Konstantin Volckov <wolf@parallels.com> 4.0.1-20
- Fixed migration from Vz 3.0 to Vz 4.0 (BUG #111773)

* Thu May 21 2009 Serguei Krasnov <krasnov@parallels.com> 4.0.1-19
- vzctl_env_lock_prvt() retcode processing fixed (#432360)

* Fri May  8 2009 Dmitry Mishin <dim@parallels.com> 4.0.1-18
- fixed some options parsing, broken in previous version (#427549)

* Wed Apr  1 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-17
- pmigrate.c2c will start in local copy/clone mode for
  localhost->localhost case (#425607)

* Mon Mar 16 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-16
- --skiplock option added for vzfsutil (#424433)

* Sat Mar 14 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-15
- memory allocation for VZMoptions.{src,dst}_addr added for all modes (#424438)

* Wed Feb 25 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-14
- pmigrate.c2c will understand containers names (#271783)
- pmigrate.c2c arguments parsing fixed
- remote host user & password processing added
- --help option fixed

* Fri Feb 20 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-13
- useless and erroneous code was removed (#271755)
- vztestcap error checking fixed
- pmigrate.c2c usage added (#271756)

* Sat Jan 24 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-12
- vzmig user homedir moved to /var/lib/vzmig,
  vzmdest will use vzmig homedir (#267377)
- vztestcap exit code checking fixed (#268597)

* Sat Jan 24 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-11
- patches from Pavel Emelyanov <xemul@parallels.com>:
  "Now vzmigrate is a wrapper on top of the pmigrate (sent earlier). The
   required by the latter one pmigrate.c2c is the link to vzmsrc (just
   like the vzmigrate was), which in turn is fixed to understand the new
   syntax (in fact, this was not that difficult)."

* Wed Jan 21 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-10
- vzmlocal syntax fixed (#268051)

* Tue Jan 20 2009 Serguei Krasnov <krasnov@sw.ru> 4.0.1-9
- ignore OSTEMPLATE absence in CT config for vzmlocal (#266295)

* Wed Dec 10 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.1-8
- rewrote using libvzsock
- ##131684,131685,131686 fixed

* Fri Oct 10 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.1-7
- app template sync for VE migration fixed (#124156)

* Wed Oct  1 2008 Konstantin Bukharov <bkb@sw.ru> 4.0.1-6
- Use static-compiled Virtuozzo patched rsync instead of system wide one

* Mon Sep  8 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.1-5
- common init_connection() function for CT and template migration 
  moved in bincom.cpp (#120726)
- pid added in log record

* Fri Aug 29 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.1-4
- numeric-owner tar options added (#120148)
- target CT locking fixed (#119945)

* Wed Aug 20 2008 Vladimir Kropylev <vkropylev@parallels.com> 4.0.1-3
- cut vzacopy from agent libs, linked directly with acronis libs

* Tue Aug 19 2008 Dmitry Mishin <dim@parallels.com> 4.0.1-2
- enabled instrumented builds for coverage

* Tue Aug 5 2008 Andrey Mirkin <amirkin@parallels.com> 4.0.1-1
- if undump fails then do not return error which can occur during cleanup
- cleanup Makefile: remove vzacopy from install, add vzmtemplate to install
- add quiet mode to operateVE
- introduce new version 4.0.1 which will be 4.0SP1

* Fri Jul 25 2008 Vladimir Kropylev <vkropylev@parallels.com> 5.0.0-11
- directory /vz/dump is created before anything is done (#115603)

* Tue Jul 22 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-10
- NFS check for vzmlocal added
- layout define from libvzctl used

* Tue Jul 15 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-9
- vzacopy temporary removed, vzmd added

* Fri Jul  4 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-8
- veformat check for NFS added, backported from 4.0 (#113201)
- obsoletes perl script removed, backported from 4.0 (#115795)

* Fri May 23 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-7
- ssl transport added
- strong password for ssh fixed (#60640)
- VZ_UNREG_PRESERVE mask added for vzctl_env_unregister() to avoid
  .owner removing on cluster (#99304)

* Thu Apr 10 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-6
- bugfixes from 4.0 backported (#100540, #99865)

* Wed Apr  9 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-5
- rewrote without vzagent
- acronis backup moved to separate binary

* Wed Mar 12 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-4
- do not expand command with '%' character
- skip EZ template area sync for --dry-run option
- some VE config params reading rewrote from vzagent to vzctl functions

* Wed Mar 12 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-3
- 'checkoptions' command fixed
- 'unknown command' processing added in send_request()

* Thu Mar  6 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-2
- 'checkoptions' command and --whole-file option added (#99354)

* Thu Mar  6 2008 Serguei Krasnov <krasnov@sw.ru> 5.0.0-1
- NFS support added
- new commands added for NFS support and protocol version increased
- 'unknown command' reply added for vzmdest
- license check fixed (#99676)

* Wed Feb  6 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.0-123
- ignore-times (-I) rsync option removed from 2nd stage of online migration
  to fix too wide time of 2nd stage. #96817 reopened on kernel.

* Tue Feb  5 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.0-122
- 'Obsoletes' tag added in vzmigrate for vzmigrate-service (#98687)

* Fri Jan 25 2008 Serguei Krasnov <krasnov@sw.ru> 4.0.0-121
- rebuild with vzagent-compat 4.0.0-73

* Sun Dec 30 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-120
- vzmpipe reply checking fixed (#96616)
- NULL cast from int to void * for all 'variable number of args' 
  functions (#97056)

* Fri Dec 28 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-118
- redirect vzctl stderr from dst to src (#96452)

* Fri Dec 28 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-117
- ignore mtime by rsync on 2nd stage copy (#96817)

* Fri Dec 28 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-116
- set ACRONIS_SNAPSHOT_TMP_DIR to /vz/tmp (#96952)

* Thu Dec 27 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-115
- ignore ENOENT for tracker terminating (#95475)

* Wed Dec 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-114
- VE to CT renamed, HN to node, etc...
- to check vzmpipe first reply (#96616)

* Thu Dec 20 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-113
- libvzsnap support added for local copy (#96171)
- -pthread g++ option added for new agent added

* Mon Dec 17 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-112
- ignore-failed-read tar option added for source

* Sat Dec 15 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-111
- wait on dst 'ssh ... tar ...' command running from src (#96302)

* Fri Dec 14 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-110
- use rsync for existing target private case (##95815,96196)
- debug package added

* Wed Nov 28 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-109
- keed dst private before dst VE destroing in failure (#95232)

* Fri Nov 23 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-108
- to read TEMPLATE from vz config (#94570)

* Wed Nov 14 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-107
- return correct error after checks (#81355)

* Fri Nov  9 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-106
- batch mode restored for compatibility (#93995)

* Fri Nov  9 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-105
- skip eztemplate area copying for PLAINFS (VZFS0)

* Thu Nov  8 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-104
- man & usage fixed (#93585)
- for noiter, lazy and require-realtime check on online mode added (#93892)
- to print debug message from migrate channel only on debug level (#93813)

* Wed Oct 24 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-103
- 'vzpkg repair' call fixed for migration from VZ3.0 (#93022)
- VE local clonning with UUID fixed (#93014)

* Wed Oct  3 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-102
- some dublicate info messages moved to debug
- 'target private on cluster' check fixed (#89400)

* Thu Sep 20 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-101
- migration to/from node with DISK_QUOTA=no fixed (#91570)

* Tue Sep 18 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-100
- disk space check added for local copy (#86349)

* Tue Sep 11 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-98
- skip disk space check if private or keep dir exist on dst node

* Tue Sep 11 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-97
- vzmlocal cleanup fixed (#89707)
- vzmigrate-agent package removed

* Mon Sep 10 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-96
- exit code fixed at post & postun rpm scripts
- migration of suspended VE fixed (#90235)
- copyright in man pages fixed (#89827)

* Fri Sep  7 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-95
- 'tar via ssh' copy fixed for -vzagent & --online (#90465)

* Thu Sep  6 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-94
- copy 'tar via ssh' added for agent mode (#90094)
- insufficient cpu capabilities diagnostic fixed (#89742)

* Thu Aug 31 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-93
- template migration from 3.0 to 4.0 in agent mode fixed (#89537)
- local clone via ATI fixed (#89535)

* Thu Aug 30 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-92
- quota fixed for VE migration
- disk space check rewrote: do not use 'du', use vzquota and check 
  VE space and inodes only.

* Wed Aug 29 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-91
- migration on the same cluster but with other private fixed (#89390)

* Wed Aug 29 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-90
- 'private on cluster' check for 'tar via ssh' added (#89363)

* Fri Aug 24 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-89
- VE private copy by tar with path changing fixed (#89214)

* Wed Aug 22 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-88
- vzcache call for local copy added (#88932)
- 'tar via ssh' copy mode added for private and 
  EZ template area migration (#84935)

* Fri Aug 17 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-86
- do not copy scripts separately for new layout VE (#88774)

* Thu Aug 16 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-85
- check EZ template dirs on target before syncing, and skip if exist
- for src private on cluster: if dst def private is not on the same cluster,
  find this cluster on available shared storage list.

* Tue Aug 14 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-83
- ez template locking fixed
- VE config update fixed for local move (#88542)

* Thu Aug  9 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-82
- correctly close migration channel

* Thu Aug  9 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-81
- clone of running VE fixed (#88267)

* Wed Aug  8 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-80
- reworked undump/resume operations in migratedst
* Wed Aug  8 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-80
- local private move to the same partition fixed (#88153)

* Mon Aug  6 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-78
- clean lazy channel only in case of error (#86721)

* Wed Aug  1 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-77
- always call vzctl with --skipowner option

* Wed Aug  1 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-76
- src VE destroy fixed for local move (#87745)

* Thu Jul 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-74
- vzmlocal copy will not rewrote src VE config as reg file (#87395)

* Tue Jul 24 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-73
- info message fixed (#86740)

* Mon Jul 23 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-72
- online migration on shared cluster fixed: full chkpnt kill of src VE
  before dst VE undump
- cleanup fixed
- cluster id check for unexisted path fixed (#86834)

* Fri Jul 20 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-70
- src VE private removing fixed for vzmlocal (#86739)

* Thu Jul 19 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-68
- cleanup fixed for online migration on shared cluster
- --nonsharedfs option added

* Thu Jul 19 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-67
- support old_agent_mode.

* Wed Jul 18 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-66
- skipowner option using fixed
- vzctl_env_unregister() call fixed for new libvzctl

* Mon Jul 16 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-65
- local move fixed (#86338)

* Mon Jul 16 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-64
- do not copy dump file if target & source dumpdir 
  are the same dir on cluster (#86188)
- do not start tracker for 'VE private on cluster' case (#86205)
- local private move fixed (#85969)

* Fri Jul 13 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-63
- vzctl stdout & stderr redirect to /dev/null from ssh channel

* Thu Jul 12 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-62
- confRealPath() fixed (#85966)
- vzctl --skipowner used for online migration on the same cluster
  and chkpnt kill of srv VE moved after dst VE resuming

* Tue Jul 10 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-61
- blowfish changed on arcfour for ssh (#84995)
- name migration fixed (#85707)
- GFS cluster support added

* Tue Jun 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-60
- batch mode (without progress bar) set as default (#84932)
- EZ application template migration fixed (#85082)

* Tue Jun 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-59
- VE name copy for vzmigrate fixed (#84879)

* Tue Jun 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-58
- src & dst VE's the same private/root case for vzmlocal fixed

* Thu Jun 21 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-57
- online mode for vzmlocal added (#64395)

* Tue Jun 19 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-56
- suffix for "--keep-dst" saved private area changed (#84408)
- VE name check fixed - ignore existance if VEID is destination VEID (#84408)
- vzcache2 directory check added
- file quota.fs added into rsync excludes (#84333)
- libvzctl, libvzfs, libvztt linked dinamically

* Thu Jun 14 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-55
- technologies check for template migration added (#84120)

* Mon Jun  4 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-54
- do not set NONBLOCK flag for 'online' connection (#83515)
- connection timeout increased up to 300 sec

* Wed May 30 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-53
- 'vzctl destroy' call added for VE moving (#83131)
- rate device '*' case fixed (#82418)
- VE config variables quoting added (#83275)
- VE name check added: find veid by name in target node (#83387)
- VE name setting rewrote - check name & set name for new name and
  for existing name too

* Tue May 29 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-52
- BF #83053.

* Sat May 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-51
- vzctl call for VE postcreate operations added (#28008)

* Sat May 26 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-50
- processing of connection terminating fixed (#77756)

* Mon May 21 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-49
- cache creation for EZ template migration removed
- info message for server added (#81500)
- copyright fixed (#76246)
- quota setting for local copy fixed (#82550)

* Mon May 21 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-48
- return correct error when CPT modules are not loaded (#81355)

* Fri May 11 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-47
- license check rewrote via libvzctl & libvzlic (#78171)
- check license only for running VE
- EZ ostemplate lock added for VE migration (#71791)
- vzmigrate append cache of migrated VPS to the node's one (#79607)

* Fri May 11 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-46
- standard template migration from/to 3.0 fixed

* Tue May  8 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-45
- quota path fixed for VZFS4 VE local move (#81138)
- original VE config saving added for VE local move
- template migration from/to vz3 fixed

* Sat May 5 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-44
- added check for "unlimited" licenses. 

* Thu Apr 19 2007 Andrey Mirkin <amirkin@sw.ru> 4.0.0-43
- unfreeze VE on src node if undump is failed (#79586)
- fix renaming of private area on dst node to .migrated on failure (#79582)

* Wed Apr 18 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-42
- send SIGTERM fixed (#79765)

* Tue Apr 17 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-41
- migration of some VEs fixed (#79439)

* Fri Apr 13 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-40
- ez template migration from 3.0 fixed
- vmlocal clone without new VE name fixed (#79286)

* Thu Apr  5 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-39
- new layout support fixed for vzmlocal (#78683)
- name support added for vzmlocal

* Wed Apr  4 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-38
- name support restored for source VE
- remote VE name support added with --new-* options
- ve layout and vzcache2 checking added for migration to old versions

* Thu Mar 29 2007 Serguei Krasnov <krasnov@sw.ru> 4.0.0-37
- VE layout version 4 support added

* Fri Mar 23 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-36
- fixed buffer overload (bug #69397).
- changed algo of cleanup "removeDir": now if we can't rename dir to
dir_tmp, remove orig (bugs #59089, #49490).
- fixed bug #77609 (template removed after migration interrupt via Ctrl+C).
- fixed bug #77611 (vzmigrate & ext. bindmount w/o --force).

* Fri Mar 16 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-35
- added: ez app-templates migrations.
- changed interface for ez-template migrations.
- fixed: "vzmlocal should allow to use old scheme of started VE migration" (bug 77417).
use USE_ATI parameter in global vz config file.

* Tue Feb 27 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-34
- fixed work with VE in suspend state (bug #66829).
Clone is forbidden. Other mode support.

* Wed Feb 21 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-33
- additional checks for empty output. (bug 76291).
- another variant fix for bugs (60407).
[diff] fixed problems for operations with templates in process migrations VE. (additional see bug 76291).

* Tue Feb 20 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-32
- added to fix 57973 agent specific.

* Sat Feb 17 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-31
- fixed bug 57973 (cannot resume OStemplate migration after terminating
migration process). 
- fixed incorrect "if".

* Wed Feb 14 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-30
- vzmigrate:
- added check_only functionality (flag --dry-run)
- modify disk_space_check (now used dst pathes)
- fix checkCapabilities (may segfault)
- vzmlocal:
- fix cleanup private path on fail.
- Apply patch from Andrey (amirkin@):
Increase sndbuf and rcvbuf size of tracker socket pair to maximum
available size (2 * /proc/sys/net/core/wmem_max).(bug #72825).

* Fri Feb 02 2007 Taras Yukish <tyukish@sw.ru> 4.0.0-29
- switch on acronis library on all arch.
- fixed: use acronis-lib+vzfsclone in vzmlocal. (bugs #67758, #66865)
- moved to new vzctl-lib interface.
- switch off "Friendly name support". (#64238 reopen).
- fixed works with version of protocol.
- realized compatibility schema(bug #75026).

* Mon Dec 11 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-28
- gets dumpdir for online migration from vz config. Its creation if it is necessary. (bug #72240).
- sets only warning on error in finish cleanup.

* Fri Dec 08 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-27
- fixed bugs #59164, #60407.

* Tue Nov 28 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-26
- fixed bugs #72240, #72420.
- add eztemplate migrate. 

* Wed Nov 08 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-25
- fixed bug #71521. 

* Mon Oct 23 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-24
- fixed bug #70763
- fixed bug in autogeneration of veid for dst node

* Fri Oct 13 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-23
- support ve names in vzmigrate, fixed bug #64238

* Tue Oct 10 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-22
- fixed bug #65012.
- apply fix from mesk@ for build with new vzagent-plugin-devel (4.0.0-59).

* Tue Oct 3 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-21
- rebuild with vzagent-compat-* , bug #64660.

* Fri Sep 29 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-20
- allow specifying ve name for src_ve not only dst_ve: additional functionality for bug #68647 and part of fix for bug#64238

* Thu Sep 28 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-19
- fixed bug #69351.
- apply patch diff-vzmigrate-dumpfile-path-20060927

* Wed Sep 27 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-18
- fixed bug #68647

* Tue Sep 26 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-17
- fixed bug #69210, #69115.

* Fri Sep 22 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-16
- fixed bugs #66585, #65222, #68013.
- add to vzmigrate user-friendly usage().
- add logic to works with old vzmigrate.
- remove skip-cpu-check flag. see below.
- expanded -f and --nodeps: add cpu_check, technologies, disk_space, license, rate.
- sync used in VE EzTemplate directories. 

* Tue Sep 19 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-15
- error messages for bug #66829 were elaborated
- build issues with 4.0.0-14 on 64 bit archs were fixed

* Fri Sep 15 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-14
- bug #67758 was fixed

* Thu Sep 14 2006 Taras Yukish <tyukish@sw.ru> 4.0.0-13
- fixed bugs #65411, #66577, #68013, #57973, #66819, #65012, #66099.

* Thu Sep 14 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-12
- bug #59786 was fixed.  really.

* Wed Sep 13 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-11
- bug #66829 was fixed

* Fri Sep 08 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-6
- bug #59163 was fixed

* Thu Sep 07 2006 Denis Lagno <dlagno@sw.ru> 4.0.0-5
- bug #59786 was fixed

* Tue Jul 18 2006 Andrey Mirkin <amirkin@sw.ru> 4.0.0-1
- bug #65242 was fixed

* Wed Nov 30 2005 Andrey Mirkin <amirkin@sw.ru> 3.0.0-3
- bug #55251 was fixed

* Thu Nov 24 2005 Andrey Mirkin <amirkin@sw.ru> 3.0.0-1
- bug #54630 was fixed

* Thu Nov 24 2005 Andrey Mirkin <amirkin@sw.ru> 2.7.0-6
- bug #54753 was fixed

* Wed Nov 23 2005 Andrey Mirkin <amirkin@sw.ru> 2.7.0-5
- bug #54717 was fixed

* Mon Nov 21 2005 Andrey Mirkin <amirkin@sw.ru> 2.7.0-3
- bug #54424 was fixed
- Made changes due to changes in vztestcaps

* Tue Oct 18 2005 Andrey Mirkin <amirkin@sw.ru> 2.7.0-2
- bug #52437 was fixed

* Thu Aug 25 2005 Andrey Mirkin <amirkin@sw.ru> 2.7.0-1
- Online migration support added

* Tue Jul 26 2005 Sergey Galas' <shrike@sw.ru> 2.6.2-16
- bug #49175 was fixed 

* Thu Jul 21 2005 Sergey Galas' <shrike@sw.ru> 2.6.2-15
- bug #48512 was fixed 

* Fri Oct 3 2003 Konstantin Pakulin <mesk@sw.ru> 2.5.1-233
- remove track tree creation timeout.
- fix glitch that brocken 2.5.1->2.5.0 migration 

* Wed Jul 16 2003 Konstantin Pakulin <mesk@sw.ru> 2.5.1-160
- add vzmtemplate to provide templates migration

* Wed Jun 11 2003 Konstantin Pakulin <mesk@sw.ru> 2.5.1-159
- add utilities (vzmagent, vzmsetkey) to provide 2.0.2->2.5.0 agent like migration

* Thu May  8 2003 Konstantin Pakulin <mesk@sw.ru> 2.5.0-158
- added keeper VE support

* Fri Mar 28 2003 Konstantin Volckov <wolf@sw.ru> 2.5.0-157.swsoft
- IA64 support is added
- Removed Werror flag from MFLAGS (this breaks IA64)

* Fri Nov 29 2002 Pakulin Konstantin <mesk@sw.ru>
- fixed 15250 (--help option)
- fixe 15249 (--ssh to usage)
- fixed some bugs with ssh error diagnistics (-q was removed from ssh arguments)

* Thu Nov 14 2002 Pakulin Konstantin <mesk@sw.ru>
- add support for old migrate

* Mon Nov  4 2002 Pakulin Konstantin <mesk@sw.ru>
- --remove-area - incorrect fixed
- glitch in apply 2-level quota parameters on destination side
- glitch in non-removing VE lock in case of VE non-existence

* Fri Oct 25 2002 Pakulin Konstantin <mesk@sw.ru>
- rewrite remote migration in C++, unify with local mode.
- add support of new VE lock, and 'shared' VE migration. 

* Tue Oct  8 2002 Pakulin Konstantin <mesk@sw.ru>
- fixe bug in 'vzmlocal' when src VE_ROOT was not deleted after move,
  add '--skiplock' option to prevent src VE unlocking on moment of stop 

* Sat Oct  5 2002 Iljin Ruslan <media@sw.ru>
- VE config secure check is removed

* Mon Sep  2 2002 Pakulin Konstantin <mesk@sw.ru>
- bugs fixed in vzmlocal : with mkdir, rmdir cleaner

* Thu Aug 15 2002 Pakulin Konstantin <mesk@sw.ru>
- fix bug in 'vzmigrate' installation
- add -b (batch mode) option
- fix problem : vzagent can't correctly use vzmigrate (add std.. closing in vzmdest)
- fix incorrect determination of unsecure VE config 

* Fri Jul 12 2002 Pakulin Konstantin <mesk@sw.ru>
- fix bug with rsync hang

* Tue May 21 2002 Pakulin Konstantin <mesk@sw.ru> 
- correct joining with 2.0.2 branch
- correct dependencies, add VZFS_TRACKING option

* Mon Apr 22 2002 Pakulin Konstantin <mesk@sw.ru>
- fixed problems with lock in migrate
    
* Fri Apr 19 2002 Pakulin Konstantin <mesk@sw.ru>
- vzpkgls call with '-q'
- undef value fix in vz_config_clearing

* Mon Apr 15 2002 Pakulin Konstantin <mesk@sw.ru>
- fix in dependency checking
- fix in sonfig scripts copiing
- commenting user redefined VZ parameters in destination VE config  

* Fri Apr 12 2002 Pakulin Konstantin <mesk@sw.ru>
- template checking, config scripts copiing

* Mon Apr  8 2002 Pakulin Konstantin <mesk@sw.ru>
- fixed -r parameter checking, fixes in migration of list of VEs

* Mon Apr  8 2002 Pakulin Konstantin <mesk@sw.ru>
- correct company name, add copyright headers, add vzmpipe man page

* Thu Mar 28 2002 Pakulin Konstantin <mesk@sw.ru> 
- ssh ugly printing fixed

* Tue Mar 26 2002 Pakulin Konstantin <mesk@sw.ru> 
- man pages reworked, bug fixes, more suitable utility output

* Fri Mar 22 2002 Pakulin Konstantin <mesk@sw.ru>
- added vz config file parser, changes in man pages    

* Thu Mar 21 2002 Pakulin Konstantin <mesk@sw.ru>
- fixes in vzmdest (incorrect detecting of destination VEID)

* Wed Mar 20 2002 Pakulin Konstantin <mesk@sw.ru>
- new migration utility, rewrite manpage, command line migrate

* Wed Feb 20 2002 Pakulin Konstantin <mesk@sw.ru>
- rewrite migration procedure, now migration is more safely, it doesn\'t use root account on HN

* Thu Dec 27 2001 Iljin Ruslan <media@sw.ru> 
- add check of existence migrated VE on target HW node

* Thu Nov 22 2001 Iljin Ruslan <media@sw.ru> 
- packaging
