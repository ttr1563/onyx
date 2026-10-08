Name:           osmanthus
Version:        %{osmanthus_version}
Release:        1%{?dist}
Summary:        Lightweight command guard for Linux servers
License:        MIT
URL:            https://github.com/ttr1563/osmanthus-shell
Requires:       shadow-utils
Conflicts:      onyx
Source0:        osmanthus
Source1:        LICENSE
Source2:        README.md
Source3:        operations.md
Source4:        osmanthus.logrotate
Source5:        osmanthusd
Source6:        osmanthusd.service
Source7:        osmanthus-shell
Source8:        ssm.md
Source9:        osmanthus-session.json

%global debug_package %{nil}

%description
Osmanthus uses a privileged daemon and Linux BPF LSM hooks to deny configured
destructive filesystem operations below protected roots. Scoped maintenance
leases require approval from an RFC 6238-compatible TOTP authenticator.

%prep

%build

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/osmanthus
install -Dpm0755 %{SOURCE5} %{buildroot}%{_bindir}/osmanthusd
install -Dpm0755 %{SOURCE7} %{buildroot}%{_bindir}/osmanthus-shell
install -Dpm0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dpm0644 %{SOURCE2} %{buildroot}%{_docdir}/%{name}/README.md
install -Dpm0644 %{SOURCE3} %{buildroot}%{_docdir}/%{name}/operations.md
install -Dpm0644 %{SOURCE8} %{buildroot}%{_docdir}/%{name}/ssm.md
install -Dpm0644 %{SOURCE9} %{buildroot}%{_datadir}/%{name}/ssm/osmanthus-session.json
install -Dpm0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/logrotate.d/osmanthus
install -Dpm0644 %{SOURCE6} %{buildroot}%{_unitdir}/osmanthusd.service

%post
%systemd_post osmanthusd.service

%pre
if [ "$1" -eq 1 ]; then
  if [ -e /sys/fs/bpf/onyx ]; then
    echo "osmanthus: legacy Onyx BPF pins remain; decommission Onyx before installation" >&2
    exit 1
  fi
  if getent passwd | awk -F: '$7 == "/usr/bin/onyx-shell" { found=1 } END { exit !found }'; then
    echo "osmanthus: restore accounts that still use /usr/bin/onyx-shell before installation" >&2
    exit 1
  fi
fi

%preun
if [ "$1" -eq 0 ]; then
  if [ -e /sys/fs/bpf/osmanthus ]; then
    echo "osmanthus: run 'sudo osmanthus daemon decommission' before uninstall" >&2
    exit 1
  fi
  if getent passwd | awk -F: '$7 == "/usr/bin/osmanthus-shell" { found=1 } END { exit !found }'; then
    echo "osmanthus: restore monitored login shells before uninstall" >&2
    exit 1
  fi
fi
%systemd_preun osmanthusd.service

%postun
%systemd_postun_with_restart osmanthusd.service

%files
%{_bindir}/osmanthus
%{_bindir}/osmanthusd
%{_bindir}/osmanthus-shell
%{_unitdir}/osmanthusd.service
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/operations.md
%doc %{_docdir}/%{name}/ssm.md
%{_datadir}/%{name}/ssm/osmanthus-session.json
%config(noreplace) %{_sysconfdir}/logrotate.d/osmanthus

%changelog
* Thu Oct 08 2026 Osmanthus maintainers <ttr1563@users.noreply.github.com> - %{osmanthus_version}-1
- Package the Osmanthus CLI for Amazon Linux 2023.
