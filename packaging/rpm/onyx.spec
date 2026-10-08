Name:           onyx
Version:        %{onyx_version}
Release:        1%{?dist}
Summary:        Lightweight command guard for Linux servers
License:        MIT
URL:            https://github.com/ttr1563/onyx
Source0:        onyx
Source1:        LICENSE
Source2:        README.md
Source3:        operations.md
Source4:        onyx.logrotate

%global debug_package %{nil}

%description
Onyx detects risky commands before execution and requires approval from a
separate RFC 6238-compatible TOTP authenticator.

%prep

%build

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/onyx
install -Dpm0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dpm0644 %{SOURCE2} %{buildroot}%{_docdir}/%{name}/README.md
install -Dpm0644 %{SOURCE3} %{buildroot}%{_docdir}/%{name}/operations.md
install -Dpm0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/logrotate.d/onyx

%files
%{_bindir}/onyx
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/operations.md
%config(noreplace) %{_sysconfdir}/logrotate.d/onyx

%changelog
* Thu Oct 08 2026 Onyx maintainers <ttr1563@users.noreply.github.com> - %{onyx_version}-1
- Package the Onyx CLI for Amazon Linux 2023.
