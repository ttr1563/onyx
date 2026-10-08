Name:           onyx-release
Version:        1
Release:        1%{?dist}
Summary:        DNF repository configuration for Onyx
License:        MIT
URL:            https://github.com/ttr1563/onyx
Source0:        onyx.repo
Source1:        RPM-GPG-KEY-ONYX
BuildArch:      noarch

%description
Repository configuration and public package-signing key for the Onyx DNF
repository on Amazon Linux 2023.

%prep

%build

%install
install -Dpm0644 %{SOURCE0} %{buildroot}%{_sysconfdir}/yum.repos.d/onyx.repo
install -Dpm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-ONYX

%files
%config(noreplace) %{_sysconfdir}/yum.repos.d/onyx.repo
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-ONYX

%changelog
* Thu Oct 08 2026 Onyx maintainers <ttr1563@users.noreply.github.com> - 1-1
- Add the initial Onyx repository configuration and signing key.
