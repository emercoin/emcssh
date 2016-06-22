Name:           emcssh
Version:        0.0.3
Release:        20%{?dist}
Summary:        Emercoin SSH Authenticator
Group:          Applications/Internet
Vendor:         Emercoin
License:        GPLv3
URL:            http://www.emercoin.com
Source0:        %{name}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  gcc-c++ openssl-devel >= 1:1.0.2d jansson-devel libcurl-devel
Requires:       emercoin pwgen openssl >= 1:1.0.2d jansson libcurl

%description
Emercoin SSH Authenticator

%prep
%setup -q -n emcssh

%build
cd source
%{__make}

%install
%{__rm} -rf $RPM_BUILD_ROOT
%{__mkdir} -p $RPM_BUILD_ROOT%{_sbindir} $RPM_BUILD_ROOT/etc/emercoin/emcssh.keys.d
%{__install} -m 755 source/emcssh $RPM_BUILD_ROOT%{_sbindir}
%{__install} -m 600 contrib/build.el7/emcssh.conf $RPM_BUILD_ROOT/etc/emercoin

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%post
[ $1 == 1 ] && {
  [ -f /var/lib/emc/.emercoin/emercoin.conf ] || { echo "Configuration file '/var/lib/emc/.emercoin/emercoin.conf' not found."; exit 2; }
  sed -i -e "s+\(^emcurl\)\(.*\)+emcurl https://emccoinrpc:$(grep rpcpassword /var/lib/emc/.emercoin/emercoin.conf | sed 's/rpcpassword=//')@127.0.0.1:6662/+" /etc/emercoin/emcssh.conf
  [ -f /etc/ssh/sshd_config ] && {
    grep "AuthorizedKeysCommand /usr/sbin/emcssh" /etc/ssh/sshd_config >/dev/null || {
      echo -e "\nAuthorizedKeysCommand /usr/sbin/emcssh\nAuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config
      systemctl status sshd >/dev/null && systemctl restart sshd >/dev/null || true
    }
  } || true
} || exit 0

%posttrans
chmod u+s /usr/sbin/emcssh

%files
%doc COPYING
%attr(700,root,root) %dir /etc/emercoin/emcssh.keys.d
%attr(600,root,root) %config(noreplace) /etc/emercoin/emcssh.conf
%attr(711,root,root) /usr/sbin/emcssh

%changelog
* Tue Jun 21 2016 Sergii Vakula <sv@emercoin.com> 0.0.3
- Initial release
