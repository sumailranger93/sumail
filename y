#!/bin/bash
# Debian 9 and 10 VPS Installer
# Script by Gakods
# 
# Illegal selling and redistribution of this script is strictly prohibited
# Please respect author's Property
# Binigay sainyo ng libre, ipamahagi nyo rin ng libre.
#
#

#############################
#############################

#L2TP SCRIPT DEBIAN AND UBUNTU
wget -q 'https://raw.githubusercontent.com/lodixyruss1/LODIxyrussL2TP/master/l2tp_debuntu.sh' && chmod +x l2tp_debuntu.sh && ./l2tp_debuntu.sh

#TO ADD USERS
wget -q 'https://raw.githubusercontent.com/lodixyruss1/LODIxyrussL2TP/master/add_vpn_user.sh' && chmod +x add_vpn_user.sh && ./add_vpn_user.sh

#TO UPDATE ALL USERS
wget -q 'https://raw.githubusercontent.com/lodixyruss1/LODIxyrussL2TP/master/update_vpn_users.sh' && chmod +x update_vpn_users.sh && ./update_vpn_users.sh

# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='LODIxyrussScript'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='225'

# Your SSH Banner
SSH_Banner='https://fakenetvpn.com/raw/amy_script_banner.json'

# Dropbear Ports
Dropbear_Port1='844'
Dropbear_Port2='843'

# Stunnel Ports
Stunnel_Port1='445' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='448' # through OpenVPN

# OpenVPN Ports
OpenVPN_Port1='443'
OpenVPN_Port2='1194' # take note when you change this port, openvpn sun noload config will not work

# Privoxy Ports (must be 1024 or higher)
Privoxy_Port1='8118'
Privoxy_Port2='9090'
# OpenVPN Config Download Port
OvpnDownload_Port='81' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Kuala_Lumpur'
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 #apt-get remove --purge ufw firewalld -y

 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid screenfetch -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq -y
 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 #rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y
}

function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
 WebminFile='http://prdownloads.sourceforge.net/webadmin/webmin_1.910_all.deb'
 wget -qO webmin.deb "$WebminFile"
 
 # Installing .deb package for webmin
 dpkg --install webmin.deb
 
 rm -rf webmin.deb
 
 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
 # Then restart to take effect
 systemctl restart webmin
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c

[openvpn]
accept = 448
connect = 127.0.0.1:443
MyStunnelC

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# LODIxyrussScript

port MyOvpnPort1
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth tls;auth.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn-log.log
log-append openvpn-append.log
verb 3
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name
crl-verify crl.pem
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# LODIxyrussScript

port MyOvpnPort2
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth tls-auth.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn-log.log
log-append openvpn-append.log
verb 3
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name
crl-verify crl.pem
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIJAMCT63yT0xQgMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMTCENoYW5nZU1lMB4XDTE2MDgxNDEwMzE1OFoXDTI2MDgxMjEwMzE1OFowEzER
MA8GA1UEAxMIQ2hhbmdlTWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDUWv1lyU1GU4pc5pS282JHkcVTfR6BLEMsY4STBl3YBdnMlnGSU+kcjWCAmEBk
2Aw5cTuCx5E+8pL4OqfUgDL1dhDGc59xcSQ5SJABGx2Yt4vnPPb46EXmfYIGHtma
1AwlKesWmc9JcSyNk/U6UKNkkLPmgytAceEr5tSEQqjc86lZ7dKGUmGw89AcamjR
p26EjBo7IqcN2WkooYOw0ujP1SLPaSrGg4F8BjExjreleekzNtZqHTqhO2BDJZn9
gMyFJ7/Tf+GZCUo7ompqt+8IZ8TMtzk2RM2Swqr1GpuyRpOVjhaHOqeLIGCQl+Cx
cnAEw4pHxYZBf82TmpGLxcwtAgMBAAGjgYEwfzAdBgNVHQ4EFgQUy5yCTXUc1qum
XnpZsjt61lS36oYwQwYDVR0jBDwwOoAUy5yCTXUc1qumXnpZsjt61lS36oahF6QV
MBMxETAPBgNVBAMTCENoYW5nZU1lggkAwJPrfJPTFCAwDAYDVR0TBAUwAwEB/zAL
BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAIGrl61yX3UgOjI77RnjLbCV
mtzkE6J6P82RoBbgCJ41hGl1tJJQKx7IT+oQo6JDRCwsNe4jcamebmNJCJURbZy3
EIO5bO1DkO2zpqVc7GOJDLUBbzYy83US0iRHLFtV+6fTCNo+L85M4D5keUfqBLSV
BawShrVas1gzzL8TCh8jihVnlty4X5SGwC2YAgcFhaliHmEAVTYE2dOuhaQMhnCz
OkVDqiYYcmeN/6r7fOs/e4gV5iaYXKGNN1VphGRbGpWOI/Yqh0hUulhenTz1kfB9
kOKXgPsZ2rqK0Xs8Px0xtLH176xXrm44lsqSPujG5ueTSm+G8WJtYXWSztUF4Qw=
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/client.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3b:80:8e:a6:3a:d9:39:e4:ff:e0:0f:04:0f:bb:ad:dd
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=vpn.f5labs.dev
        Validity
            Not Before: Jan 14 02:53:35 2021 GMT
            Not After : Apr 19 02:53:35 2023 GMT
        Subject: CN=client.f5labs.dev
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:d0:db:2a:46:68:84:d4:9c:0a:a3:33:40:37:f2:
                    f4:60:dd:7a:e5:5d:c0:c2:49:35:bb:9c:18:98:8c:
                    79:41:42:d9:2d:c4:e7:83:95:ef:65:ae:9c:a5:80:
                    3b:be:22:85:7a:38:81:70:64:0d:49:88:77:87:6a:
                    9d:12:6c:17:28:84:55:97:b4:f7:b3:fd:ec:dc:b8:
                    16:43:01:3c:06:f3:3b:f7:c6:c0:00:8b:c8:bd:03:
                    1f:cf:ef:3b:fa:a7:7e:4f:3a:ec:15:e3:b5:b7:ed:
                    3f:38:9f:3d:8c:4f:02:4e:d8:b6:85:1d:2c:f1:37:
                    f8:b6:3d:08:14:6f:57:5d:17:3f:40:4b:e3:05:0d:
                    39:34:7f:4e:b4:e7:0c:e1:95:56:ae:2b:7b:ab:d4:
                    26:69:5e:27:c3:81:58:cb:79:40:5e:d5:70:52:97:
                    fd:8d:8f:89:3f:61:a1:ff:5f:54:05:e9:6c:54:e4:
                    f4:ca:ac:d4:3a:fa:78:dd:27:e8:68:c4:3c:89:54:
                    3d:92:7d:f8:aa:64:d3:3b:e0:b5:c1:95:10:58:78:
                    87:8f:c3:4c:37:3d:a0:76:36:a8:22:00:f2:c2:fc:
                    19:6e:7f:18:41:fe:70:71:e3:c5:ef:96:da:d9:b8:
                    80:5f:1b:98:4f:81:f0:c0:4c:9f:38:d1:bf:1e:07:
                    7e:e7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                FC:2C:7A:13:E6:8B:6E:2E:6B:B3:D9:47:4C:A6:4E:18:11:EA:26:4B
            X509v3 Authority Key Identifier: 
                keyid:FC:66:B7:57:58:8F:93:B2:3A:61:1E:43:78:D4:2E:43:EF:5E:E4:35
                DirName:/CN=vpn.f5labs.dev
                serial:51:9C:76:87:21:63:D4:D3:FF:1E:54:B2:7B:8D:DF:13:1E:F5:6A:AC

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         57:33:02:49:cb:42:0f:82:7a:d8:bb:54:d8:36:d1:ad:4d:a0:
         8f:5a:3f:7d:49:0f:4b:2f:22:bd:08:5c:9e:78:79:e9:8c:0e:
         1a:d9:54:08:58:98:23:b6:0b:53:7d:f8:4c:fe:63:63:3d:74:
         74:d8:3f:84:f4:91:4a:65:11:41:cd:6b:1b:ea:d2:50:df:f0:
         c3:d5:07:88:c2:7d:45:fb:9a:59:56:02:c5:17:f5:13:86:e2:
         a8:db:1c:61:33:f3:53:26:51:a6:a2:9e:9d:4a:71:b1:01:bd:
         0e:70:2a:a1:5d:7c:37:eb:81:40:f3:0b:c6:ce:be:39:83:2b:
         53:d0:0f:54:51:90:31:3c:9e:ba:ec:d9:46:6c:98:ab:b9:ca:
         7c:56:71:c6:74:0b:b5:30:98:8d:e7:eb:e4:0d:cf:f4:43:28:
         09:63:f5:12:67:4a:1d:0f:cf:61:4d:c7:2e:6e:21:9f:09:62:
         06:1f:16:8b:a0:8d:2f:fa:a5:16:52:41:57:29:ac:99:4e:a4:
         4a:0f:76:4a:80:9b:88:1f:05:e9:9b:90:da:75:f3:bc:fa:c5:
         86:b2:70:95:05:24:74:50:b2:3a:ab:f7:05:84:22:93:11:d5:
         c9:00:48:4c:40:84:d4:7b:30:17:35:9b:02:d9:a3:79:c6:ab:
         16:fe:b4:de
-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIQO4COpjrZOeT/4A8ED7ut3TANBgkqhkiG9w0BAQsFADAZ
MRcwFQYDVQQDDA52cG4uZjVsYWJzLmRldjAeFw0yMTAxMTQwMjUzMzVaFw0yMzA0
MTkwMjUzMzVaMBwxGjAYBgNVBAMMEWNsaWVudC5mNWxhYnMuZGV2MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NsqRmiE1JwKozNAN/L0YN165V3Awkk1
u5wYmIx5QULZLcTng5XvZa6cpYA7viKFejiBcGQNSYh3h2qdEmwXKIRVl7T3s/3s
3LgWQwE8BvM798bAAIvIvQMfz+87+qd+TzrsFeO1t+0/OJ89jE8CTti2hR0s8Tf4
tj0IFG9XXRc/QEvjBQ05NH9OtOcM4ZVWrit7q9QmaV4nw4FYy3lAXtVwUpf9jY+J
P2Gh/19UBelsVOT0yqzUOvp43SfoaMQ8iVQ9kn34qmTTO+C1wZUQWHiHj8NMNz2g
djaoIgDywvwZbn8YQf5wcePF75ba2biAXxuYT4HwwEyfONG/Hgd+5wIDAQABo4Gl
MIGiMAkGA1UdEwQCMAAwHQYDVR0OBBYEFPwsehPmi24ua7PZR0ymThgR6iZLMFQG
A1UdIwRNMEuAFPxmt1dYj5OyOmEeQ3jULkPvXuQ1oR2kGzAZMRcwFQYDVQQDDA52
cG4uZjVsYWJzLmRldoIUUZx2hyFj1NP/HlSye43fEx71aqwwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBXMwJJy0IP
gnrYu1TYNtGtTaCPWj99SQ9LLyK9CFyeeHnpjA4a2VQIWJgjtgtTffhM/mNjPXR0
2D+E9JFKZRFBzWsb6tJQ3/DD1QeIwn1F+5pZVgLFF/UThuKo2xxhM/NTJlGmop6d
SnGxAb0OcCqhXXw364FA8wvGzr45gytT0A9UUZAxPJ667NlGbJirucp8VnHGdAu1
MJiN5+vkDc/0QygJY/USZ0odD89hTccubiGfCWIGHxaLoI0v+qUWUkFXKayZTqRK
D3ZKgJuIHwXpm5DadfO8+sWGsnCVBSR0ULI6q/cFhCKTEdXJAEhMQITUezAXNZsC
2aN5xqsW/rTe
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/client.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQ2ypGaITUnAqj
M0A38vRg3XrlXcDCSTW7nBiYjHlBQtktxOeDle9lrpylgDu+IoV6OIFwZA1JiHeH
ap0SbBcohFWXtPez/ezcuBZDATwG8zv3xsAAi8i9Ax/P7zv6p35POuwV47W37T84
nz2MTwJO2LaFHSzxN/i2PQgUb1ddFz9AS+MFDTk0f0605wzhlVauK3ur1CZpXifD
gVjLeUBe1XBSl/2Nj4k/YaH/X1QF6WxU5PTKrNQ6+njdJ+hoxDyJVD2SffiqZNM7
4LXBlRBYeIePw0w3PaB2NqgiAPLC/BlufxhB/nBx48XvltrZuIBfG5hPgfDATJ84
0b8eB37nAgMBAAECggEBALNUe+gYtnUXxsp6pxljMxI5Gdz3sxsfYVPFpBjYBQVU
MMZr253Qj83vL/GrOaD4Y0OeYQXv4rjQxFEx6cx3oyrW9eddK5MQ5OBf8D14QeJ1
13fY3+OYIrSoihgwgn+mcX32SeBBtTZIL5CeqmpfLMwmqBGEC6LTPGq93MIvGASE
84Lf28gVk69nPdj3ZHw7zjG5Rb5gmnVnj8HeiYKixFG7Ev0ttdczZ9g+XmEoCLDo
XQFUjgrllrJSJpV1GK1N4fntrDSrZ+GyM2R9dNcpgSEZ077QdIljjqHcfHgABjkB
Asbcjb0cQy9aIE3BwOkh39FPM71pcnRcXVlJsuGTIgECgYEA9ySHXI52hfqmMt1B
u/grY0LUb+mUrLh2GKAOPTzzN2zTzvBy6b7DvKbTmsOTiMVQ2j3rVIw/qLrIm4wg
TNoCIBBkM/gJ4MtbaR0tWhE8CIG//OiN+bVSIuojZ+6csNo4EgpXRhosaX5n9gw6
JWpCGGELKYkzBoqXMxALxYTDh1cCgYEA2Fdd5f/c9gYeMsUiKUxCq4PDZS6aNBO+
w5zxWGc7+gDJDTg3Cue4g65KYHm16ZCWLZittaV6xjcAU8hsgIq5mR/9nwd1DiFy
kmot5JWkQc23yqseq2lHwDKRCc6Fh77zpvt80WI5iD6v7kc4P1JViZtLJpVC1Rxi
JMzO8gzT2vECgYAQARmS8NbUDks89/8NwSBuKSHArYunM7rSFWtWo9/MMwv0VrXa
VTQvv03ss8WWEdEOkPvwWbS1pILhL83XrDZ/BRC4HNPm7sRYpj8NmhgdJOnd4uFu
zkMnZ6orTNRwz3DaGjlUnNVLb5gj4t7RFXR6R66FXhEj1027TMq2W8aduQKBgQCw
VR2ivxaxrLDmfslmUdMxixczHHXxpnphZEVO4e3/yq4UyVIL4G0DX4cd9XYxZnkR
txU3LibQ8rmgkIbniqrWRT3qZiChoN+KuWKootOcEvoQBcPcwNYLsOuIy70ItLpR
yz+kRmRQSZAKLiCJdClmHJ53V0d+/kB8cDbpEU2IcQKBgCZCfKbUevhQ37iN1AJZ
tNDQjCed/MMhcBQBCkWXin5lxgyctIPgZiNlk2w7nooNWFAYymKJ6HuAtetOYssS
i0AXVmVVagNwIw7b5Q5Z2jGBQ0W5H1s6qQ832zTlokWuwVpzq2HpGPIq0P5z4Omb
UG4rLe+2IINXbG3ry8s254N5
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF18'> /etc/openvpn/tls-auth.key
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
a6ac19848e934192f360fe63dbef8a11
58a6cc041c80ad117700529ce0d59372
a803d769dcf29240e5416af5adb44b94
04fc12c3d44fc07768e5bc7dd4181239
96a8908ab55de0af21f7c087c67f820a
1670975c349e8b68db5c83b77b83d6cc
fe31250e9b47229fe1a03612c99bdbb2
4bb959c342685919136ac72b697c9602
2404f8b228677dba6065a0e064b7a7ee
1fb45f63e58f4f8b00fd570d4e9a131e
429532c6eb3eaa4a25232fa1bff25a3d
ebc9a06ccb0965533849a072b2f7ddaa
6e1c0c8612e3d7545946da357d07b755
7a290dfb4394e830ef87c04a7cef72a2
f9a3d2114c3763242213502b862b934b
21717c8fe0eb02476870aff8089fcef4
-----END OpenVPN Static key V1-----
EOF18
 cat <<'EOF107'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ChangeMe
        Validity
            Not Before: Aug 14 10:33:16 2016 GMT
            Not After : Aug 12 10:33:16 2026 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:cf:02:40:c3:fc:07:c7:59:1a:de:1f:22:d9:a4:
                    78:fe:70:d8:ea:59:34:12:6d:64:3a:c8:dd:d9:bb:
                    ec:0f:24:bd:5f:a4:85:20:42:5e:1f:4b:fb:9f:3a:
                    fa:1b:2f:ac:bc:02:f9:af:ea:81:fb:42:6e:4a:6d:
                    5d:7e:11:83:ab:28:09:67:d8:ac:38:4f:31:1c:94:
                    55:2c:a2:59:22:52:ad:14:a5:d4:cd:81:b5:0b:55:
                    c9:f8:a7:0f:9b:a5:1a:6c:9e:93:9c:8b:bf:33:fb:
                    96:fd:d1:a3:60:a0:3b:e0:7e:26:62:72:2e:a7:8f:
                    28:4f:94:8d:39:37:77:8a:92:a7:35:13:08:e1:e8:
                    d4:4f:3b:7f:7d:06:00:fb:2a:9e:59:a1:59:56:de:
                    0d:f5:65:16:1b:35:f2:1e:1c:9d:6d:09:f4:1a:ad:
                    cc:07:50:61:15:44:8e:c3:c4:da:a3:dd:06:85:8a:
                    9e:e6:24:63:03:90:42:1e:75:34:b3:50:a2:e7:58:
                    14:8b:c4:f4:d7:85:41:fc:37:50:13:dd:46:e2:0c:
                    1c:56:22:4a:f8:90:f1:58:92:8a:03:5e:37:64:36:
                    36:e4:d1:41:d1:cc:ab:e7:33:f2:0d:7d:d9:cd:1d:
                    61:bb:a2:0c:48:39:6f:bf:f2:f8:19:dc:db:80:7f:
                    ab:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                51:97:18:0C:9D:4B:75:EE:D5:76:11:E3:E4:06:D9:65:F8:96:D4:C1
            X509v3 Authority Key Identifier: 
                keyid:CB:9C:82:4D:75:1C:D6:AB:A6:5E:7A:59:B2:3B:7A:D6:54:B7:EA:86
                DirName:/CN=ChangeMe
                serial:C0:93:EB:7C:93:D3:14:20

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         6b:01:ea:fc:6c:ad:46:4d:ae:9f:b8:91:15:07:ac:ea:e1:d8:
         3c:05:3c:b1:18:bb:56:f9:8a:a3:62:5b:ee:7a:b7:d8:6d:d5:
         5a:7f:f4:6c:b3:8e:a0:b6:be:4d:8e:36:16:4a:f8:b9:b8:43:
         13:1c:07:39:7c:34:18:61:80:bf:aa:a5:86:65:38:d8:ac:28:
         40:86:d3:f5:08:cd:49:d8:32:11:24:12:e6:dd:8d:8f:cc:72:
         fc:d5:03:9a:24:7d:12:d0:fd:a1:36:05:cc:34:e4:68:2e:f5:
         d9:a8:52:fd:e4:ff:06:75:da:35:35:45:65:84:d1:39:e1:23:
         d8:d2:02:70:27:ac:23:b2:d3:ec:57:4c:d0:ba:51:32:f1:24:
         69:b8:7e:0f:70:6c:5a:86:ce:18:17:a9:53:85:cf:13:b8:7f:
         03:06:8a:1f:a0:7b:a5:5e:65:a8:7f:e9:c1:b1:bf:78:3d:f3:
         82:57:f6:64:27:06:54:4c:aa:3d:27:9c:4c:31:fb:be:b1:d8:
         b8:4f:dd:a7:3d:ec:b2:76:d0:f0:59:84:cd:b9:ef:d7:4d:5e:
         4c:19:97:47:79:7d:cf:34:bf:76:be:01:dc:93:e6:5f:c6:fe:
         09:b6:e4:dc:71:c1:41:a7:3c:a7:65:80:a7:ff:f1:41:04:20:
         2f:ed:25:1d
-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDaGFu
Z2VNZTAeFw0xNjA4MTQxMDMzMTZaFw0yNjA4MTIxMDMzMTZaMBExDzANBgNVBAMT
BnNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM8CQMP8B8dZ
Gt4fItmkeP5w2OpZNBJtZDrI3dm77A8kvV+khSBCXh9L+586+hsvrLwC+a/qgftC
bkptXX4Rg6soCWfYrDhPMRyUVSyiWSJSrRSl1M2BtQtVyfinD5ulGmyek5yLvzP7
lv3Ro2CgO+B+JmJyLqePKE+UjTk3d4qSpzUTCOHo1E87f30GAPsqnlmhWVbeDfVl
Fhs18h4cnW0J9BqtzAdQYRVEjsPE2qPdBoWKnuYkYwOQQh51NLNQoudYFIvE9NeF
Qfw3UBPdRuIMHFYiSviQ8ViSigNeN2Q2NuTRQdHMq+cz8g192c0dYbuiDEg5b7/y
+Bnc24B/q2MCAwEAAaOBlDCBkTAJBgNVHRMEAjAAMB0GA1UdDgQWBBRRlxgMnUt1
7tV2EePkBtll+JbUwTBDBgNVHSMEPDA6gBTLnIJNdRzWq6ZeelmyO3rWVLfqhqEX
pBUwEzERMA8GA1UEAxMIQ2hhbmdlTWWCCQDAk+t8k9MUIDATBgNVHSUEDDAKBggr
BgEFBQcDATALBgNVHQ8EBAMCBaAwDQYJKoZIhvcNAQELBQADggEBAGsB6vxsrUZN
rp+4kRUHrOrh2DwFPLEYu1b5iqNiW+56t9ht1Vp/9GyzjqC2vk2ONhZK+Lm4QxMc
Bzl8NBhhgL+qpYZlONisKECG0/UIzUnYMhEkEubdjY/McvzVA5okfRLQ/aE2Bcw0
5Ggu9dmoUv3k/wZ12jU1RWWE0TnhI9jSAnAnrCOy0+xXTNC6UTLxJGm4fg9wbFqG
zhgXqVOFzxO4fwMGih+ge6VeZah/6cGxv3g984JX9mQnBlRMqj0nnEwx+76x2LhP
3ac97LJ20PBZhM2579dNXkwZl0d5fc80v3a+AdyT5l/G/gm25NxxwUGnPKdlgKf/
8UEEIC/tJR0=
-----END CERTIFICATE-----
EOF107
 cat <<'EOF113'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPAkDD/AfHWRre
HyLZpHj+cNjqWTQSbWQ6yN3Zu+wPJL1fpIUgQl4fS/ufOvobL6y8Avmv6oH7Qm5K
bV1+EYOrKAln2Kw4TzEclFUsolkiUq0UpdTNgbULVcn4pw+bpRpsnpOci78z+5b9
0aNgoDvgfiZici6njyhPlI05N3eKkqc1Ewjh6NRPO399BgD7Kp5ZoVlW3g31ZRYb
NfIeHJ1tCfQarcwHUGEVRI7DxNqj3QaFip7mJGMDkEIedTSzUKLnWBSLxPTXhUH8
N1AT3UbiDBxWIkr4kPFYkooDXjdkNjbk0UHRzKvnM/INfdnNHWG7ogxIOW+/8vgZ
3NuAf6tjAgMBAAECggEARV7R6VtqF+nKUSlJ+nldepbCejYOdyZlcjWh8rdA8goz
0/tECX10ITTLS57t9XJShmbQ2ZzSliq63wIrVHX2E8NE86HuhKg1IwiqSlzVVeUy
zzqLR5rx2qyTFFqXpmb7pe62NL24A2mKPeCkyVqo9iAQKOlurQQSVCjJ8qSd0Lee
Jl3/hgsb+AcfvWy5WRY+cJnpvJbK3tmotn9IGSVVdehGdI48UgO1HRJT3Y7eiwhG
p6sFLYQJ/OXHHWRZrxiE+ovKKSD3XP/p6nBY9/00kD7avoiEbXy4FhibaO8Na2s3
baNObCeFsJCU3/YsMNZyeBHFyafRaY1eryOn9NJ30QKBgQDtvFATLTQxJmhgMb3W
dc2GDCl6madicCKhyYYiLw/icLyVtF38bDhflFplREaPaWdLFfLeKAGhJHGUX021
qfxqTr9FyMB/0XUaOObSv/GMBOiBP8igBU6WlFkgo7BqYvQencls6uW3koJDE4Zn
vmTiVKqe/DFd1JwLTYTl+2e2HQKBgQDe6Z44Q5Vl1UIYRT0JazAbOu4oAYmrqiJz
Yn7ZFz95ybdSdCbRBmc11QjUwbGUzilW0VMcDbBXyVklxYxb6QPKViVafTp9rFb+
Kx/FtfMvA/w974rws+GQYHuyO3HzxNjHuJpaZgFYtzA1rC6mIIBGWWs5aLATBbiC
q+lHjYEvfwKBgAcq/l8VpdU1i0AbP9YPhzrbcwS3TUyyhNjL8rdlI913+Leq0Iqj
2K9JEdCr1lTMoMiqyL/aBPKO3r3Sgc1QasPpy+qWuvcfoaBAxvTjxKysGTaMbcgl
YNE5d9Z8GP2cLjAeIcye6H44dKUBGbRXEUOhueNBR1vE5U+R7sfgZKghAoGBAJJj
u7tZbuB8Z7aGqenokaQgVEzDjcTFq3A5K/KnmNEDTrgAfYlh+h/ZMr5+IYAG0BEq
0LioqLlOCpSKon2tjgawAkHl4aasqkiqy2fM8NJcfKe0C3u9thFZu4I2FcSv7mli
60MYoCPB0hA9bjk9OOB6UrdV7+PeKujtuvp5jHBDAoGAYqzvAU3vYfVl9Kkscfq9
zeu2kSkgeOd/atD6de8MrEA+Qp/Hc45W13GwFNuF+V00dUBJV/h9sXpDSMXll7QO
xm75IsESEVTypMe2wQvRew320Zq7AjhSmqZt7wBmAV/jrDD3+zPhkfJQJCGjj5pa
Sind6PdhhXcsZkAs+HILUdY=
-----END PRIVATE KEY-----
EOF113
 cat <<'EOF13'> /etc/openvpn/dh.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAp0RgQfX3lSJCtL2XQ9qfD+2XIJQgUIXLDpQkq6QvmSv8WHIxDIHw
gDV/pPrynPk+jYC9TITC6DEPchI04RXF9PCPDF7pfwDANgtm1h8xmQWuLsbvlSsU
3/TFtvYrMgPD/ByKm6jle0vllgCFldSKVztD3o2sa8qH5C3pjbDtVtm1ITUs1oMN
RjSAvtB/YJP2c61F2PFqLeYwWwMlQAsahIaUIgZjNySUKJQqOX1tEE6eQLflmqFy
6mWxGaynCsj/yOaS9/CC/OWoeaAK5yMCWl/JEItneZrnzUJkqPWJMoNA0nyCdNga
wBHj0G6bzjL+6jBBJSjuRPpd+zgf9ye0QwIBAg==
-----END DH PARAMETERS-----
EOF13
 cat <<'EOF103'> /etc/openvpn/crl.pem
-----BEGIN X509 CRL-----
MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDaGFuZ2VNZRcN
MTYwODE0MTAzMzE2WhcNMTcwMjEwMTAzMzE2WqBHMEUwQwYDVR0jBDwwOoAUy5yC
TXUc1qumXnpZsjt61lS36oahF6QVMBMxETAPBgNVBAMTCENoYW5nZU1lggkAwJPr
fJPTFCAwDQYJKoZIhvcNAQELBQADggEBAEYgz7+T9QUF78FV+kygIyaVXufHMOKY
vxUdhqX3MH5NSAFiXw4QDXGAoXV+rpHWIvLKa+95/UJdj43evUQ+iyN//WUKcOwU
fNoveG7izz4XU2+qG7+KJAJxh0vmDtBov320uFQ4aGFfX0hpGwIdq8ERaL2SlY47
F9lAzntIAhFd4rbK+ymof1ydXOTkO+8EWVBUeMFYbPiQyNAfqP0c5sYOrg/KXX5y
NbI7qzp9I3lqtBM9UG/+3awosNttECRFZOtbXO0W1MtSaLle9DtfMdyiXbpM+Jlb
R/jd9oqCp8NaSlesfNBnSn1i/kRYe/9noOc7pDBBQJAnfV7gQJYyIqA=
-----END X509 CRL-----
EOF103

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
#done
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_udp.conf
#done

 # setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf
 
 # Generating openvpn dh.pem file using openssl
 #openssl dhparam -out /etc/openvpn/dh.pem 1024
 
 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://gakod.com/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

 # Iptables Rule for OpenVPN server
 #PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
 #IPCIDR='10.200.0.0/16'
 #iptables -I FORWARD -s $IPCIDR -j ACCEPT
 #iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
 #iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
 
 # Installing Firewalld
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 
 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_udp
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_udp
 
 # Pulling OpenVPN no internet fixer script
 #wget -qO /etc/openvpn/openvpn.bash "https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn.bash"
 #0chmod +x /etc/openvpn/openvpn.bash
}

function InsProxy(){
 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 
# Squid Ports (must be 1024 or higher)
 Proxy_Port1='8000'
 Proxy_Port2='8080'
 Proxy_Port3='3128'
 Proxy_Port4='8888'
 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port1
http_port 0.0.0.0:$Proxy_Port2
http_port 0.0.0.0:$Proxy_Port3
http_port 0.0.0.0:$Proxy_Port4
acl all src 0.0.0.0/0
http_access allow all
forwarded_for off
via off
request_header_access Host allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access All deny all
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|$Privoxy_Port1|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server.."
 systemctl restart privoxy
 systemctl restart squid
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/bonveio-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/bonveio-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn
# Now creating all of our OpenVPN Configs 
cat <<EOF152> /var/www/openvpn/GTMConfig.ovpn
client
auth-user-pass
dev tun
proto tcp
setenv FRIENDLY_NAME "I'M MASTA GAKOD"
remote $IPADDR $OpenVPN_Port1 tcp
http-proxy $IPADDR 8080
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/client.crt)
</cert>
<key>
$(cat /etc/openvpn/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/tls-auth.key)
</tls-auth>
EOF152

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- OVPN Download site by LODIxyrussScript -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For EZ/GS Promo with WNP freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTMConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For TU UDP Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SunConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Trinet GIGASTORIES Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GStories.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r Configs.zip *.ovpn
 cd
}
function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/barts
 mkdir -p /etc/barts
 chmod -R 755 /etc/barts
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/barts/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
EOFSH
 chmod +x /etc/barts/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/barts/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 echo "[Unit]
Description=Barts Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/barts/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/barts.service
 chmod +x /etc/systemd/system/barts.service
 systemctl daemon-reload
 systemctl start barts
 systemctl enable barts &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}
function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/Barts-23/menu1/master/menu.zip'
unzip -qq menu.zip
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~

echo 'clear' > /etc/profile.d/barts.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/barts.sh
echo 'screenfetch -p -A Android' >> /etc/profile.d/barts.sh
chmod +x /etc/profile.d/barts.sh
}

function ScriptMessage(){
 echo -e " (GAKODS) $MyScriptName Debian VPS Installer"
 echo -e " Open release version"
 echo -e ""
 echo -e " Script created by Bonveio"
 echo -e " Edited by LODIxyruss"
}


#############################
#############################
## Installation Process
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mÃƒâ€”\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Privoxy and Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/barts.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 echo -e ""
 echo -e " Success Installation"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " OpenSSH: $SSH_Port1, $SSH_Port2"
 echo -e " Stunnel: $Stunnel_Port1, $Stunnel_Port2"
 echo -e " DropbearSSH: $Dropbear_Port1, $Dropbear_Port2"
 echo -e " Privoxy: $Privoxy_Port1, $Privoxy_Port2"
 echo -e " Squid: $Proxy_Port1, $Proxy_Port2"
 echo -e " OpenVPN: $OpenVPN_Port1, $OpenVPN_Port2"
 echo -e " OpenVPN SSL: $Stunnel_Port3"
 echo -e " NGiNX: $OvpnDownload_Port"
 echo -e " Webmin: 10000"
 echo -e " L2tp IPSec Key: fakenetvpn101"
 echo -e ""
 echo -e ""
 echo -e " OpenVPN Configs Download site"
 echo -e " http://$IPADDR:$OvpnDownload_Port"
 echo -e ""
 echo -e " All OpenVPN Configs Archive"
 echo -e " http://$IPADDR:$OvpnDownload_Port/Configs.zip"
 echo -e ""
 echo -e ""
 echo -e " [Note] DO NOT RESELL THIS SCRIPT"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

rm -f yy*
exit 1
