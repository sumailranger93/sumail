#!/bin/sh

wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -
sleep 2
echo "deb http://build.openvpn.net/debian/openvpn/release/2.4 stretch main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
#Requirement
apt update
apt upgrade -y
apt install openvpn nginx php7.0-fpm stunnel4 squid3 dropbear easy-rsa vnstat ufw build-essential fail2ban zip -y

# initializing var
MYIP=`ifconfig eth0 | awk 'NR==2 {print $2}'`
MYIP2="s/xxxxxxxxx/$MYIP/g";
cd /root
# wget "https://raw.githubusercontent.com/Gugun09/VPSauto/master/tool/plugin.tgz"
wget "https://raw.githubusercontent.com/Gugun09/VPSauto/master/tool/premiummenu.zip"

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6


# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime

# install webmin
cd
wget "https://raw.githubusercontent.com/Gugun09/premscript/master/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/Gugun09/VPSauto/master/tool/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=444/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
apt-get -y install squid
cat > /etc/squid/squid.conf <<-END
acl server dst xxxxxxxxx/32 localhost
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
via on
request_header_access X-Forwarded-For deny all
request_header_access user-agent  deny all
reply_header_access X-Forwarded-For deny all
reply_header_access user-agent  deny all
http_port 8080
http_port 3128
http_port 8000
http_port 8888
acl all src 0.0.0.0/0
http_access allow all
access_log /var/log/squid/access.log
visible_hostname TD-LTE/FDD-LTE(nb110.cn)
cache_mgr Welcome_to_use_OpenVPN
#
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/Gugun09/premscript/master/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/servertcp.conf
# GakodScript

port 443
proto tcp
dev tun
dev-type tun
sndbuf 100000
rcvbuf 100000
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth tls-auth.key 0
dh dh.pem
topology subnet
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-tun
status openvpn-status.log
verb 2
mute 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
username-as-common-name
myOpenVPNconf1

cat <<'myOpenVPNconf2' > /etc/openvpn/serverudp.conf
# GakodScript

port 1194
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "redirect-gateway def1 bypass-dhcp" 
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
cipher AES-128-CBC
tls-server
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
status openvpn.log
verb 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
username-as-common-name
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIGKDCCBBCgAwIBAgIJAKFO3vqQ8q6BMA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNV
BAYTAktHMQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UEChMM
T3BlblZQTi1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW4w
HhcNMTQxMDIyMjE1OTUyWhcNMjQxMDE5MjE1OTUyWjBmMQswCQYDVQQGEwJLRzEL
MAkGA1UECBMCTkExEDAOBgNVBAcTB0JJU0hLRUsxFTATBgNVBAoTDE9wZW5WUE4t
VEVTVDEhMB8GCSqGSIb3DQEJARYSbWVAbXlob3N0Lm15ZG9tYWluMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsJVPCqt3vtoDW2U0DII1QIh2Qs0dqh88
8nivxAIm2LTq93e9fJhsq3P/UVYAYSeCIrekXypR0EQgSgcNTvGBMe20BoHO5yvb
GjKPmjfLj6XRotCOGy8EDl/hLgRY9efiA8wsVfuvF2q/FblyJQPR/gPiDtTmUiqF
qXa7AJmMrqFsnWppOuGd7Qc6aTsae4TF1e/gUTCTraa7NeHowDaKhdyFmEEnCYR5
CeUsx2JlFWAH8PCrxBpHYbmGyvS0kH3+rQkaSM/Pzc2bS4ayHaOYRK5XsGq8XiNG
KTTLnSaCdPeHsI+3xMHmEh+u5Og2DFGgvyD22gde6W2ezvEKCUDrzR7bsnYqqyUy
n7LxnkPXGyvR52T06G8KzLKQRmDlPIXhzKMO07qkHmIonXTdF7YI1azwHpAtN4dS
rUe1bvjiTSoEsQPfOAyvD0RMK/CBfgEZUzAB50e/IlbZ84c0DJfUMOm4xCyft1HF
YpYeyCf5dxoIjweCPOoP426+aTXM7kqq0ieIr6YxnKV6OGGLKEY+VNZh1DS7enqV
HP5i8eimyuUYPoQhbK9xtDGMgghnc6Hn8BldPMcvz98HdTEH4rBfA3yNuCxLSNow
4jJuLjNXh2QeiUtWtkXja7ec+P7VqKTduJoRaX7cs+8E3ImigiRnvmK+npk7Nt1y
YE9hBRhSoLsCAwEAAaOB2DCB1TAdBgNVHQ4EFgQUK0DlyX319JY46S/jL9lAZMmO
BZswgZgGA1UdIwSBkDCBjYAUK0DlyX319JY46S/jL9lAZMmOBZuhaqRoMGYxCzAJ
BgNVBAYTAktHMQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UE
ChMMT3BlblZQTi1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21h
aW6CCQChTt76kPKugTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG
9w0BAQsFAAOCAgEABc77f4C4P8fIS+V8qCJmVNSDU44UZBc+D+J6ZTgW8JeOHUIj
Bh++XDg3gwat7pIWQ8AU5R7h+fpBI9n3dadyIsMHGwSogHY9Gw7di2RVtSFajEth
rvrq0JbzpwoYedMh84sJ2qI/DGKW9/Is9+O52fR+3z3dY3gNRDPQ5675BQ5CQW9I
AJgLOqzD8Q0qrXYi7HaEqzNx6p7RDTuhFgvTd+vS5d5+28Z5fm2umnq+GKHF8W5P
ylp2Js119FTVO7brusAMKPe5emc7tC2ov8OFFemQvfHR41PLryap2VD81IOgmt/J
kX/j/y5KGux5HZ3lxXqdJbKcAq4NKYQT0mCkRD4l6szaCEJ+k0SiM9DdTcBDefhR
9q+pCOyMh7d8QjQ1075mF7T+PGkZQUW1DUjEfrZhICnKgq+iEoUmM0Ee5WtRqcnu
5BTGQ2mSfc6rV+Vr+eYXqcg7Nxb3vFXYSTod1UhefonVqwdmyJ2sC79zp36Tbo2+
65NW2WJK7KzPUyOJU0U9bcu0utvDOvGWmG+aHbymJgcoFzvZmlXqMXn97pSFn4jV
y3SLRgJXOw1QLXL2Y5abcuoBVr4gCOxxk2vBeVxOMRXNqSWZOFIF1bu/PxuDA+Sa
hEi44aHbPXt9opdssz/hdGfd8Wo7vEJrbg7c6zR6C/Akav1Rzy9oohIdgOw=
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/client.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=KG, ST=NA, L=BISHKEK, O=OpenVPN-TEST/emailAddress=me@myhost.mydomain
        Validity
            Not Before: Oct 22 21:59:53 2014 GMT
            Not After : Oct 19 21:59:53 2024 GMT
        Subject: C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Client/emailAddress=me@myhost.mydomain
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ec:65:8f:e9:12:c2:1a:5b:e6:56:2a:08:a9:82:
                    3a:2d:44:78:a3:00:3b:b0:9f:e7:27:10:40:93:ef:
                    f1:cc:3e:a0:aa:04:a2:80:1b:13:a9:e6:fe:81:d6:
                    70:90:a8:d8:d4:de:30:d8:35:00:d2:be:62:f0:48:
                    da:fc:15:8d:c4:c6:6d:0b:99:f1:2b:83:00:0a:d3:
                    2a:23:0b:e5:cd:f9:35:df:43:61:15:72:ad:95:98:
                    f6:73:21:41:5e:a0:dd:47:27:a0:d5:9a:d4:41:a8:
                    1c:1d:57:20:71:17:8f:f7:28:9e:3e:07:ce:ec:d5:
                    0e:42:4f:1e:74:47:8e:47:9d:d2:14:28:27:2c:14:
                    10:f5:d1:96:b5:93:74:84:ef:f9:04:de:8d:4a:6f:
                    df:77:ab:ea:d1:58:d3:44:fe:5a:04:01:ff:06:7a:
                    97:f7:fd:e3:57:48:e1:f0:df:40:13:9f:66:23:5a:
                    e3:55:54:3d:54:39:ee:00:f9:12:f1:d2:df:74:2e:
                    ba:d7:f0:8d:c6:dd:18:58:1c:93:22:0b:75:fa:a8:
                    d6:e0:b5:2f:2d:b9:d4:fe:b9:4f:86:e2:75:48:16:
                    60:fb:3f:c9:b4:30:42:29:fb:3b:b3:2b:b9:59:81:
                    6a:46:f3:45:83:bf:fd:d5:1a:ff:37:0c:6f:5b:fd:
                    61:f1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                D2:B4:36:0F:B1:FC:DD:A5:EA:2A:F7:C7:23:89:FA:E3:FA:7A:44:1D
            X509v3 Authority Key Identifier: 
                keyid:2B:40:E5:C9:7D:F5:F4:96:38:E9:2F:E3:2F:D9:40:64:C9:8E:05:9B
                DirName:/C=KG/ST=NA/L=BISHKEK/O=OpenVPN-TEST/emailAddress=me@myhost.mydomain
                serial:A1:4E:DE:FA:90:F2:AE:81

    Signature Algorithm: sha256WithRSAEncryption
         7f:e0:fe:84:a7:ec:df:62:a5:cd:3c:c1:e6:42:b1:31:12:f0:
         b9:da:a7:9e:3f:bd:96:52:b6:fc:55:74:64:3e:e4:ff:7e:aa:
         f7:3e:06:18:5f:73:85:f8:c8:e0:67:1b:4d:97:ca:05:d0:37:
         07:33:64:9b:e6:78:77:14:9a:55:bb:2a:ac:c3:7f:c9:15:08:
         83:5c:c8:c2:61:d3:71:4c:05:0b:2b:cb:a3:87:6d:a0:32:ed:
         b0:b3:27:97:4a:55:8d:01:2a:30:56:68:ab:f2:da:5c:10:73:
         c9:aa:0a:9c:4b:4c:a0:5b:51:6e:0a:7e:6c:53:80:b0:00:e1:
         1e:9a:4c:0a:37:9e:20:89:bc:c5:e5:79:58:b7:45:ff:d3:c4:
         a1:fd:d9:78:3d:45:16:74:df:82:44:1d:1d:81:50:5a:b9:32:
         4c:e2:4f:3f:0e:3a:65:5a:64:83:3b:29:31:c4:99:88:bc:c5:
         84:39:f2:19:12:e1:66:d0:ea:fb:75:b1:d2:27:be:91:59:a3:
         2b:09:d5:5c:bf:46:8e:d6:67:d6:0b:ec:da:ab:f0:80:19:87:
         64:07:a9:77:b1:5e:0c:e2:c5:1d:6a:ac:5d:23:f3:30:75:36:
         4e:ca:c3:4e:b0:4d:8c:2c:ce:52:61:63:de:d5:f5:ef:ef:0a:
         6b:23:25:26:3c:3a:f2:c3:c2:16:19:3f:a9:32:ba:68:f9:c9:
         12:3c:3e:c6:1f:ff:9b:4e:f4:90:b0:63:f5:d1:33:00:30:5a:
         e8:24:fa:35:44:9b:6a:80:f3:a6:cc:7b:3c:73:5f:50:c4:30:
         71:d8:74:90:27:0a:01:4e:a5:5e:b1:f8:da:c2:61:81:11:ae:
         29:a3:8f:fa:7e:4c:4e:62:b1:00:de:92:e3:8f:6a:2e:da:d9:
         38:5d:6b:7c:0d:e4:01:aa:c8:c6:6d:8b:cd:c0:c8:6e:e4:57:
         21:8a:f6:46:30:d9:ad:51:a1:87:96:a6:53:c9:1e:c6:bb:c3:
         eb:55:fe:8c:d6:5c:d5:c6:f3:ca:b0:60:d2:d4:2a:1f:88:94:
         d3:4c:1a:da:0c:94:fe:c1:5d:0d:2a:db:99:29:5d:f6:dd:16:
         c4:c8:4d:74:9e:80:d9:d0:aa:ed:7b:e3:30:e4:47:d8:f5:15:
         c1:71:b8:c6:fd:ee:fc:9e:b2:5f:b5:b7:92:ed:ff:ca:37:f6:
         c7:82:b4:54:13:9b:83:cd:87:8b:7e:64:f6:2e:54:3a:22:b1:
         c5:c1:f4:a5:25:53:9a:4d:a8:0f:e7:35:4b:89:df:19:83:66:
         64:d9:db:d1:61:2b:24:1b:1d:44:44:fb:49:30:87:b7:49:23:
         08:02:8a:e0:25:f3:f4:43
-----BEGIN CERTIFICATE-----
MIIFFDCCAvygAwIBAgIBAjANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJLRzEL
MAkGA1UECBMCTkExEDAOBgNVBAcTB0JJU0hLRUsxFTATBgNVBAoTDE9wZW5WUE4t
VEVTVDEhMB8GCSqGSIb3DQEJARYSbWVAbXlob3N0Lm15ZG9tYWluMB4XDTE0MTAy
MjIxNTk1M1oXDTI0MTAxOTIxNTk1M1owajELMAkGA1UEBhMCS0cxCzAJBgNVBAgT
Ak5BMRUwEwYDVQQKEwxPcGVuVlBOLVRFU1QxFDASBgNVBAMTC1Rlc3QtQ2xpZW50
MSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW4wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDsZY/pEsIaW+ZWKgipgjotRHijADuwn+cnEECT
7/HMPqCqBKKAGxOp5v6B1nCQqNjU3jDYNQDSvmLwSNr8FY3Exm0LmfErgwAK0yoj
C+XN+TXfQ2EVcq2VmPZzIUFeoN1HJ6DVmtRBqBwdVyBxF4/3KJ4+B87s1Q5CTx50
R45HndIUKCcsFBD10Za1k3SE7/kE3o1Kb993q+rRWNNE/loEAf8Gepf3/eNXSOHw
30ATn2YjWuNVVD1UOe4A+RLx0t90LrrX8I3G3RhYHJMiC3X6qNbgtS8tudT+uU+G
4nVIFmD7P8m0MEIp+zuzK7lZgWpG80WDv/3VGv83DG9b/WHxAgMBAAGjgcgwgcUw
CQYDVR0TBAIwADAdBgNVHQ4EFgQU0rQ2D7H83aXqKvfHI4n64/p6RB0wgZgGA1Ud
IwSBkDCBjYAUK0DlyX319JY46S/jL9lAZMmOBZuhaqRoMGYxCzAJBgNVBAYTAktH
MQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UEChMMT3BlblZQ
Ti1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW6CCQChTt76
kPKugTANBgkqhkiG9w0BAQsFAAOCAgEAf+D+hKfs32KlzTzB5kKxMRLwudqnnj+9
llK2/FV0ZD7k/36q9z4GGF9zhfjI4GcbTZfKBdA3BzNkm+Z4dxSaVbsqrMN/yRUI
g1zIwmHTcUwFCyvLo4dtoDLtsLMnl0pVjQEqMFZoq/LaXBBzyaoKnEtMoFtRbgp+
bFOAsADhHppMCjeeIIm8xeV5WLdF/9PEof3ZeD1FFnTfgkQdHYFQWrkyTOJPPw46
ZVpkgzspMcSZiLzFhDnyGRLhZtDq+3Wx0ie+kVmjKwnVXL9GjtZn1gvs2qvwgBmH
ZAepd7FeDOLFHWqsXSPzMHU2TsrDTrBNjCzOUmFj3tX17+8KayMlJjw68sPCFhk/
qTK6aPnJEjw+xh//m070kLBj9dEzADBa6CT6NUSbaoDzpsx7PHNfUMQwcdh0kCcK
AU6lXrH42sJhgRGuKaOP+n5MTmKxAN6S449qLtrZOF1rfA3kAarIxm2LzcDIbuRX
IYr2RjDZrVGhh5amU8kexrvD61X+jNZc1cbzyrBg0tQqH4iU00wa2gyU/sFdDSrb
mSld9t0WxMhNdJ6A2dCq7XvjMORH2PUVwXG4xv3u/J6yX7W3ku3/yjf2x4K0VBOb
g82Hi35k9i5UOiKxxcH0pSVTmk2oD+c1S4nfGYNmZNnb0WErJBsdRET7STCHt0kj
CAKK4CXz9EM=
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/client.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDsZY/pEsIaW+ZW
KgipgjotRHijADuwn+cnEECT7/HMPqCqBKKAGxOp5v6B1nCQqNjU3jDYNQDSvmLw
SNr8FY3Exm0LmfErgwAK0yojC+XN+TXfQ2EVcq2VmPZzIUFeoN1HJ6DVmtRBqBwd
VyBxF4/3KJ4+B87s1Q5CTx50R45HndIUKCcsFBD10Za1k3SE7/kE3o1Kb993q+rR
WNNE/loEAf8Gepf3/eNXSOHw30ATn2YjWuNVVD1UOe4A+RLx0t90LrrX8I3G3RhY
HJMiC3X6qNbgtS8tudT+uU+G4nVIFmD7P8m0MEIp+zuzK7lZgWpG80WDv/3VGv83
DG9b/WHxAgMBAAECggEBAIOdaCpUD02trOh8LqZxowJhBOl7z7/ex0uweMPk67LT
i5AdVHwOlzwZJ8oSIknoOBEMRBWcLQEojt1JMuL2/R95emzjIKshHHzqZKNulFvB
TIUpdnwChTKtH0mqUkLlPU3Ienty4IpNlpmfUKimfbkWHERdBJBHbtDsTABhdo3X
9pCF/yRKqJS2Fy/Mkl3gv1y/NB1OL4Jhl7vQbf+kmgfQN2qdOVe2BOKQ8NlPUDmE
/1XNIDaE3s6uvUaoFfwowzsCCwN2/8QrRMMKkjvV+lEVtNmQdYxj5Xj5IwS0vkK0
6icsngW87cpZxxc1zsRWcSTloy5ohub4FgKhlolmigECgYEA+cBlxzLvaMzMlBQY
kCac9KQMvVL+DIFHlZA5i5L/9pRVp4JJwj3GUoehFJoFhsxnKr8HZyLwBKlCmUVm
VxnshRWiAU18emUmeAtSGawlAS3QXhikVZDdd/L20YusLT+DXV81wlKR97/r9+17
klQOLkSdPm9wcMDOWMNHX8bUg8kCgYEA8k+hQv6+TR/+Beao2IIctFtw/EauaJiJ
wW5ql1cpCLPMAOQUvjs0Km3zqctfBF8mUjdkcyJ4uhL9FZtfywY22EtRIXOJ/8VR
we65mVo6RLR8YVM54sihanuFOnlyF9LIBWB+9pUfh1/Y7DSebh7W73uxhAxQhi3Y
QwfIQIFd8OkCgYBalH4VXhLYhpaYCiXSej6ot6rrK2N6c5Tb2MAWMA1nh+r84tMP
gMoh+pDgYPAqMI4mQbxUmqZEeoLuBe6VHpDav7rPECRaW781AJ4ZM4cEQ3Jz/inz
4qOAMn10CF081/Ez9ykPPlU0bsYNWHNd4eB2xWnmUBKOwk7UgJatVPaUiQKBgQCI
f18CVGpzG9CHFnaK8FCnMNOm6VIaTcNcGY0mD81nv5Dt943P054BQMsAHTY7SjZW
HioRyZtkhonXAB2oSqnekh7zzxgv4sG5k3ct8evdBCcE1FNJc2eqikZ0uDETRoOy
s7cRxNNr+QxDkyikM+80HOPU1PMPgwfOSrX90GJQ8QKBgEBKohGMV/sNa4t14Iau
qO8aagoqh/68K9GFXljsl3/iCSa964HIEREtW09Qz1w3dotEgp2w8bsDa+OwWrLy
0SY7T5jRViM3cDWRlUBLrGGiL0FiwsfqiRiji60y19erJgrgyGVIb1kIgIBRkgFM
2MMweASzTmZcri4PA/5C0HYb
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF18'> /etc/openvpn/tls-auth.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
a863b1cbdb911ff4ef3360ce135157e7
241a465f5045f51cf9a92ebc24da34fd
5fc48456778c977e374d55a8a7298aef
40d0ab0c60b5e09838510526b73473a0
8da46a8c352572dd86d4a871700a915b
6aaa58a9dac560db2dfdd7ef15a202e1
fca6913d7ee79c678c5798fbf7bd920c
caa7a64720908da7254598b052d07f55
5e31dc5721932cffbdd8965d04107415
46c86823da18b66aab347e4522cc05ff
634968889209c96b1024909cd4ce574c
f829aa9c17d5df4a66043182ee23635d
8cabf5a7ba02345ad94a3aa25a63d55c
e13f4ad235a0825e3fe17f9419baff1c
e73ad1dd652f1e48c7102fe8ee181e54
10a160ae255f63fd01db1f29e6efcb8e
-----END OpenVPN Static key V1-----
EOF18
 cat <<'EOF107'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=KG, ST=NA, L=BISHKEK, O=OpenVPN-TEST/emailAddress=me@myhost.mydomain
        Validity
            Not Before: Oct 22 21:59:52 2014 GMT
            Not After : Oct 19 21:59:52 2024 GMT
        Subject: C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server/emailAddress=me@myhost.mydomain
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a5:b8:a2:ee:ce:b1:a6:0f:6a:b2:9f:d3:22:17:
                    79:de:09:98:71:78:fa:a7:ce:36:51:54:57:c7:31:
                    99:56:d1:8a:d6:c5:fd:52:e6:88:0e:7b:f9:ea:27:
                    7a:bf:3f:14:ec:aa:d2:ff:8b:56:58:ac:ca:51:77:
                    c5:3c:b6:e4:83:6f:22:06:2d:5b:eb:e7:59:d4:ab:
                    42:c8:d5:a9:87:73:b3:73:36:51:2f:a5:d0:90:a2:
                    87:64:54:6c:12:d3:b8:76:47:69:af:ae:8f:00:b3:
                    70:b9:e7:67:3f:8c:6a:3d:79:5f:81:27:a3:0e:aa:
                    a7:3d:81:48:10:b1:18:6c:38:2e:8f:7a:7b:c5:3d:
                    21:c8:f9:a0:7f:17:2b:88:4f:ba:f2:ec:6d:24:8e:
                    6c:f1:0a:5c:d9:5b:b1:b0:fc:49:cb:4a:d2:58:c6:
                    2a:25:b0:97:84:c3:9e:ff:34:8c:10:46:7f:0f:fb:
                    3c:59:7a:a6:29:0c:ae:8e:50:3a:f2:53:84:40:2d:
                    d5:91:7b:0a:37:8e:82:77:ce:66:2f:34:77:5c:a5:
                    45:3b:00:19:a7:07:d1:92:e6:66:b9:3b:4e:e9:63:
                    fc:33:98:1a:ae:7b:08:7d:0a:df:7a:ba:aa:59:6d:
                    86:82:0a:64:2b:da:59:a7:4c:4e:ef:3d:bd:04:a2:
                    4b:31
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                OpenSSL Generated Server Certificate
            X509v3 Subject Key Identifier: 
                B3:9D:81:E6:16:92:64:C4:86:87:F5:29:10:1B:5E:2F:74:F7:ED:B1
            X509v3 Authority Key Identifier: 
                keyid:2B:40:E5:C9:7D:F5:F4:96:38:E9:2F:E3:2F:D9:40:64:C9:8E:05:9B
                DirName:/C=KG/ST=NA/L=BISHKEK/O=OpenVPN-TEST/emailAddress=me@myhost.mydomain
                serial:A1:4E:DE:FA:90:F2:AE:81

            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         4e:25:80:1b:cb:b0:42:ff:bb:3f:e8:0d:58:c1:80:db:cf:d0:
         90:df:ca:c1:e6:41:e1:48:7f:a7:1e:c7:35:9f:9c:6d:7c:3e:
         82:e8:de:7e:ae:82:16:00:33:0f:02:23:f1:9d:fe:2b:06:16:
         05:55:16:89:dc:63:ac:5f:1a:31:13:79:21:a3:6e:60:28:e8:
         e7:6b:54:00:22:a1:b7:69:5a:17:31:ce:0f:c2:a6:dd:a3:6f:
         de:ea:19:6c:d2:d2:cb:35:9d:dd:87:51:33:68:cd:c3:9b:90:
         55:f1:80:3d:5c:b8:09:b6:e1:3c:13:a4:5d:4a:ce:a5:11:9e:
         f9:08:ee:be:e3:54:1d:06:4c:bb:1b:72:13:ee:7d:a0:45:cc:
         fe:d1:3b:02:03:c1:d4:ea:45:2d:a8:c9:97:e7:f3:8a:7a:a0:
         2f:dd:48:3a:75:c9:42:28:94:fc:af:44:52:16:68:98:d6:ad:
         a8:65:b1:cd:ac:60:41:70:e5:44:e8:5a:f2:e7:fc:3b:fe:45:
         89:17:1d:6d:85:c6:f0:fc:69:87:d1:1d:07:f3:cb:7b:54:8d:
         aa:a3:cc:e3:c6:fc:d6:05:76:35:d0:26:63:8e:d1:a8:b7:ff:
         61:42:8a:2c:63:1f:d4:ec:14:47:6b:1e:e3:81:61:12:3b:8c:
         16:b5:cf:87:6a:2d:42:21:83:9c:0e:3a:90:3a:1e:c1:36:61:
         41:f9:fb:4e:5d:ea:f4:df:23:92:33:2b:9b:14:9f:a0:f5:d3:
         c4:f8:1f:2f:9c:11:36:af:2a:22:61:95:32:0b:c4:1c:2d:b1:
         c1:0a:2a:97:c0:43:4a:6c:3e:db:00:cd:29:15:9e:7e:41:75:
         36:a8:56:86:8c:82:9e:46:20:e5:06:1e:60:d2:03:5f:9f:9e:
         69:bb:bf:c2:b4:43:e2:7d:85:17:83:18:41:b0:cb:a9:04:1b:
         18:52:9f:89:8b:76:9f:94:59:81:4f:60:5b:33:18:fc:c7:52:
         d0:d2:69:fc:0b:a2:63:32:75:43:99:e9:d7:f8:6d:c7:55:31:
         0c:f3:ef:1a:71:e1:0a:57:e1:9d:13:b2:1e:fe:1d:ef:e4:f1:
         51:d9:95:b3:fd:28:28:93:91:4a:29:c5:37:0e:ab:d8:85:6a:
         fe:a8:83:1f:7b:80:5d:1f:04:79:b7:a9:08:6e:0d:d6:2e:aa:
         7c:f6:63:7d:41:de:70:13:32:ce:dd:58:cc:a6:73:d4:72:7e:
         d7:ac:74:a8:35:ba:c3:1b:2a:64:d7:5a:37:97:56:94:34:2b:
         2a:71:60:bc:69:ab:00:85:b9:4f:67:32:17:51:c3:da:57:3a:
         37:89:66:c4:7a:51:da:5f
-----BEGIN CERTIFICATE-----
MIIFgDCCA2igAwIBAgIBATANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJLRzEL
MAkGA1UECBMCTkExEDAOBgNVBAcTB0JJU0hLRUsxFTATBgNVBAoTDE9wZW5WUE4t
VEVTVDEhMB8GCSqGSIb3DQEJARYSbWVAbXlob3N0Lm15ZG9tYWluMB4XDTE0MTAy
MjIxNTk1MloXDTI0MTAxOTIxNTk1MlowajELMAkGA1UEBhMCS0cxCzAJBgNVBAgT
Ak5BMRUwEwYDVQQKEwxPcGVuVlBOLVRFU1QxFDASBgNVBAMTC1Rlc3QtU2VydmVy
MSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW4wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCluKLuzrGmD2qyn9MiF3neCZhxePqnzjZRVFfH
MZlW0YrWxf1S5ogOe/nqJ3q/PxTsqtL/i1ZYrMpRd8U8tuSDbyIGLVvr51nUq0LI
1amHc7NzNlEvpdCQoodkVGwS07h2R2mvro8As3C552c/jGo9eV+BJ6MOqqc9gUgQ
sRhsOC6PenvFPSHI+aB/FyuIT7ry7G0kjmzxClzZW7Gw/EnLStJYxiolsJeEw57/
NIwQRn8P+zxZeqYpDK6OUDryU4RALdWRewo3joJ3zmYvNHdcpUU7ABmnB9GS5ma5
O07pY/wzmBquewh9Ct96uqpZbYaCCmQr2lmnTE7vPb0EoksxAgMBAAGjggEzMIIB
LzAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYk
T3BlblNTTCBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBSz
nYHmFpJkxIaH9SkQG14vdPftsTCBmAYDVR0jBIGQMIGNgBQrQOXJffX0ljjpL+Mv
2UBkyY4Fm6FqpGgwZjELMAkGA1UEBhMCS0cxCzAJBgNVBAgTAk5BMRAwDgYDVQQH
EwdCSVNIS0VLMRUwEwYDVQQKEwxPcGVuVlBOLVRFU1QxITAfBgkqhkiG9w0BCQEW
Em1lQG15aG9zdC5teWRvbWFpboIJAKFO3vqQ8q6BMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAsGA1UdDwQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAgEATiWAG8uwQv+7P+gN
WMGA28/QkN/KweZB4Uh/px7HNZ+cbXw+gujefq6CFgAzDwIj8Z3+KwYWBVUWidxj
rF8aMRN5IaNuYCjo52tUACKht2laFzHOD8Km3aNv3uoZbNLSyzWd3YdRM2jNw5uQ
VfGAPVy4CbbhPBOkXUrOpRGe+QjuvuNUHQZMuxtyE+59oEXM/tE7AgPB1OpFLajJ
l+fzinqgL91IOnXJQiiU/K9EUhZomNatqGWxzaxgQXDlROha8uf8O/5FiRcdbYXG
8Pxph9EdB/PLe1SNqqPM48b81gV2NdAmY47RqLf/YUKKLGMf1OwUR2se44FhEjuM
FrXPh2otQiGDnA46kDoewTZhQfn7Tl3q9N8jkjMrmxSfoPXTxPgfL5wRNq8qImGV
MgvEHC2xwQoql8BDSmw+2wDNKRWefkF1NqhWhoyCnkYg5QYeYNIDX5+eabu/wrRD
4n2FF4MYQbDLqQQbGFKfiYt2n5RZgU9gWzMY/MdS0NJp/AuiYzJ1Q5np1/htx1Ux
DPPvGnHhClfhnROyHv4d7+TxUdmVs/0oKJORSinFNw6r2IVq/qiDH3uAXR8Eebep
CG4N1i6qfPZjfUHecBMyzt1YzKZz1HJ+16x0qDW6wxsqZNdaN5dWlDQrKnFgvGmr
AIW5T2cyF1HD2lc6N4lmxHpR2l8=
-----END CERTIFICATE-----
EOF107
 cat <<'EOF113'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCluKLuzrGmD2qy
n9MiF3neCZhxePqnzjZRVFfHMZlW0YrWxf1S5ogOe/nqJ3q/PxTsqtL/i1ZYrMpR
d8U8tuSDbyIGLVvr51nUq0LI1amHc7NzNlEvpdCQoodkVGwS07h2R2mvro8As3C5
52c/jGo9eV+BJ6MOqqc9gUgQsRhsOC6PenvFPSHI+aB/FyuIT7ry7G0kjmzxClzZ
W7Gw/EnLStJYxiolsJeEw57/NIwQRn8P+zxZeqYpDK6OUDryU4RALdWRewo3joJ3
zmYvNHdcpUU7ABmnB9GS5ma5O07pY/wzmBquewh9Ct96uqpZbYaCCmQr2lmnTE7v
Pb0EoksxAgMBAAECggEAPMOMin+jR75TYxeTNObiunVOPh0b2zeTVxLT9KfND7ZZ
cBK8pg79SEJRCnhbW5BnvbeNEkIm8PC6ZlDCM1bkRwUStq0fDUqQ95esLzOYq5/S
5qW98viblszhU/pYfja/Zi8dI1uf96PT63Zbt0NnGQ9N42+DLDeKhtTGdchZqiQA
LeSR0bQanY4tUUtCNYvBT8E3pzhoIsUzVwzIK53oovRpcOX3pMXVYZsmNhXdFFRy
YkjMXpj7fGyaAJK0QsC+PsgrKuhXDzDttsG2lI/mq9+7RXB3d/pzhmBVWynVH2lw
iQ7ONkSz7akDz/4I4WmxJep+FfQJYgK6rnLAlQqauQKBgQDammSAprnvDvNhSEp8
W+xt7jQnFqaENbGgP0/D/OZMXc4khgexqlKFmSnBCRDmQ6JvLTWqDXC4+aqAbFQz
zAIjiKaT+so8xvFRob+rBMJY5JLYKNa+zUUanfORUNYLFJPvFqnrWGaJ9uufdaM7
0a5bu95PN74NXee3DBbpBv8HLwKBgQDCEk+IjNbjMT+Neq0ywUeM5rFrUKi92abe
AgsVpjbighRV+6jA2lZFJcize+xYJ9wiOR1/TEI9PZ2OtBkqpwVdvTEHTagRLcvd
NfGcptREDnNLoNWA22buQpztiEduutACWQsrd+JQmqbUicUdW4zw86/oCMbYCW3V
QmYOLns7nwKBgHHUX20WZE91S4pmqFKlUzHTDdkk1ESX6Qx2q0R01j8BwawHFs6O
0DW9EZ7w55nfsh+OPRl1sjK/3ubMgfQO0TZLm+IGf3Sya0qEnVeiPMkpDMX+TgRA
wzEe+ou6uho+9uFSvdxMxeglaYA5M2ycvNwLsbEyZ4ZyVYxdgTiKahYFAoGAcIfP
iD0qKQiYcj/tB94cz+3AeJqHjbYT1O1YYhBECOkmQ4kuG80+cs/q5W/45lEOiuWV
Xgfo7Lu6jVGOujWoneci87oqtvNYH4e09oGh2WiLoBG9Wv9dWtBTUERSLzmxfXsG
SAk2uEhEbj8IhfJc8iZLHH9iVUh6YEslBBodqL8CgYEAlAhvcqAvw5SzsfBR5Mcu
4Nql6mXEVhHCvS4hdFCGaNF0z9A6eBORKJpdLWnqhpquDQDsghWE+Ga4QKSNFIi1
fnAaykmZuY3ToqNOIaVlYM6HpMEz0wHQbTWfDLGcTFcElLZgMAk7VlDyiYVOco+E
QX9lXOO1PGpLzXhlDxSe63Y=
-----END PRIVATE KEY-----
EOF113
 cat <<'EOF13'> /etc/openvpn/dh.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA2w2E4Ppnc89jXP4tBsMizxtRPmpwJkYoBpF9EVN5QO/ws96/x8Te
hAg2mD6ZzoPFm4KhjD9YrD+M3c05j2kCLMnPc81i+EQ6M+xG6hzbPl5D8upe3W3/
RoYadS85yIEJPs+SFToO3tXZlCklbU9+MVm8FaWohC32j4O3dNTDvKIQtSWjU0WC
m1OVQAgdv4TZtcF5/FSGFbbcGY1arrrX0JK4+0ThW9XktTL9LPCNM/0UqSAqSB89
LvFFlL47ek5JPMh76ulEBxWco2FHbnSsIWd12rYMGRn7G/EqbR1pQi+3UNMQpAIz
5JnupCKu4GFS6KU5q1WKg0q1IBvhNroRwwIBAg==
-----END DH PARAMETERS-----
EOF13
 cat <<'EOF103'> /etc/openvpn/crl.pem
-----BEGIN X509 CRL-----
MIIBsDCBmQIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhSYWR6IFZQThcN
MTkwODA4MDM1NDI1WhcNMjAwMjA0MDM1NDI1WqBSMFAwTgYDVR0jBEcwRYAUpZcJ
dK9kVRcXepwjPkZbQahd+YKhF6QVMBMxETAPBgNVBAMMCFJhZHogVlBOghQHkI1U
FC2+EYQoi9jXsAtjsYTrHzANBgkqhkiG9w0BAQsFAAOCAQEAauCvXzfFxGk1x1sz
UKTjrG4A1QG3nD/5V9Zd2N0uClXGwHUi7wn4BDT7ckGtdNyl37SQ+WK+C73lUbz8
u6Pj40k8/YOMD3IasInHYG74ZulVCg0KbXxCgi6TXl5/c1XT+sSSuO46XNpRWkV3
lRhj31D3Uh5jbrCJ6bCyWU+nv/DA1QsFXXo2BfcMU7a6XoJ6n/zrogwzrXvPpYkh
CuZEyGkEZO8Wd0KYGm7pT2nsFzmUqES2W5LLZkVtgYziKG7/5Lcw4u1OOd/R3Jqy
NDJboL0lnAK6QLMspx3OThLdusI2Kn/cEQiSdhC9RExBibS83N2Fti+3lom0rjdX
j+cNXw==
-----END X509 CRL-----
EOF103

 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/GakodArmy/teli/main/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip

systemctl start openvpn@server
#Create OpenVPN Config
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/client.ovpn <<-END
client
dev tun
setenv FRIENDLY_NAME "I'M MASTA GAKOD"
remote $MYIP 443 tcp
http-proxy $MYIP 8080
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
verb 3
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 100000
rcvbuf 100000
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
END
echo '<ca>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/ca.crt >> /home/vps/public_html/client.ovpn
echo '</ca>' >> /home/vps/public_html/client.ovpn
echo '<cert>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/client.crt >> /home/vps/public_html/client.ovpn
echo '</cert>' >> /home/vps/public_html/client.ovpn
echo '<key>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/client.key >> /home/vps/public_html/client.ovpn
echo '</key>' >> /home/vps/public_html/client.ovpn
echo '<tls-auth>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/tls-auth.key >> /home/vps/public_html/client.ovpn
echo '</tls-auth>' >> /home/vps/public_html/client.ovpn

cat > /home/vps/public_html/udp.ovpn <<-END
client
dev tun
proto udp
setenv FRIENDLY_NAME "I'M MASTA GAKOD"
remote $MYIP 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
verb 3
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 100000
rcvbuf 100000
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
END
echo '<ca>' >> /home/vps/public_html/udp.ovpn
cat /etc/openvpn/ca.crt >> /home/vps/public_html/udp.ovpn
echo '</ca>' >> /home/vps/public_html/udp.ovpn
echo '<cert>' >> /home/vps/public_html/udp.ovpn
cat /etc/openvpn/client.crt >> /home/vps/public_html/udp.ovpn
echo '</cert>' >> /home/vps/public_html/udp.ovpn
echo '<key>' >> /home/vps/public_html/udp.ovpn
cat /etc/openvpn/client.key >> /home/vps/public_html/udp.ovpn
echo '</key>' >> /home/vps/public_html/udp.ovpn
echo '<tls-auth>' >> /home/vps/public_html/udp.ovpn
cat /etc/openvpn/tls-auth.key >> /home/vps/public_html/udp.ovpn
echo '</tls-auth>' >> /home/vps/public_html/udp.ovpn


client = yes
debug = 6

[openvpn]
accept = 127.0.0.1:1147
connect = $MYIP:587
TIMEOUTclose = 0
verify = 0
sni = m.facebook.com
END

# Configure Stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj '/CN=127.0.0.1/O=localhost/C=PH' -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
cat > /etc/stunnel/stunnel.conf <<-END

sslVersion = all
pid = /stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
accept = 587
connect = 127.0.0.1:443
cert = /etc/stunnel/stunnel.pem

[dropbear]
accept = 44
connect = 127.0.0.1:442
cert = /etc/stunnel/stunnel.pem

END

#Setting UFW
ufw allow ssh
ufw allow 443/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

#Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source xxxxxxxxx
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.10.0/24 -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:fail2ban-ssh - [0:0]
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 442  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 587  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1147  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1147  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT 
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A fail2ban-ssh -j RETURN
COMMIT
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
END
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules


# Configure Nginx
sed -i 's/\/var\/www\/html;/\/home\/vps\/public_html\/;/g' /etc/nginx/sites-enabled/default
cp /var/www/html/index.nginx-debian.html /home/vps/public_html/index.html
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/index.html <<-END
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Hiratechi VPN</title>
        <meta name="description" content="Use Hiratechi VPN for free!" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!--Bootstrap 4-->
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/3.5.2/animate.min.css">
        <!--icons-->
        <link rel="stylesheet" href="https://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css" />
    </head>
    <body>
        <!--header-->
        <nav class="navbar navbar-expand-md navbar-dark fixed-top sticky-navigation">
            <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
                <span class="ion-grid icon-sm"></span>
            </button>
            <a class="navbar-brand hero-heading" href="#">Hiratechi VPN</a>
            <div class="collapse navbar-collapse" id="navbarCollapse">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#main">Home<span class="sr-only">(current)</span></a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#features">Features</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#configs">Configs</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#download">VPN App</a>
                    </li>
					<li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#team">Our Team</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#links">Links</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#contact">Contact</a>
                    </li>
                </ul>
            </div>
        </nav>

        <!--main section-->
        <section class="bg-texture hero" id="main">
            <div class="container">
                <div class="row d-md-flex brand">
                    <div class="col-md-6 hidden-sm-down wow fadeIn">
                        <img class="img-fluid mx-auto d-block" src="img/product.png"/>
                    </div>
                    <div class="col-md-6 col-sm-12 text-white wow fadeIn">
                        <h2 class="pt-4">Experience <b class="text-primary-light">Hiratechi VPN </b> for FREE</h2>
                        <p class="mt-5">
                            The best gets even better. With our swift and fastest low ping private server, you'll not being worried again with our vpn services.
                        </p>
                        <p class="mt-5">
                            <a href="#configs" class="btn btn-primary mr-2 mb-2 page-scroll">Try Now</a>
                            <a href="#download" class="btn btn-white mb-2 page-scroll">Download App</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!--features-->
        <section class="bg-light" id="features">
            <div class="container">
                <div class="row mb-3">
                    <div class="col-md-6 col-sm-8 mx-auto text-center wow fadeIn">
                        <h2 class="text-primary">Amazing Features of Hiratechi VPN</h2>
                        <p class="lead mt-4">
                            A plenty of awesome features to <br/>wow the users.
                        </p>
                    </div>
                </div>
                <div class="row mt-5 text-center">
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-game-controller-b-outline icon-md"></em>
                                </div>
                                <h6>Unlimited Gaming</h6>
                                <p>
                                    Low ping & Optimized server for your best unlimited gaming experience. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-android-wifi icon-md"></em>
                                </div>
                                <h6>Cloudflare DNS</h6>
                                <p>
                                    With the best DNS installed in our server to keep your connection at stable, streaming faster, download accelerated, & uploading boosted. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-settings icon-md"></em>
                                </div>
                                <h6>Advanced Configs</h6>
                                <p>
                                    All our SSH/OVPN/DROPBEAR/SSL are highly configurable to meet your VPN experience & satisfaction. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-cloud-upload-outline icon-md"></em>
                                </div>
                                <h6>Unlimited Bandwidth</h6>
                                <p>
                                    No capping and you can download/stream/browse all what you want without limitations. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-locked-outline icon-md"></em>
                                </div>
                                <h6>Highly Secure</h6>
                                <p>
                                    Our server is from best VPS Cloud service, with anti-torrent & anti-ddos installed for our servers go for a longer last. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-android-color-palette icon-md"></em>
                                </div>
                                <h6>More Features & Colors</h6>
                                <p>
                                    With more future plans coming to keep this server colored and beautiful. 
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-white p-0">
            <div class="container-fluid">
                <div class="row d-md-flex mt-5">
                    <div class="col-sm-6 p-0 wow fadeInLeft">
                        <img class="img-fluid" src="img/whyus.png" alt="Why we Choose us">
                    </div>
                    <div class="col-sm-6 pl-5 pr-5 pt-5 pb-4 wow fadeInRight">
                        <h3><a href="#"></a></h3>
                        <p class="lead pt-4">VPN (virtual private network) is a technology that could make internet access you comfortable with eliminating prevention in accessing all sites. Giving new anonymous identity, disguise your original location and encrypts all traffic, such things make all data access and secure internet. Internet service provider or network operator, even the government, will not be able to check or filter your activity on the web.</p>
						Why you choose Hiratechi VPN?
                        <ul class="pt-4 pb-3 list-default">
                            <li><font color="green"><b>FREE at all</b></font></li>
                            <li>Anonymous</li>
                            <li>Safe</li>
                            <li>Fast</li>
                            <li>Low Ping</li>
                            <li>Smooth</li>
                            <li>The best of the BEST!</li>
                        </ul>
                        <a href="#configs" class="btn btn-primary mr-2 page-scroll">Get Started with Hiratechi VPN</a>
                    </div>
                </div>
            </div>
        </section>

        <!--pricing-->
        <section class="bg-light" id="configs">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center">
                        <h2 class="text-primary">Configs</h2>
                        <p class="lead pt-3">
                            Our OpenVPN configs.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-4 text-center">
                    <div class="col-sm-4 mt-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN</h5>
                                <h3 class="card-title text-primary pt-4">TCP</h3>
                                <p class="card-text text-muted pb-3 border-bottom">Default Config</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>Port: 1153</li>
                                    <li>TCP Connection</li>
                                    <li>Stable</li>
                                    <li>Fast &amp; Smooth</li>
                                </ul>
                                <a href="/client.ovpn" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-0 wow fadeIn">
                        <div class="card pt-4 pb-4">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN</h5>
                                <h3 class="card-title text-primary pt-4"><sup></sup>SSL</h3>
                                <p class="card-text text-muted pb-3 border-bottom">Default config</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>Port: 443</li>
                                    <li>OpenVPN over SSL</li>
                                    <li>Stable</li>
                                    <li>Fast &amp; Smooth</li>
                                </ul>
                                <a href="/clientssl.ovpn" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN Package <small class="badge bg-primary small-xs">HOT</small></h5>
                                <h3 class="card-title text-primary pt-4"><sup></sup>Combo</h3>
                                <p class="card-text text-muted pb-3 border-bottom">zip packed</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>TCP &amp; SSL</li>
                                    <li>With stunnel.conf</li>
                                    <li>For modem used</li>
                                    <li>Zip packed</li>
                                </ul>
                                <a href="/openvpn.zip" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!--download-->
        <section class="bg-orange pt-0" id="download">
            <div class="container">
                <div class="row d-md-flex text-center wow fadeIn">
                    <div class="col-md-6 offset-md-3 col-sm-10 offset-sm-1 col-xs-12">
                        <h5 class="text-primary">Download Our Mobile App</h5>
                        <p class="mt-4">
                            Download our provided apps for free for your android phone & pc.
                            
                        <p class="mt-5">
                            RADZ VPN<br><a href="https://play.google.com/store/apps/details?id=www.radzvpn.ml" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
                            WENZ VPN<br><a href="https://play.google.com/store/apps/details?id=wenz.soft.dev.wenzvpn" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
                            Configs PH<br><a href="https://play.google.com/store/apps/details?id=fb.com.nicanor03" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
							<br>FOR PC<br><a href="https://www.phcorner.net/threads/685100/" target="_blank">Uni OVPN (&#169; JustPlaying)</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!--team-->
        <section class="bg-white" id="team">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 col-sm-8 mx-auto text-center">
                        <h2 class="text-primary">Our Team</h2>
                        <p class="lead pt-3">
                            Meet our awesome team.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-5 text-center">
                    <div class="team col-sm-3 mt-2 wow fadeInLeft">
                        <img src="img/team-1.gif" alt="Owner" class="img-team img-fluid rounded-circle"/>
                        <h5>Hiratechi</h5>
                        <p>Developer, Owner</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeIn">
                        <img src="img/team-2.jpg" alt="Team Epiphany" class="img-team img-fluid rounded-circle"/>
                        <h5>Team Epiphany</h5>
                        <p>Our Official Group Name</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeIn">
                        <img src="img/team-3.gif" alt="Team RADZVPN" class="img-team img-fluid rounded-circle"/>
                        <h5>RADZVPN TEAM</h5>
                        <p>Partner Team</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeInRight">
                        <img src="img/team-4.png" alt="Team Unstoppable" class="img-team img-fluid rounded-circle"/>
                        <h5>Team Unstoppable</h5>
                        <p>Partner Team</p>
                    </div>
                </div>
            </div>
        </section>

        <!--blog-->
        <section class="bg-light" id="links">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center">
                        <h2 class="text-primary">Links</h2>
                        <p class="lead pt-3">
                            Our recommended and partner sites.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-5">
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/pt.png" alt="PinoyThread">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em>&nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em>  &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://www.pinoythread.com" target="_blank">Join PinoyThread Forum!</a></h5>
                                <p class="card-text">Welcome to PinoyThread. Come and join discuss about the pinoy cyber world.<br>FREE VPNs<br>Giveaways<br>Droplets<br>more...</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://www.pinoythread.com" class="card-link" target="_blank"><strong>Join now</strong></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/radz.png" alt="RADZ VPN">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://radzvpn.ml/" target="_blank">Finally! RADZ VPN</a></h5>
                                <p class="card-text">New Web Design<br>
								Can create up to 50 accounts every server per day<br>
								3 VIP Fast Servers Available<br>
								Fast and Easy to create account<br>
								Customer Service Chat Box Plugins<br>
								You can able to check your account info</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://radzvpn.ml/" class="card-link"target="_blank"><strong>Visit now</strong></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/te.jpg" alt="Our Discord server">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em>&nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://discord.gg/EHq4XjH" target="_blank">The TEAM Epiphany</a></h5>
                                <p class="card-text"><b>TEAM Epiphany<b> is now live on Discord with...<br>
								VPN Scripts<br>
								Daily Giveaways<br>
								Friendly members<br>
								VPN Configs<br>
								Source Codes<br>
								Bins & VPS<br>
								A tons of richness of features<br>
								that you can't find here!</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://discord.gg/EHq4XjH" class="card-link" target="_blank"><strong>Connect to them</strong></a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!--contact-->
        <section class="bg-texture-collage p-0" id="contact">
            <div class="container">
                <div class="row d-md-flex text-white text-center wow fadeIn">
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-telephone-outline icon-md"></em></p>
                        <p class="lead"><a href="https://discord.gg/bC6bfwK" target="_blank"><font color="#0000EE">Discord</font></a></p>
                    </div>
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-email-outline icon-md"></em></p>
                        <p class="lead">hiratechi@team-epiphany.com</p>
                    </div>
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-location-outline icon-md"></em></p>
                        <p class="lead">Manila, PH</p>
                    </div>
                </div>
            </div>
        </section>

        <!--footer-->
        <section class="bg-footer" id="connect">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center wow fadeIn">
                        <h1>HIRATECHI VPN</h1>
			<br>
			<iframe src="https://discordapp.com/widget?id=499555022078607360&amp;theme=dark" width="350" height="500" allowtransparency="true" frameborder="0"></iframe>
			<br>
                        <p class="mt-4">
                            <a href="https://discord.gg/EHq4XjH" target="_blank"><img src="img/discord.png" alt="Our Discord server"/></a>   
                            <a href="https://www.facebook.com/RADZ-VPN-260317881583057" target="_blank"><img src="img/facebook.png" alt="Our Facebook"/></a>
                           
                        </p>
                        <p class="pt-2 text-muted">
                            &copy; 2019 <a href="http://www.phcorner.net/members/446411/" target="_blank">Hiratechi</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.3/umd/popper.min.js"></script>
        <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/js/bootstrap.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/wow/1.1.2/wow.js"></script>
        <script src="js/scripts.js"></script>
    </body>
</html>
END

# Unpack hiratechi homepage
cd /home/vps/public_html
wget "https://raw.githubusercontent.com/Hira20/VPSauto/master/hiratechihomepage.zip"
unzip hiratechihomepage.zip
rm hiratechihomepage.zip
cd


# Create and Configure rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e

exit 0
END
chmod +x /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local

# Configure menu
apt-get install unzip
cd /usr/local/bin/
wget "https://raw.githubusercontent.com/Gugun09/VPSauto/master/tool/premiummenu.zip" 
unzip premiummenu.zip
chmod +x /usr/local/bin/*

# add eth0 to vnstat
vnstat -u -i eth0

# compress configs
cd /home/vps/public_html
zip configs.zip client.ovpn udp.ovpn stunnel.conf

# install libxml-parser
apt-get install -y libxml-parser-perl

# finalizing
vnstat -u -i eth0
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
service nginx start
service php7.0-fpm start
service vnstat restart
service openvpn restart
service dropbear restart
service fail2ban restart
service squid restart

#clearing history
history -c
rm -rf /root/*
cd /root
# info
clear
echo " "
echo "Installation has been completed!!"
echo "DEVICE WILL REBOOT IN 10 SECONDS"
echo "PLEASE WAIT PATIENTLY AND RELOGIN TO YOUR VPS"
echo " "
echo "--------------------------- Configuration Setup Server -------------------------"
echo "                         Copyright HostingTermurah.net                          "
echo "                                Modified by wangzki                        "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Server Information"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Manila (GMT +8)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [OFF]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Application & Port Information"  | tee -a log-install.txt
echo "   - OpenVPN		: TCP 1147 "  | tee -a log-install.txt
echo "   - OpenVPN-Stunnel	: 587 "  | tee -a log-install.txt
echo "   - Dropbear		: 442"  | tee -a log-install.txt
echo "   - Stunnel	: 443"  | tee -a log-install.txt
echo "   - Squid Proxy	: 3128, 8080 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Nginx		: 80"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "   To display list of commands: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Download Config OpenVPN : http://$MYIP/configs.zip"  | tee -a log-install.txt
echo "   - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo ""
echo "------------------------------ Modified by Gugun -----------------------------"
echo "-----Rebooting your VPS -----"
sleep 5
reboot
