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
 apt update && apt upgrade -y
 apt-get install openvpn -y
 cd /etc/openvpn/
 wget -O openvpn.tar "https://raw.githubusercontent.com/sumailranger93/sumail/main/openvpn.tar"
 tar xf openvpn.tar;rm openvpn.tar
 wget -O /etc/rc.local "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/rc.local"
 chmod +x /etc/rc.local
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
verify-client-cert none
username-as-common-name
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# LODIxyrussScript

port MyOvpnPort2
dev tun
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
dev tun
remote $IPADDR $OpenVPN_Port1 tcp
http-proxy $IPADDR 8080
http-proxy-retry
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
echo '<ca>' >> /etc/openvpn/GTMConfig.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/GTMConfig.ovpn
echo '</ca>' >> /etc/openvpn/GTMConfig.ovpn

cat <<EOF16> /var/www/openvpn/SunConfig.ovpn
# Credits to GakodX
client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port2
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
EOF16

cat <<EOF17> /var/www/openvpn/SunNoLoad.ovpn
client
proto tcp-client
dev tun
remote 127.0.0.1 443
route $IPADDR 255.255.255.255 net_gateway 
http-proxy $IPADDR 8080
http-proxy-retry
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
EOF17

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
