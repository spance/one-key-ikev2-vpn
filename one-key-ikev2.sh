#!/bin/bash
#===============================================================================================
#   Description:  Install IKEV2 VPN for CentOS and Ubuntu
#   Author: quericy
#   Intro:  https://quericy.me/blog/699
#===============================================================================================

# first vpn user
vpn_user="user1"
vpn_pass=`head -c 6 /dev/urandom | base64 | head -c 6`
my_psk=`head -c 6 /dev/urandom | base64 | head -c 6`

target_strongswan="strongswan-5.4.0"


function printline() {
	echo "#############################################################"
}

# Install IKEV2
function install_ikev2(){
	rootness
	disable_selinux
	determine_os
	install_packages
	pre_install
	download_file
	build_strongswan
	generate_keys
	configure_ipsec
	configure_strongswan
	configure_secrets
	prompt_snat
	set_iptables
	success_info
}

# Make sure only root can run our script
function rootness(){
	if [[ $EUID -ne 0 ]]; then
	   echo "Error:This script must be run as root!" 1>&2
	   exit 1
	fi
}

# Disable selinux
function disable_selinux(){
	if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
		setenforce 0
	fi
}

# Ubuntu or CentOS
function determine_os(){
	get_os_dist=`cat /etc/issue`
	echo "$get_os_dist" |grep -q "CentOS"
	if  [ $? -eq 0 ]; then
		os_dist="0"
	fi
	echo "$get_os_dist" |grep -qP "(Ubuntu|Debian)"
	if [ $? -eq 0 ]; then
		os_dist="1"
	fi
	# error
	if [[ -z "$os_dist" ]]; then
		echo "This Script must be running at the CentOS or Ubuntu!"
		exit 1
	fi
}

#install necessary lib
function install_packages(){
	if [ "$os_dist" = "0" ]; then
		yum -y update
		yum -y install pam-devel openssl-devel make gcc curl
	else
		ii=`dpkg -l libpam0g-dev libssl-dev make gcc curl | grep "^ii" | wc -l`
		if [[ "$ii" == "5" ]]; then
			return 0
		fi
		apt-get -y update
		apt-get -y install libpam0g-dev libssl-dev make gcc curl
	fi
}

# Pre-installation settings
function pre_install(){
	echo -n "Please input the public ip (or domain) of your server"
	while true; do
		read -p "? " my_ip
		if [ -n "$my_ip" ]; then
			break
		fi
	done
	echo -n "Please input the cert country "
	read -p "C=(default: USA): " my_cert_c
	if [[ -z "$my_cert_c" ]]; then
		my_cert_c="USA"
	fi
	echo -n "Please input the cert organization "
	read -p "O=(default: White House): " my_cert_o
	if [[ -z "$my_cert_o" ]]; then
		my_cert_o="White House"
	fi
	echo -n "Please input the cert common name "
	read -p "CN=(default: Meetings): " my_cert_cn
	if [[ -z "$my_cert_cn" ]]; then
		my_cert_cn="Meetings"
	fi
	
	printline
	echo "Please confirm the information:"
	echo -e "the ip(or domain) of your server: [\033[32;1m$my_ip\033[0m]"
	echo -e "the cert_info:[\033[32;1mC=${my_cert_c}, O=${my_cert_o}\033[0m]"
	echo ""
	echo -n "Press Enter to start?"
	read -p ""
	#Current folder
	cur_dir=`pwd`
}


# Download strongswan
function download_file(){
	if [[ -f "$target_strongswan.tar.bz2" ]];then
		echo -e "$target_strongswan.tar.bz2 [\033[32;1mfound\033[0m]"
	else
		if ! wget --no-check-certificate https://download.strongswan.org/$target_strongswan.tar.bz2; then
			echo "Failed to download $target_strongswan.tar.bz2"
			exit 1
		fi
	fi
	# strongswan dir existed
	if [[ -d $target_strongswan ]]; then
		pushd $target_strongswan > /dev/null
		return 0
	fi
	tar xf $target_strongswan.tar.bz2
	if [[ $? -eq 0 ]];then
		pushd $target_strongswan > /dev/null
	else
		echo "uncompress failed!"
		exit 1
	fi
}

# configure and install strongswan
function build_strongswan(){
	echo "building strongswan ..."
	# configure and make
	if [[ ! -e "Makefile" ]]; then
		./configure  --enable-eap-identity --enable-eap-md5 \
	--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
	--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
	--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
	--enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp >& build0.log
		make >& build1.log
	fi
	make install >& build2.log
	if [[ $? -ne 0 ]]; then
		echo "failed to install"
		exit 1
	fi
	popd > /dev/null
}

# configure cert and key
function generate_keys(){
	if [ -f ca.pem ]; then
		echo -e "ca.pem [\033[32;1mfound\033[0m]"
	else
		echo -e "ca.pem [\033[32;1mauto create\033[0m]"
		echo "auto create ca.pem ..."
		ipsec pki --gen --type ecdsa --size 256 --outform pem > ca.pem
	fi
	
	if [ -f ca.cert.pem ];then
		echo -e "ca.cert.pem [\033[32;1mfound\033[0m]"
	else
		echo -e "ca.cert.pem [\033[33;1mauto create\033[0m]"
		echo "auto create ca.cert.pem ..."
		ipsec pki --self --in ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn}" --ca --outform pem >ca.cert.pem
	fi
	if [ ! -d my_key ];then
		mkdir my_key
	fi
	cp ca.pem my_key/ca.pem
	cp ca.cert.pem my_key/ca.cert.pem
	pushd my_key > /dev/null
	
	# server
	ipsec pki --gen --outform pem > server.pem	
	# sign server cert
	ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_ip}" --san="${my_ip}" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
	# client
	ipsec pki --gen --outform pem > client.pem	
	# sign client cert
	ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn} Client" --outform pem > client.cert.pem
	echo "set password to client p12 key:"
	openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "${my_cert_cn}"  -out client.cert.p12
	
	printline
	echo -n "Press Enter to install VPN cert?"
	read -p ""
	cp -f ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
	cp -f server.cert.pem /usr/local/etc/ipsec.d/certs/
	cp -f server.pem /usr/local/etc/ipsec.d/private/
	cp -f client.cert.pem /usr/local/etc/ipsec.d/certs/
	cp -f client.pem  /usr/local/etc/ipsec.d/private/
	popd > /dev/null
}

# generate the ipsec.conf
# must use space as indent symbol
function configure_ipsec(){
	cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=never 

conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    auto=add

conn ios_ikev2
    keyexchange=ikev2
    ike=aes256-sha2_256-ecp256, aes256-sha2_256-modp2048!
    esp=aes256-sha1, aes128-sha1!
    rekey=no
    left=%defaultroute
    leftid=${my_ip}
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add

EOF
}

# configure the strongswan.conf
function configure_strongswan(){
	cat > /usr/local/etc/strongswan.conf<<-EOF
charon {
    load_modular = yes
    duplicheck.enable = no
    compress = yes
    plugins {
            include strongswan.d/charon/*.conf
    }
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
    nbns1 = 8.8.8.8
    nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF
}

# configure the ipsec.secrets
function configure_secrets(){
	cat > /usr/local/etc/ipsec.secrets<<-EOF
: RSA server.pem
: PSK "$my_psk"
: XAUTH "myXAUTHPass"
$vpn_user %any : EAP "$vpn_pass"
EOF
}

function prompt_snat(){
	echo "Use SNAT could implove the speed,but your server MUST have static ip address."
	read -p "yes or no?(default:no):" use_SNAT
	if [ "$use_SNAT" = "yes" ]; then
		use_SNAT_str="1"
		read -p "static ip(default:${IP}):" static_ip
		if [ "$static_ip" = "" ]; then
			static_ip=$IP
		fi
	else
		use_SNAT_str="0"
	fi
}

# iptables set
function set_iptables(){
	sysctl -w net.ipv4.ip_forward=1
	echo "Please enter the name of the interface which can be connected to the public network."

	read -p "Network interface(default:eth0):" interface
	if [ "$interface" = "" ]; then
		interface="eth0"
	fi

	if [ "$use_SNAT_str" = "1" ]; then
		iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
		iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
		iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j SNAT --to-source $static_ip
	else
		iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j MASQUERADE
	fi
}

# echo the success info
function success_info(){
	printline
	echo -e "[\033[32;1mInstall Complete\033[0m]"
	echo -e "There is the default login info of your VPN"
	echo -e "UserName:\033[33;1m $vpn_user \033[0m"
	echo -e "PassWord:\033[33;1m $vpn_pass \033[0m"
	echo -e "PSK:\033[33;1m $my_psk \033[0m"
	echo -e "Users database in \033[32;1m /usr/local/etc/ipsec.secrets\033[0m"
	echo -e "Should import the cert \033[32;1m ./my_key/ca.cert.pem \033[0m to the client."
	echo "And may need save iptables rules manually."
	printline
	ipsec start
}


printline
echo "# Install IKEV2 VPN for Linux"
echo "# Intro: https://quericy.me/blog/699"
echo "#"
echo "# Author:quericy"
echo "#"
printline
# Initializing setup
install_ikev2
