#!/bin/bash
# (C) Murty Rompalli
# Fix OpenSSH server to remove weak encryption algorithms
set -e
eval `grep ^ID= /etc/os-release`

# Our custom directives
case $ID in
  fedora)
CUSTOM='
HostKey /etc/ssh/ssh_host_ed25519_key
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
GSSAPIKexAlgorithms gss-curve25519-sha256-
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-256,rsa-sha2-512
' ;;
  debian)
# Debian 10 does not recognize GSSAPIKexAlgorithms and CASignatureAlgorithms directives
CUSTOM='
HostKey /etc/ssh/ssh_host_ed25519_key
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
' ;;
  centos)
# CentOS Stream 8 does not recognize CASignatureAlgorithms directive
CUSTOM='
HostKey /etc/ssh/ssh_host_ed25519_key
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
GSSAPIKexAlgorithms gss-curve25519-sha256-
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
' ;;
  *) echo Unsupported OS: $ID; exit;;
esac

# Disable automatic generation of rsa and ecdsa keys
systemctl mask sshd-keygen@rsa.service
systemctl mask sshd-keygen@ecdsa.service
[ -f /usr/lib/systemd/system/sshd-keygen.target ] &&
sed -i '/sshd-keygen@rsa.service/d;/sshd-keygen@ecdsa.service/d' /usr/lib/systemd/system/sshd-keygen.target
[ -f /usr/lib/systemd/system/sshd-keygen.service ] &&
sed -i '/ssh_host_rsa_key/d;/ssh_host_ecdsa_key/d' /usr/lib/systemd/system/sshd-keygen.service
systemctl daemon-reload

# Backup rsa, dsa, ecdsa host keys and generate ED25519 key if it doesn't exist already
for i in /etc/ssh/ssh_host_rsa* /etc/ssh/ssh_host_dsa* /etc/ssh/ssh_host_ecdsa*
do
  [ -f "$i" ] && mv "$i" "$i"~
done

if ! [ -s /etc/ssh/ssh_host_ed25519_key -a -s /etc/ssh/ssh_host_ed25519_key.pub ]
then
  for i in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub
  do
    [ -f $i ] && mv $i $i~
  done
  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
fi

[ -s /etc/ssh/ssh_host_ed25519_key -a -s /etc/ssh/ssh_host_ed25519_key.pub ] || exit
chown root:root /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
chmod 600 /etc/ssh/ssh_host_ed25519_key
if grep -q ^ssh_keys: /etc/group
then
    chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key
    chmod 640 /etc/ssh/ssh_host_ed25519_key
fi

# Remove small Diffie-Hellman moduli
[ ! -s /etc/ssh/moduli ] && echo Empty moduli && exit
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
[ ! -s /etc/ssh/moduli.safe ] && echo Empty moduli.safe && exit
\mv -bf /etc/ssh/moduli.safe /etc/ssh/moduli

# Define sshd config file
CONFIGFILE=/etc/ssh/sshd_config

# Comment out directives that we plan to overwrite
[ ! -s $CONFIGFILE ] && echo $CONFIGFILE is empty && exit
sed -i~ 's/^\s*\(HostKey\s\|Ciphers\|KexAlgo\|MACs\|HostKeyAlgo\|GSSAPIKexAlgo\|CASignatureAlgo\|PubkeyAcceptedKeyTypes\)/#\1/I' $CONFIGFILE

# Append our custom directives
if [ -d /etc/ssh/sshd_config.d ]
then
  CONFIGFILE1=/etc/ssh/sshd_config.d/01-custom.conf
  [ -f $CONFIGFILE1 ] && mv $CONFIGFILE1 $CONFIGFILE1~
  echo "$CUSTOM" > $CONFIGFILE1
  chown root:root $CONFIGFILE1*
  chmod 600 $CONFIGFILE1*
else
  echo "$CUSTOM" >> $CONFIGFILE

  # Edit /etc/sysconfig/sshd if necessary (i.e. only for old CentOS and Fedora)
  if [ -f /etc/sysconfig/sshd ]
  then
    sed -i~ 's/^\s*#\s*CRYPTO_POLICY\s*=\s*$/CRYPTO_POLICY=/' /etc/sysconfig/sshd
  fi
fi

# Check for errors
sshd -t
echo
echo If no errors printed above, run:
echo systemctl restart sshd
echo -n rm
for i in $CONFIGFILE~ $CONFIGFILE1~ /etc/ssh/moduli~ /etc/ssh/ssh_host_*~ /etc/sysconfig/sshd~
do
  [ -f "$i" ] && echo -n " $i"
done
echo
