#!/bin/bash

adduser $1 
usermod -a -G sftp-users $1
chown root:root /home/$1
chmod 755 /home/$1
mkdir /home/$1/uploads
chown $1:$1 /home/$1/uploads
chmod 755 /home/$1/uploads



groupadd sftp-users

echo "Match Group sftp-group
ForceCommand internal-sftp
PasswordAuthentication yes
ChrootDirectory /home/%u
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no" > /etc/ssh/sshd_config.d/sftp-users.conf

systemctl restart ssh




### USERDATA DEFINITIVO PER SERVER SFTP CON UTENTI CON DIRECTORY DEDICATA (HRTOOLS)

#!/bin/bash

groupadd sftp-users

echo "Match Group sftp-users
ForceCommand internal-sftp
PasswordAuthentication yes
ChrootDirectory /sftp/%u
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no" > /etc/ssh/sshd_config.d/sftp-users.conf

systemctl restart ssh

mkdir /home/ubuntu/scripts
chown ubuntu:ubuntu /home/ubuntu/scripts
chmod 755 /home/ubuntu/scripts

echo '#!/bin/bash
adduser $1 --no-create-home
mkdir -p /sftp/$1
usermod -a -G sftp-users $1
mkdir -p /sftp/$1/uploads
chown $1:$1 /sftp/$1/uploads
chmod 755 /sftp/$1/uploads' > /home/ubuntu/scripts/create-sftp-user

chmod +x /home/ubuntu/scripts/create-sftp-user
chown ubuntu:ubuntu /home/ubuntu/scripts/create-sftp-user



### USERDATA PER UN USER SFTP (ERACLITO)

# create user with no login shell, no home (remember to create password manually)
useradd -s /usr/sbin/nologin -M sftp-user

# create mountpoint for EFS
mkdir -p /sftp/wordpress

# edit sshd config 
echo "Match User sftp-user
ForceCommand internal-sftp
PasswordAuthentication yes
ChrootDirectory /sftp
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no" > /etc/ssh/sshd_config.d/sftp-user.conf

echo "Match User websupport
ForceCommand internal-sftp
PasswordAuthentication yes
ChrootDirectory /sftp
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no" > /etc/ssh/sshd_config.d/websupport.conf
systemctl restart ssh 

fs-0c866a9dca3c276c9 /sftp/wordpress efs _netdev,tls,accesspoint=fsap-0e6d75e3c8bcfdd85 0 0




