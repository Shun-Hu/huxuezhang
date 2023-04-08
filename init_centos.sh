#!/bin/bash
# CentOS System Optimization Script
#公众号：胡学长的小站 www.52pojiee.com
# Version: ChatGpt

#更新系统和软件包
## Update and Upgrade System
yum update -y
yum upgrade -y

# Set Timezone
#timedatectl set-timezone Asia/Shanghai

# Set Locale
localectl set-locale LANG=en_US.utf8

#禁用未使用的服务
# Disable Unnecessary Services
systemctl disable postfix
systemctl disable avahi-daemon

# Disable SELinux
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

# Enable Automatic Updates
yum install -y yum-cron
sed -i 's/update_messages = no/update_messages = yes/g' /etc/yum/yum-cron.conf
systemctl enable yum-cron
systemctl start yum-cron

# Install Basic Packages
yum install -y vim wget curl unzip

## System Optimization Configurations
# Increase File Descriptors
echo "* soft nofile 65535" >> /etc/security/limits.conf
echo "* hard nofile 65535" >> /etc/security/limits.conf

# Increase TCP Connection Limit
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p

# Enable TCP Fast Open
echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf

# Optimize TCP Congestion Control
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sysctl -p

# Increase Inode Cache
echo "vm.vfs_cache_pressure = 500" >> /etc/sysctl.conf
sysctl -p

# Disable Transparent Hugepages
echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/rc.local
echo "echo never > /sys/kernel/mm/transparent_hugepage/defrag" >> /etc/rc.local
chmod +x /etc/rc.d/rc.local
systemctl start rc-local.service

# Enable Kernel Samepage Merging (KSM)
echo "echo 1 > /sys/kernel/mm/ksm/run" >> /etc/rc.local
systemctl start ksmtuned.service

# Enable Swapiness
echo "vm.swappiness = 10" >> /etc/sysctl.conf
sysctl -p

# Enable journald Rate Limiting
sed -i 's/#RateLimitIntervalSec=30s/RateLimitIntervalSec=2s/g' /etc/systemd/journald.conf
sed -i 's/#RateLimitBurst=1000/RateLimitBurst=3000/g' /etc/systemd/journald.conf
systemctl restart systemd-journald

# Set SSH Session Timeout
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
systemctl restart sshd

# Disable INT/IOR randomization
echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf
sysctl -p

# Set max file handles
echo "* soft nofile 262144" >> /etc/security/limits.conf
echo "* hard nofile 262144" >> /etc/security/limits.conf

# Set max user processes
echo "* soft nproc 65535" >> /etc/security/limits.conf
echo "* hard nproc 65535" >> /etc/security/limits.conf

# Enable DNS cache
echo "options timeout:2 attempts:3 rotate single-request-reopen" >> /etc/resolv.conf
systemctl restart NetworkManager

# Network kernel optimization
cat >> /etc/sysctl.conf << EOF
net.core.netdev_max_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_recycle = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10
EOF
sysctl -p

# Disable timer
echo "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" >> /etc/rc.local
chmod +x /etc/rc.local

# Allow multiple session SSH
sed -i 's/#MaxSessions\s*10/MaxSessions 100/g' /etc/ssh/sshd_config
systemctl restart sshd

# Set user umask
echo "umask 027" >> /etc/profile

# Optimize TCP settings
cat >> /etc/sysctl.conf << EOF
# Accepting a TCP SYN packet
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
# Connection tracking
net.ipv4.netfilter.ip_conntrack_max = 131072
# Security
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_orphans = 262144
EOF
sysctl -p

# Optimize hard drive performance
cat >> /etc/fstab << EOF
# Tune filesystem options to improve performance
tmpfs /tmp tmpfs defaults,noatime,nodiratime,mode=1777,size=800M 0 0
tmpfs /var/tmp tmpfs defaults,noatime,nodiratime,mode=1777,size=100M 0 0
tmpfs /var/log tmpfs defaults,noatime,nodiratime,mode=0755,size=100M 0 0
EOF
mount -a

# Optimize memory settings
cat >> /etc/sysctl.conf << EOF
# Reclaimable memory which is used for caching and buffering
vm.vfs_cache_pressure = 50
vm.swappiness = 10
EOF
sysctl -p

# Disable SELinux
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

# Optimize log settings
cat >> /etc/rsyslog.conf << EOF
# Disable logging for non-critical messages
*.emerg :omusrmsg:
mail.* -/var/log/mail
mail.info -/var/log/mail.info
mail.warning -/var/log/mail.warn
mail.err /var/log/mail.err
authpriv.* /var/log/secure
cron.* /var/log/cron
*.info;mail.none;authpriv.none;cron.none /var/log/messages
EOF
systemctl restart rsyslog

# Add more secure cipher suites and disable insecure cipher suites
cat >> /etc/ssh/sshd_config << EOF
# Disable weak encryption algorithms
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
EOF
systemctl restart sshd

# Improve networking performance
cat >> /etc/sysctl.conf << EOF
# Increase the amount of memory available for network buffers
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF
sysctl -p

# Configure iptables rules to prevent DDoS attacks
iptables -A FORWARD -p tcp --syn -m limit --limit 10/second -j ACCEPT
iptables -A FORWARD -p udp -m limit --limit 10/second -j ACCEPT
iptables -A FORWARD -f -m limit --limit 100/s -j ACCEPT
iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p udp -m limit --limit 5/s -j ACCEPT
iptables -A INPUT -f -m limit --limit 50/s -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# Optimize DNS resolution
cat >> /etc/sysctl.conf << EOF
# Add Google DNS resolvers
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
EOF
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Optimize system performance
echo "*/10 * * * * root /usr/bin/fstrim -v /" >> /etc/crontab
echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/rc.local
chmod +x /etc/rc.local

reboot
