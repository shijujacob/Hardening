#!/bin/bash
# Deployer for Ubuntu Server 18.04 LTS
#Credits to Center for Internet Security CIS
##############################################################################################################

f_banner(){
echo
echo "
For Ubuntu Server 18.04 LTS"
echo
echo

}

##############################################################################################################

# Check if running with root User

clear
f_banner

check_root() {
if [ "$USER" != "root" ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
else
      clear
      f_banner
      my_home=$(pwd)
      cat templates/texts/welcome
fi
}

##############################################################################################################

# Install spinner tool
spinner_install_system(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Installing the Spinner"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt install spinner -y
   say_done
}

##############################################################################################################



# Installing Dependencies
# Needed Prerequesites will be set up here
install_dep(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Setting some Prerequisites"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   add-apt-repository universe
   say_done
}

##############################################################################################################

# Configure Hostname
config_host() {
    #Creating Legal Banner for unauthorized Access
    echo ""
    echo "Creating legal Banners for unauthorized access"
    spinner
    cat templates/motd > /etc/motd
    cat templates/motd > /etc/issue
    cat templates/motd > /etc/issue.net
    sed -i s/server.com/$host_name.$domain_name/g /etc/motd /etc/issue /etc/issue.net
    echo "OK "
    say_done
}

##############################################################################################################

# Configure TimeZone
config_timezone(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m We will now Configure the TimeZone"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
   say_done
}

##############################################################################################################

# Update System, Install sysv-rc-conf tool
update_system(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Updating the System"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt update -y
   apt upgrade -y
   apt dist-upgrade -y
   say_done
}

##############################################################################################################

# Setting a more restrictive UMASK
restrictive_umask(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Setting UMASK to a more Restrictive Value (027)"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   cp templates/login.defs /etc/login.defs
   echo ""
   echo "OK"
   say_done
}

#############################################################################################################

#Disabling Unused Filesystems

unused_filesystems(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Unused FileSystems"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done
}

##############################################################################################################

uncommon_netprotocols(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Uncommon Network Protocols"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done

}

##############################################################################################################



# Set IPTABLES Rules
set_iptables(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Setting IPTABLE RULES"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Setting Iptables Rules..."
    spinner
    sh templates/iptables.sh
    cp templates/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
    say_done
}


##############################################################################################################

# Tune and Secure Kernel
tune_secure_kernel(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Tuning and Securing the Linux Kernel"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Securing Linux Kernel"
    spinner
    echo "* hard core 0" >> /etc/security/limits.conf
    cp templates/sysctl.conf /etc/sysctl.conf; echo " OK"
    cp templates/ufw /etc/default/ufw
    sysctl -e -p
    say_done
}


##############################################################################################################

# Additional Hardening Steps
additional_hardening(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Running additional Hardening Steps"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Running Additional Hardening Steps...."
    spinner
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #Remove AT and Restrict Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " Securing Cron "
    spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
       echo "Disabling USB Support"
       spinner
       echo "blacklist usb-storage" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u
       echo "OK"
       say_done
}


##############################################################################################################



# Disable Compilers
disable_compilers(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Disabling Compilers"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Disabling Compilers....."
    spinner
    chmod 000 /usr/bin/as >/dev/null 2>&1
    chmod 000 /usr/bin/byacc >/dev/null 2>&1
    chmod 000 /usr/bin/yacc >/dev/null 2>&1
    chmod 000 /usr/bin/bcc >/dev/null 2>&1
    chmod 000 /usr/bin/kgcc >/dev/null 2>&1
    chmod 000 /usr/bin/cc >/dev/null 2>&1
    chmod 000 /usr/bin/gcc >/dev/null 2>&1
    chmod 000 /usr/bin/*c++ >/dev/null 2>&1
    chmod 000 /usr/bin/*g++ >/dev/null 2>&1
    spinner
    echo ""
    echo " If you wish to use them, just change the Permissions"
    echo " Example: chmod 755 /usr/bin/gcc "
    echo " OK"
    say_done
}

##############################################################################################################

# Enable Process Accounting
enable_proc_acct(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Enable Process Accounting"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install acct -y
  touch /var/log/wtmp
  echo "OK"
}

##############################################################################################################

#Install and enable auditd

install_auditd(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing auditd"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install auditd -y

  # Using CIS Benchmark configuration
  
  #Ensure auditing for processes that start prior to auditd is enabled 
  echo ""
  echo "Enabling auditing for processes that start prior to auditd"
  spinner
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub

  echo ""
  echo "Configuring Auditd Rules"
  spinner

  cp templates/audit-CIS.rules /etc/audit/rules.d/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/rules.d/audit.rules

  echo " " >> /etc/audit/rules.d/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/rules.d/audit.rules
  echo "-e 2" >>/etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
  echo "OK"
  say_done
}
##############################################################################################################

#Install and Enable sysstat

install_sysstat(){
  clear
  f_banner
 echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing and enabling sysstat"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install sysstat -y
  sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
  service sysstat start
  echo "OK"
 say_done
}
##############################################################################################################

set_grubpassword(){
  clear
 f_banner
 echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m GRUB Bootloader Password"
 echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "It is recommended to set a password on GRUB bootloader to prevent altering boot configuration (e.g. boot in single user mode without password)"
  echo ""
   grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
   grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
    echo " set superusers="root" " >> /etc/grub.d/40_custom
    echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
    rm grubpassword.tmp
    update-grub
    echo "On every boot enter root user and the password you just set"
echo -e ""
echo -e "Securing Boot Settings"
spinner
sleep 2
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
say_done
}    

##############################################################################################################

file_permissions(){
 clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Setting File Permissions on Critical System Files"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  sleep 2
  chmod -R g-wx,o-rwx /var/log/*

  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config

  chown root:root /etc/passwd
  chmod 644 /etc/passwd

  chown root:shadow /etc/shadow
  chmod o-rwx,g-wx /etc/shadow

  chown root:root /etc/group
  chmod 644 /etc/group

  chown root:shadow /etc/gshadow
  chmod o-rwx,g-rw /etc/gshadow

  chown root:root /etc/passwd-
  chmod 600 /etc/passwd-

  chown root:root /etc/shadow-
  chmod 600 /etc/shadow-

  chown root:root /etc/group-
  chmod 600 /etc/group-

  chown root:root /etc/gshadow-
  chmod 600 /etc/gshadow-


  echo -e ""
  echo -e "Setting Sticky bit on all world-writable directories"
  sleep 2
  spinner

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

  echo " OK"
  say_done

}
##############################################################################################################

CIS(){
 clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m CIS Benchmark Hardening"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  sleep 2

#1.1.1.1 Ensure Mounting of cramfs is disabled (Scored)

echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)

echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)

echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)

echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)

echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)

echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)

echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)

echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf


  echo " OK"
  say_done

}

#########################################################################################





# Reboot Server
reboot_server(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Final Step"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    read -p "Do that? [y,n]" doit
     case $doit in
    y|Y) reboot ;;
    n|N) echo No rebooted;;
   *) echo dont know ;;
  esac
}

#################################################################################################################
clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m SELECT THE DESIRED OPTION"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. Update System & Security & Permission"
echo "2. CIS Benchmark Hardening"
echo "3. Reboot"
echo "4. Exit"
echo

read choice
case $choice in
1)
check_root
spinner_install_system
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
set_iptables
tune_secure_kernel
additional_hardening
disable_compilers
check_root
enable_proc_acct
install_auditd
install_sysstat
set_grubpassword
file_permissions
CIS
;;


2)
#chmod +x myscript-CIS.sh
#./myscript-CIS.sh
;;

3)
reboot_server
;;

4)
exit 0
;;

esac

#####################################################################################################
