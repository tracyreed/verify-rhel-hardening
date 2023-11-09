#!/bin/bash
#
# RedHat 5 Linux Hardening Checklist Verification Program
# 
#
# Tracy Reed
# 2012-01-23
#
# md5 sums, comparison strings, etc. baselined off of server1.
# Corrected for tabs instead of spaces, extra spaces, etc.
#
VERSION="1.0 2012-01-31"

tmp="/tmp/verify"
mkdir -p $tmp

archivedir=$tmp/`date +%y-%m-%d-%T`
mkdir $archivedir

echo "Preserving copies of system files in $archivedir and script output in $archivedir/results"

exec > $archivedir/results

echo -n "Host: "
hostname
echo -n "Date: "
date
echo "Version: $VERSION"


truststores=`find /app/instances -name truststore`
instances=`find /app/instances -maxdepth 1 -mindepth 1`

function check() {
    expect="$1"
    result="$2"

    if [ "$expect" == "$result" ];
    then
    	echo "OK"
    else
    	echo "FAIL"
    	diffit "$expect" "$result"
    fi
}

function diffit() {
    echo "$1" > $tmp/expect
    echo "$2" > $tmp/result
    diff -u $tmp/expect $tmp/result
}

function normalize_spaces() {
    egrep -v '^#|^$' $1 | sed -e 's/  */ /g'  -e 's/\t/ /g'
}

function minimize_packages() {
    echo -n "4.1 Verify correct packages installed: "
    result=`rpm -qa | sort -f`
    echo `hostname -s` | egrep "^bosded" > /dev/null
    if [ $? -eq 0 ];
    then
        check "$apprpmlist" "$result"
    else 
        check "$dbrpmlist" "$result"
    fi

}

function patch_repositories() {
    echo -n "4.2 Verify Patch Repositories: "
    result=`yum repolist | awk '{print $1}'`
    expect="Loaded
repo
our-rhel
repolist:"
    check "$expect" "$result"
}

function gpgcheck() {
    echo -n "4.2 Verify gpgcheck enabled: "
    result=`grep gpgcheck /etc/yum.conf`
    expect="gpgcheck=1"
    check "$expect" "$result"
}

function yum_check_update() {
    echo -n "4.3 Patch server to current: "
    yum check-update > $archivedir/pending-patches
    if [ $? -ne 0 ];
    then
    	echo "FAIL updates are pending"
    else
        echo "OK"
    fi    
}

function review_logs() {
    echo -n "4.4 Review system logs: "
    egrep -i "(crit|alert|error|warn)" /var/log/* > $archivedir/log-errors
    if [ $? -ne 1 ];
    then
	echo "Possible errors in logs found. MANUAL REVIEW of logs required"
    fi
}

function ssh_key_length() {
    echo -n "4.5 Verify ssh host key length: "
    result=`/usr/bin/ssh-keygen -l -v -f /etc/ssh/ssh_host_key.pub | \
	awk '{print $1}'`
    expect="2048"
    check "$expect" "$result"
}

function ssh_config() {
    echo -n "4.5.1 Verify ssh server config: "
    result=`md5sum /etc/ssh/sshd_config`
    expect="d3696c60609d0987d78c75ddf7e36b7e  /etc/ssh/sshd_config"
    cp /etc/ssh/sshd_config $archivedir
    check "$expect" "$result"
}
    
function disable_jnjrunbook() {
    echo -n "4.5.2 Disable jnjrunbook login from specific IPs: "
    result=`md5sum /etc/security/access.conf`
    expect="740a52ef00298eafa06b0396615d7b57  /etc/security/access.conf"
    cp /etc/security/access.conf $archivedir
    check "$expect" "$result"
}
function pam_sshd_access() {
    echo -n "4.5.2 Modify pam sshd config to use access: "
    result=`md5sum /etc/pam.d/sshd`
    expect="41624739e22766590053b702e027fbcc  /etc/pam.d/sshd"
    cp /etc/pam.d/sshd $archivedir
    check "$expect" "$result"
}

function enable_accounting() {
    echo -n "4.6 Enable system accounting: "
    result=`crontab -l | grep \/sa`
    expect='*/5 * * * * /usr/lib/sa/sa1 -S DISK -S POWER -S XDISK 1 1
53 23 * * * /usr/lib/sa/sa2 -A'
    check "$expect" "$result"
}

function ntp_config() {
    echo -n "4.7 Correct NTP settings: "
    result=`md5sum /etc/ntp.conf`
    expect="c9a1522a0e7433e3d59d4d5d483d6199  /etc/ntp.conf"
    cp /etc/ntp.conf $archivedir
    check "$expect" "$result"
}

function mcafee_schedule() {
    echo -n "4.8 McAfee scheduled items: "
    result=`echo "select * from schedule;" | /opt/NAI/LinuxShield/libexec/sqlite /var/opt/NAI/LinuxShield/etc/nailsd.db|wc -l`
    expect="2"
    check "$expect" "$result"
}

function mcafee_crontab() {
    echo -n "4.8 McAfee in /etc/crontab: "
    result=`md5sum /etc/crontab`
    expect="8e0fedc3893c768cdde298798d031efd  /etc/crontab"
    cp /etc/crontab $archivedir
    check "$expect" "$result"
}

function mcafee_installed() {
    echo -n "4.8 McAfee installed: "
    result=`rpm -qa | sort | grep MFE`
    expect="MFEcma-4.5.0-1470
MFErt-2.0-0"
    check "$expect" "$result"
}

function mcafee_running() {
    echo -n "4.8 McAfee running: "
    result=`/sbin/service nails status | grep "is running"`
    expect="the McAfeeVSEForLinux daemon is running: process information follows
the McAfeeVSEForLinux monitor gateway is running: process information follows
the McAfeeVSEForLinux Apache server is running: "
    check "$expect" "$result"
}

function remove_webmin() {
    echo -n "4.9 Remove webmin: "
    result=`rpm -qva | grep webmin`
    expect=""
    check "$expect" "$result"
}

function truststore_exists() {
    echo -n "4.10 Verify existence of truststore: "
    # This makes sure there exists a truststore for each instance by
    # making sure the instance directory count and trust store counts
    # are the same.
    result=`find /app/instances/ -mindepth 1 -maxdepth 1 -type d |wc -l`
    expect=`find /app/instances/ -mindepth 1 -maxdepth 2 -type f -name truststore| wc -l`
    check "$expect" "$result"
}

function mysql_ssl() {
    echo "4.10 MySQL SSL: "
    export PATH=$PATH:/app/java32_1.6.0_12/bin
    for store in $truststores; do
        instance=`echo $store | cut -d/ -f4`
        result=`echo | keytool -list -v -keystore $store 2>/dev/null > $archivedir/$instance.keystore`
        echo "Verify CN is correct for DB server instance $instance: "
        grep "Owner: CN=" $archivedir/$instance.keystore
    done        
}

function app_server_ssl() {
    echo -n "4.10 App server SSL configuration: "
    fail=0
    for instance in `find /app/instances/ -name app.properties | grep -v localhost`; do
        result=`egrep "^app.db.url=jdbc:mysql://.+:3306/\?useSSL=true&requireSSL=true&requireVerifyCertificate=true" $instance`
        if [ ! $? -eq 0 ];
        then
            echo "FAIL: app.db.url misconfigured in $instance app.properties"
            fail=1
        fi

        result=`egrep "^app.db.user=.+" $instance`
        if [ ! $? -eq 0 ];
        then
            echo "FAIL: app.db.user misconfigured in $instance app.properties"
            fail=1
        fi

        result=`egrep "^app.db.password=.+" $instance`
        if [ ! $? -eq 0 ];
        then
            fail=1
            echo "FAIL: app.db.password misconfigured in $instance app.properties"
        fi

    done
    if [ $fail -eq 0 ];
    then
        echo "OK"
    fi
}

function remove_tomcat_user() {
    echo -n "4.11 Remove unused Tomcat user: "
    fail=0
    for instance in $instances; do
        grep 'username="admin"' $instance/conf/tomcat-users.xml
        if [ $? -eq 0 ];
        then
            echo "FAIL: Found tomcat admin user in $instance/conf/tomcat-users.xml"
            fail=1
        fi
    done
    if [ $fail -eq 0 ];
    then
        echo "OK"
    fi
}

function minimize_services() {
    echo -n "5 Minimize network services: "
    result=`/sbin/chkconfig --list | egrep "autofs|avahi-daemon|cups|haldaemon|kudzu|pcscd|rpcgssd|rpcidmapd|nscd" | grep on`
    expect=""
    check "$expect" "$result"
}

function config_firewall_appserver() {
    echo -n "5.2 Iptables rule sets: "
    result=`/sbin/iptables --list -n | wc -l`
    expect="94"
    /sbin/iptables --list > $archivedir/iptables-output
    check "$expect" "$result"
}

function disable_zeroconf() {
    echo -n "6.1 Disable zeroconf: "
    result=`/sbin/route | grep 169.254`
    expect=""
    check "$expect" "$result"
}

function disable_ipv6() {
    echo -n "6.1.1 Disable IPv6: "
    result=`grep IPV6 /etc/sysconfig/network`
    expect="NETWORKING_IPV6=no"
    check "$expect" "$result"
}

function kernel_net_params() {
    echo -n "6.2 Kernel network parameters: "
    result=`normalize_spaces /etc/sysctl.conf|md5sum`
    expect="e835688681725fabf1547a11a6d989e4  -"
    cp /etc/sysctl.conf $archivedir
    check "$expect" "$result"
}

function logging() {
    echo -n "7.1 Test logging config: "
    logger -p auth.info "This is a test"
    grep "This is a test" /var/log/messages > /dev/null
    if [ $? -eq 0 ];
    then
	echo "OK: Manually verify 'This is a test' appeared in Splunk index."
    else
	echo "FAIL"
    fi
}    

function syslog() {
    echo -n "7.2 Syslog config: "
    result=`normalize_spaces /etc/syslog.conf | md5sum`
    expect="7d8a5f62434f8ee4534dea28e1225a35  -"
    cp /etc/syslog.conf $archivedir
    check "$expect" "$result"
}

function logfile_perms() {
    echo -n "7.3 Permissions on system log files: "
    result=`ls -la /var/log/messages \
                   /var/log/secure   \
                   /var/log/maillog  \
                   /var/log/cron     \
                   /var/log/boot.log | awk '{print $1}'`
    expect="-rw-------
-rw-------
-rw-------
-rw-------
-rw-------"
    check "$expect" "$result"
}

function nodev_partitions() {
    echo -n "8.1 nodev on appropriate partitions: "
    result=`grep nodev /etc/fstab | wc -l; wc -l /etc/fstab`
    expect="3
10 /etc/fstab"
    check "$expect" "$result"
}

function nosuid_nodev_fstab() {
    echo -n "8.2 Add nosuid and nodev for removable media to fstab: "
    result=`normalize_spaces /etc/fstab | egrep "(nosuid|nodev)"`
    expect="/dev/das_vg/app_lv /app ext3 defaults,noatime,nodev 1 2
LABEL=/boot /boot ext3 defaults,noatime,nodev 1 2
/dev/das_vg/tmp_lv /tmp ext3 rw,nosuid,nodev,noexec 0 0"
    check "$expect" "$result"
}

function nosuid_nodev_hal() {
    echo -n "8.2 Ensure nosuid and nodev are not in hal rule files: "
    result=`md5sum /usr/share/hal/fdi/policy/10osvendor/20-storage-methods.fdi`
    expect="49078ebc56246b4157533663667be668  /usr/share/hal/fdi/policy/10osvendor/20-storage-methods.fdi"
    cp /usr/share/hal/fdi/policy/10osvendor/20-storage-methods.fdi $archivedir
    check "$expect" "$result"
}

function user_removable_fs() {
    echo -n "8.3 Disable user-mountable removable file systems: "
    result=`md5sum /etc/security/console.perms /etc/security/console.perms.d/50-default.perms`
    expect="12bc98ec0f0e6d22876bcb318642ed53  /etc/security/console.perms
4309dbe35b95af9e9282d894e59d09d6  /etc/security/console.perms.d/50-default.perms"
    cp /etc/security/console.perms $archivedir
    cp /etc/security/console.perms.d/50-default.perms $archivedir
    check "$expect" "$result"
}

function check_shadow_perms() {
    echo -n "8.4 Verify passwd, shadow, group file permissions: "
    result=`ls -la /etc/group /etc/gshadow /etc/passwd /etc/shadow | awk '{print $1 $3 $4}'`
    expect="-rw-r--r--rootroot
-r--------rootroot
-rw-r--r--rootroot
-r--------rootroot"
    check "$expect" "$result"
}

function world_write_sticky() {
    echo -n "8.5 Ensure world-writeable dirs have sticky bit: "
    result=`find / -xdev -type d \( -perm -002 -a ! -perm -1000 \) -print`
    expect=""
    check "$expect" "$result"
}

function unauth_world_write() {
    echo -n "8.6 Find unauthorized world-writeable files: "
    result=`find / -mount -type f -perm -o+w -ls`
    expect=""
    check "$expect" "$result"
}

function unauth_suid_sgid() {
    echo -n "8.7 Find unauthorized suid/sgid executables: "

    if [ ! -x suidverify ];
    then
	wget --quiet http://install.mydomain.com/app/distribution/etc/suidverify 2>&1 > /dev/null
    fi
    results=`sh suidverify > $archivedir/sugid-files.txt`
    grep "These are not in the list of approved files" $archivedir/sugid-files.txt > /dev/null
    if [ $? -eq 0 ];
    then
	echo "FAIL: Unapproved SUID/SGID files...list in $archivedir/sugid-files.txt"
    else
	echo "OK"
    fi
}

function unowned() {
    echo -n "8.8 Find all unowned directories and files: "
    find / -nogroup -exec ls -la {} \; 2>/dev/null > $archivedir/unowned-files
    find / -nouser  -exec ls -la {} \; 2>/dev/null >> $archivedir/unowned-files
    count=`wc -l $archivedir/unowned-files | awk '{print $1}'`
    if [ $count -eq 0 ];
    then
	echo "OK"
    else
	echo "FAIL: $count unowned files, list in $archivedir/unowned-files"
    fi
}    

function disable_usb() {
    echo -n "8.9 Disable USB storage devices: "
    result=`grep usb-storage /etc/modprobe.d/blacklist.conf`
    expect="blacklist usb-storage"
    check "$expect" "$result"
}

function instance_config_perms() {
    echo -n "8.10 Instance configuration file permissions: "
    result=`find /app/instances -name "app.properties" -perm /o+r,o+w,o+x`
    expect=""
    check "$expect" "$result"
}

function instance_config_ownership() {
    echo -n "8.10 Instance configuration file ownership: "
    result=`find /app/instances -name "app.properties" ! -user mydomain`
    expect=""
    check "$expect" "$result"
}

function rhost_pam() {
    echo -n "9.1 Remove .rhosts support in PAM: "
    result=`grep -ri "rhosts_auth" /etc/pam.d/*`
    expect=""
    check "$expect" "$result"
}

function restrict_at_cron() {
    echo -n "9.2 Restrict at/cron to authorized users: "
    result=`cat /etc/cron.allow /etc/at.allow`
    expect="root
root"
    check "$expect" "$result"
}

function restrict_crontab_perms() {
    echo -n "9.3 Restrict permissions on crontab files: "
    result=`ls -la /etc/crontab | awk '{print $1 $3 $4}'`
    expect="-r--------rootroot"
    check "$expect" "$result"
}

function block_system_accounts() {
    echo -n "10.1 Block login of system accounts: "
    for name in `cut -d: -f1 /etc/passwd`; do
        failed=0
        uid=`id -u $name`
        if [ $uid -lt 500 -a $name != 'root' ]; then
            shell=`grep ":$uid:" /etc/passwd | grep $name | cut -d: -f7`
            if [ ! $shell = "/sbin/nologin" ]; then
                echo "FAIL: $uid shell is $shell"
                failed=1
            fi
        fi
    done
    if [ ! $failed -eq 1 ]; then
        echo "OK"
    fi
}

function ldap_conf() {
    echo -n "10.2 Enable LDAP authentication: "
    result1=`normalize_spaces /etc/ldap.conf|md5sum`
    expect1="7ed5b799562f65f8a4e13b37a82572cd  -"
    result2=`normalize_spaces /etc/pam.d/system-auth-ac|md5sum`
    expect2="150244da3fcf726bb6db069a393a950a  -"
    cp /etc/ldap.conf /etc/pam.d/system-auth-ac $archivedir
    check "$expect1" "$result1"
    check "$expect2" "$result2"
}

function no_home() {
    echo -n "10.3 Unmount LDAP user's home directory: "
    result=`mount | grep '\/home\/users'`
    expect=""
    check "$expect" "$result"
}

function failed_logins() {
    echo -n "10.4 Failed login attempts: "
    result=`normalize_spaces /etc/pam.d/system-auth | grep pam_tally`
    expect="auth required pam_tally.so deny=5 onerr=fail unlock_time=900"
    check "$expect" "$result"
}

function password_length() {
    echo -n "10.4 Password strength and expiration: "
    result=`grep pam_cracklib /etc/pam.d/system-auth`
    expect="password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=8 minclass=2"
    check "$expect" "$result"
}

function password_expiration() {
    echo -n "10.4 Password expiration: "
    result=`grep PASS /etc/login.defs`
    expect="#	PASS_MAX_DAYS	Maximum number of days a password may be used.
#	PASS_MIN_DAYS	Minimum number of days allowed between password changes.
#	PASS_MIN_LEN	Minimum acceptable password length.
#	PASS_WARN_AGE	Number of days warning given before a password expires.
PASS_MAX_DAYS	90
PASS_MIN_DAYS	1
PASS_MIN_LEN	8
PASS_WARN_AGE	14"
    check "$expect" "$result"
}

function password_reuse() {
    echo -n "10.4 Password reuse: "
    result=`grep "account.*pam_unix" /etc/pam.d/system-auth`
    expect="account     required      pam_unix.so broken_shadow remember=5"
    check "$expect" "$result"
}

function password_hashes() {
    echo -n "10.5 Strong password hashes: "
    result=`authconfig --test | grep hashing`
    expect=" password hashing algorithm is sha512"
    check "$expect" "$result"
}

function no_runbook_user() {
    echo -n "10.6 No runbook user: "
    result=`id runbook 2>&1`
    expect="id: runbook: No such user"
    check "$expect" "$result"
}

function jnjrunbook_user() {
    echo -n "10.6 jnjrunbook user: "
    result=`id jnjrunbook 2>&1`
    expect="uid=31112(jnjrunbook) gid=31112(jnjrunbook) groups=31112(jnjrunbook) context=user_u:system_r:unconfined_t:s0"
    check "$expect" "$result"
}

function no_operations_user() {
    echo -n "10.6 No operations user: "
    result=`id operations 2>&1`
    expect="id: operations: No such user"
    check "$expect" "$result"
}

function jnjoperations_user() {
    echo -n "10.6 jnjoperations user: "
    result=`id jnjoperations 2>&1`
    expect="uid=31100(jnjoperations) gid=31100(jnjoperations) groups=31100(jnjoperations) context=user_u:system_r:unconfined_t:s0"
    check "$expect" "$result"
}

function sudoers_config() {
    echo -n "10.6 Verify sudoers config: "
    result=`egrep "runbook|operations" /etc/sudoers`
    expect="jnjoperations	ALL=(ALL)	ALL
jnjrunbook		ALL=(ALL)	ALL"
    check "$expect" "$result"
}

function warning_banner() {
    echo -n "11 Warning banner: "
    result=`egrep -v '^#|^$' /etc/issue | sed -e 's/  */ /g'  -e 's/\t/ /g' | md5sum`
    expect="819875022b24ffa07767e0758449e0d3  -"
    cp /etc/issue $archivedir
    check "$expect" "$result"
}

apprpmlist="acl-2.2.39-6.el5
acpid-1.0.4-9.el5_4.2
alsa-lib-1.0.17-1.el5
amtu-1.0.6-2.el5
anacron-2.3-45.el5
aspell-0.60.3-7.1
aspell-0.60.3-7.1
aspell-en-6.0-2.1
at-3.1.8-84.el5
atk-1.12.2-1.fc6
atk-1.12.2-1.fc6
attr-2.4.32-1.1
audit-1.7.18-2.el5
audit-libs-1.7.18-2.el5
audit-libs-1.7.18-2.el5
audit-libs-python-1.7.18-2.el5
authconfig-5.3.21-7.el5
autofs-5.0.1-0.rc2.156.el5_7.4
avahi-0.6.16-10.el5_6
avahi-compat-libdns_sd-0.6.16-10.el5_6
basesystem-8.0-5.1.1
bash-3.2-32.el5
bc-1.06-21
beecrypt-4.1.2-10.1.1
bind-libs-9.3.6-16.P1.el5_7.1
bind-utils-9.3.6-16.P1.el5_7.1
binutils-2.17.50.0.6-14.el5
bitmap-fonts-0.3-5.1.1
bitstream-vera-fonts-1.10-7
bluez-libs-3.7-1.1
bridge-utils-1.1-3.el5
bzip2-1.0.3-6.el5_5
bzip2-libs-1.0.3-6.el5_5
ccid-1.3.8-1.el5
celt051-0.5.1.3-0.el5
checkpolicy-1.33.1-6.el5
chkconfig-1.3.30.2-2.el5
compat-libstdc++-33-3.2.3-61
compat-libstdc++-33-3.2.3-61
conman-0.1.9.2-8.el5
coolkey-1.1.0-15.el5
coolkey-1.1.0-15.el5
coreutils-5.97-34.el5
cpio-2.6-23.el5_4.1
cpuspeed-1.2.1-10.el5
cracklib-2.8.9-3.3
cracklib-2.8.9-3.3
cracklib-dicts-2.8.9-3.3
crash-4.1.2-8.el5
crontabs-1.10-8
cryptsetup-luks-1.0.3-8.el5
cryptsetup-luks-1.0.3-8.el5
curl-7.15.5-9.el5_7.4
curl-7.15.5-9.el5_7.4
cyrus-sasl-2.1.22-5.el5_4.3
cyrus-sasl-lib-2.1.22-5.el5_4.3
cyrus-sasl-lib-2.1.22-5.el5_4.3
cyrus-sasl-md5-2.1.22-5.el5_4.3
cyrus-sasl-plain-2.1.22-5.el5_4.3
cyrus-sasl-plain-2.1.22-5.el5_4.3
db4-4.3.29-10.el5_5.2
db4-4.3.29-10.el5_5.2
dbus-1.1.2-16.el5_7
dbus-glib-0.73-10.el5_5
dbus-libs-1.1.2-16.el5_7
dbus-python-0.70-9.el5_4
device-mapper-1.02.63-4.el5
device-mapper-1.02.63-4.el5
device-mapper-event-1.02.63-4.el5
device-mapper-multipath-0.4.7-46.el5_7.2
dhcdbd-2.2-2.el5
dhclient-3.0.5-29.el5_7.1
dhcpv6-client-1.0.10-20.el5
diffutils-2.8.1-15.2.3.el5
dmidecode-2.11-1.el5
dmraid-1.0.0.rc13-65.el5
dmraid-events-1.0.0.rc13-65.el5
dos2unix-3.1-27.2.el5
dosfstools-2.11-9.el5
dump-0.4b41-5.el5
e2fsprogs-1.39-33.el5
e2fsprogs-libs-1.39-33.el5
e2fsprogs-libs-1.39-33.el5
e4fsprogs-libs-1.41.12-2.el5
ebtables-2.0.9-5.el5
ed-0.2-39.el5_2
eject-2.1.5-4.2.el5
elfutils-libelf-0.137-3.el5
elinks-0.11.1-6.el5_4.1
ethtool-6-4.el5
expat-1.95.8-8.3.el5_5.3
expat-1.95.8-8.3.el5_5.3
fbset-2.1-22
file-4.17-15.el5_3.1
filesystem-2.4.0-3.el5
findutils-4.2.27-6.el5
fipscheck-1.2.0-1.el5
fipscheck-lib-1.2.0-1.el5
freetype-2.2.1-28.el5_7.2
freetype-2.2.1-28.el5_7.2
gamin-0.1.7-8.el5
gamin-python-0.1.7-8.el5
gawk-3.1.5-14.el5
gdbm-1.8.0-26.2.1.el5_6.1
gettext-0.17-1.el5
glib2-2.12.3-4.el5_3.1
glib2-2.12.3-4.el5_3.1
glibc-2.5-65.el5_7.1
glibc-2.5-65.el5_7.1
glibc-common-2.5-65.el5_7.1
gnupg-1.4.5-14.el5_5.1
gnutls-1.4.1-3.el5_4.8
gnutls-1.4.1-3.el5_4.8
gpg-pubkey-37017186-45761324
gpm-1.20.1-74.1
grep-2.5.1-55.el5
groff-1.18.1.1-11.1
grub-0.97-13.5
gzip-1.3.5-13.el5
hal-0.5.8.1-62.el5
hdparm-6.6-2
hesiod-3.1.0-8
hicolor-icon-theme-0.9-2.1
hmaccalc-0.9.6-3.el5
hwdata-0.213.24-1.el5
ifd-egate-0.05-15
info-4.8-14.el5
initscripts-8.45.38-2.el5
iproute-2.6.18-11.el5
iptables-1.3.5-5.3.el5_4.1
iptables-ipv6-1.3.5-5.3.el5_4.1
iptstate-1.4-2.el5
iputils-20020927-46.el5
irqbalance-0.55-15.el5
iscsi-initiator-utils-6.2.0.872-10.el5
jwhois-3.2.3-12.el5
kbd-1.12-21.el5
kernel-2.6.18-164.11.1.el5
kernel-2.6.18-274.12.1.el5
kernel-2.6.18-274.el5
keyutils-1.2-1.el5
keyutils-libs-1.2-1.el5
keyutils-libs-1.2-1.el5
kpartx-0.4.7-46.el5_7.2
krb5-libs-1.6.1-62.el5
krb5-libs-1.6.1-62.el5
krb5-workstation-1.6.1-62.el5
ksh-20100202-1.el5_6.6
less-436-7.el5
libacl-2.2.39-6.el5
libaio-0.3.106-5
libaio-0.3.106-5
libattr-2.4.32-1.1
libcap-1.10-26
libdaemon-0.10-5.el5
libdrm-2.0.2-1.1
libdrm-2.0.2-1.1
libevent-1.4.13-1
libgcc-4.1.2-51.el5
libgcc-4.1.2-51.el5
libgcrypt-1.4.4-5.el5
libgcrypt-1.4.4-5.el5
libgomp-4.4.4-13.el5
libgpg-error-1.4-2
libgpg-error-1.4-2
libgssapi-0.10-2
libhugetlbfs-1.3-8.2.el5
libhugetlbfs-1.3-8.2.el5
libICE-1.0.1-2.1
libICE-1.0.1-2.1
libIDL-0.8.7-1.fc6
libidn-0.6.5-1.1
libidn-0.6.5-1.1
libjpeg-6b-37
libjpeg-6b-37
libnl-1.0-0.10.pre5.5
libogg-1.1.3-3.el5
libpcap-0.9.4-15.el5
libpng-1.2.10-7.1.el5_7.5
libpng-1.2.10-7.1.el5_7.5
libselinux-1.33.4-5.7.el5
libselinux-1.33.4-5.7.el5
libselinux-python-1.33.4-5.7.el5
libselinux-utils-1.33.4-5.7.el5
libsemanage-1.9.1-4.4.el5
libsepol-1.15.2-3.el5
libsepol-1.15.2-3.el5
libSM-1.0.1-3.1
libSM-1.0.1-3.1
libstdc++-4.1.2-51.el5
libstdc++-4.1.2-51.el5
libsysfs-2.1.0-1.el5
libtermcap-2.0.8-46.1
libtermcap-2.0.8-46.1
libtiff-3.8.2-7.el5_6.7
libtiff-3.8.2-7.el5_6.7
libusb-0.1.12-5.1
libuser-0.54.7-2.1.el5_5.2
libutempter-1.1.4-4.el5
libutempter-1.1.4-4.el5
libvolume_id-095-14.27.el5_7.1
libXau-1.0.1-3.1
libXau-1.0.1-3.1
libXdmcp-1.0.1-2.1
libXdmcp-1.0.1-2.1
libxml2-2.6.26-2.1.12.el5_7.1
libxml2-2.6.26-2.1.12.el5_7.1
libxml2-python-2.6.26-2.1.12.el5_7.1
lm_sensors-2.10.7-9.el5
log4cpp-1.0-9.el5
logrotate-3.7.4-12
logwatch-7.3-9.el5_6
lsof-4.78-3
lvm2-2.02.84-6.el5_7.1
m2crypto-0.16-8.el5
m4-1.4.5-3.el5.1
mailcap-2.1.23-1.fc6
mailx-8.1.1-44.2.2
make-3.81-3.el5
MAKEDEV-3.23-1.2
man-1.6d-2.el5
man-pages-2.39-17.el5
McAfeeVSEForLinux-1.6.0-28488
mcelog-0.9pre-1.32.el5
mcstrans-0.2.11-3.el5
MFEcma-4.5.0-1470
MFErt-2.0-0
mgetty-1.1.33-9.fc6
microcode_ctl-1.17-1.52.el5
mingetty-1.07-5.2.2
mkinitrd-5.1.19.6-71.el5_7.1
mkinitrd-5.1.19.6-71.el5_7.1
mktemp-1.5-23.2.2
mlocate-0.15-1.el5.2
module-init-tools-3.3-0.pre3.1.60.el5_5.1
mozldap-6.0.5-1.el5
mtools-3.9.10-2.fc6
mtr-0.71-3.1
nano-1.3.12-1.1
nash-5.1.19.6-71.el5_7.1
ncurses-5.5-24.20060715
ncurses-5.5-24.20060715
neon-0.25.5-10.el5_4.1
net-snmp-5.3.2.2-14.el5_7.1
net-snmp-libs-5.3.2.2-14.el5_7.1
net-tools-1.60-81.el5
newt-0.52.2-15.el5
nfs-utils-1.0.9-54.el5
nfs-utils-lib-1.0.8-7.6.el5
nscd-2.5-65.el5_7.1
nspr-4.8.8-1.el5_7
nspr-4.8.8-1.el5_7
nss-3.12.10-7.el5_7
nss-3.12.10-7.el5_7
nss_db-2.2-35.4.el5_5
nss_db-2.2-35.4.el5_5
nss_ldap-253-42.el5_7.4
nss_ldap-253-42.el5_7.4
nss-tools-3.12.10-7.el5_7
ntp-4.2.2p1-15.el5_7.1
ntsysv-1.3.30.2-2.el5
numactl-0.9.8-12.el5_6
numactl-0.9.8-12.el5_6
OpenIPMI-2.0.16-11.el5_7.2
OpenIPMI-libs-2.0.16-11.el5_7.2
openldap-2.3.43-12.el5_7.10
openldap-2.3.43-12.el5_7.10
openssh-4.3p2-72.el5_7.5
openssh-clients-4.3p2-72.el5_7.5
openssh-server-4.3p2-72.el5_7.5
openssl-0.9.8e-20.el5
openssl-0.9.8e-20.el5
ORBit2-2.14.3-5.el5
pam-0.99.6.2-6.el5_5.2
pam-0.99.6.2-6.el5_5.2
pam_ccreds-3-5
pam_ccreds-3-5
pam_krb5-2.2.14-21.el5
pam_krb5-2.2.14-21.el5
pam_passwdqc-1.0.2-1.2.2
pam_passwdqc-1.0.2-1.2.2
pam_pkcs11-0.5.3-23
pam_pkcs11-0.5.3-23
pam_smb-1.1.7-7.2.1
pam_smb-1.1.7-7.2.1
parted-1.8.1-28.el5
parted-1.8.1-28.el5
passwd-0.73-2
patch-2.5.4-31.el5
pax-3.4-2.el5
pciutils-3.1.7-3.el5
pcmciautils-014-5
pcre-6.6-6.el5_6.1
pcsc-lite-1.4.4-4.el5_5
pcsc-lite-libs-1.4.4-4.el5_5
perl-5.8.8-32.el5_7.6
perl-AppConfig-1.52-4
perl-rrdtool-1.2.23-1.el5.rf
perl-String-CRC32-1.4-2.fc6
pkinit-nss-0.7.6-1.el5
pm-utils-0.99.3-10.el5
policycoreutils-1.33.12-14.8.el5
popt-1.10.2.3-22.el5_7.2
portmap-4.0-65.2.2.1
prelink-0.4.0-2.el5
procmail-3.22-17.1
procps-3.2.7-17.el5
psacct-6.3.2-44.el5
psmisc-22.2-7.el5_6.2
pygobject2-2.12.1-5.el5
pyOpenSSL-0.6-2.el5
python-2.4.3-44.el5_7.1
python-dmidecode-3.10.13-1.el5_5.1
python-elementtree-1.2.6-5
python-iniparse-0.2.3-4.el5
python-libs-2.4.3-44.el5_7.1
python-numeric-23.7-2.2.2.el5_6.1
python-sqlite-1.1.7-1.2.1
python-urlgrabber-3.1.0-6.el5
qffmpeg-libs-0.4.9-0.16.20080908.el5_5
qpixman-0.13.3-4.el5
quota-3.13-5.el5
readahead-1.3-8.el5
readline-5.1-3.el5
readline-5.1-3.el5
redhat-logos-4.9.16-1
redhat-release-5Server-5.7.0.3
redhat-release-notes-5Server-41
rhel-instnum-1.0.9-1.el5
rhn-check-0.4.20-56.el5
rhn-client-tools-0.4.20-56.el5
rhnlib-2.5.22-6.el5
rhnsd-4.7.0-10.el5
rhn-setup-0.4.20-56.el5
rhpl-0.194.1-1
rmt-0.4b41-5.el5
rng-utils-2.0-4.el5
rootfiles-8.1-1.1.1
rpm-4.4.2.3-22.el5_7.2
rpm-libs-4.4.2.3-22.el5_7.2
rpm-python-4.4.2.3-22.el5_7.2
rrdtool-1.2.23-1.el5.rf
rsync-3.0.6-4.el5_7.1
screen-4.0.3-4.el5
secpwgen-1.3-2.el5.rf
sed-4.1.5-8.el5
selinux-policy-2.4.6-316.el5
selinux-policy-targeted-2.4.6-316.el5
setarch-2.0-1.1
setools-3.0-3.el5
setserial-2.17-19.2.2
setup-2.5.58-7.el5
setuptool-1.19.2-1
sgpio-1.2.0_10-2.el5
shadow-utils-4.0.17-18.el5_6.1
slang-2.0.6-4.el5
slrn-0.9.8.1pl1-1.2.2
smartmontools-5.38-2.el5
sos-1.7-9.54.el5_7.1
specspo-13-1.el5
sqlite-3.3.6-5
srvadmin-cm-6.1.0-648
srvadmin-deng-6.1.0-648
srvadmin-hapi-6.1.0-648
srvadmin-idracadm-6.1.0-648
srvadmin-idrac-components-6.1.0-648
srvadmin-idracdrsc-6.1.0-648
srvadmin-isvc-6.1.0-648
srvadmin-iws-6.1.0-648
srvadmin-jre-6.1.0-648
srvadmin-omacore-6.1.0-648
srvadmin-omauth-6.1.0-648.rhel5
srvadmin-omcommon-6.1.0-648
srvadmin-omhip-6.1.0-648
srvadmin-omilcore-6.1.0-648
srvadmin-storage-6.1.0-648
srvadmin-syscheck-6.1.0-648
srvadmin-wsmanclient-6.1.0-648.rhel5
strace-4.5.18-5.el5_5.5
stunnel-4.15-2.el5.1
sudo-1.7.2p1-10.el5
svrcore-4.0.4-3.el5
svrcore-4.0.4-3.el5
symlinks-1.2-24.2.2
sysfsutils-2.1.0-1.el5
sysklogd-1.4.1-46.el5
syslinux-3.11-4
sysstat-9.0.4-1
system-config-securitylevel-tui-1.6.29.1-6.el5
systemconfigurator-2.2.11-1
SysVinit-2.86-17.el5
tar-1.15.1-30.el5
tcl-8.4.13-4.el5
tcpdump-3.9.4-15.el5
tcp_wrappers-7.6-40.7.el5
tcp_wrappers-7.6-40.7.el5
tcsh-6.14-17.el5_5.2
telnet-0.17-39.el5
termcap-5.5-1.20060701.1
time-1.7-27.2.2
tmpwatch-2.9.7-1.1.el5.5
traceroute-2.0.1-6.el5
tree-1.5.0-4
tzdata-2011l-4.el5
udev-095-14.27.el5_7.1
udftools-1.0.0b3-0.1.el5
unix2dos-2.2-26.2.3.el5
unzip-5.52-3.el5
usermode-1.88-3.el5.2
util-linux-2.13-0.56.el5
vconfig-1.9-3
vim-common-7.0.109-7.el5
vim-enhanced-7.0.109-7.el5
vim-minimal-7.0.109-7.el5
vixie-cron-4.1-77.el5_4.1
wget-1.11.4-2.el5_4.1
which-2.16-7
wireless-tools-28-2.el5
wireless-tools-28-2.el5
words-3.0-9.1
wpa_supplicant-0.5.10-9.el5
xinetd-2.3.14-13.el5
xz-4.999.9-0.3.beta.20091007git.el5
xz-libs-4.999.9-0.3.beta.20091007git.el5
ypbind-1.19-12.el5_6.1
yp-tools-2.9-1.el5
yum-3.2.22-37.el5
yum-metadata-parser-1.1.2-3.el5
yum-rhn-plugin-0.5.4-22.el5_7.2
yum-security-1.1.16-16.el5
zip-2.31-2.el5
zlib-1.2.3-4.el5
zlib-1.2.3-4.el5"

dbrpmlist="acl-2.2.39-6.el5
acpid-1.0.4-9.el5_4.2
alsa-lib-1.0.17-1.el5
amtu-1.0.6-2.el5
anacron-2.3-45.el5
aspell-0.60.3-7.1
aspell-0.60.3-7.1
aspell-en-6.0-2.1
at-3.1.8-84.el5
atk-1.12.2-1.fc6
atk-1.12.2-1.fc6
attr-2.4.32-1.1
audit-1.7.18-2.el5
audit-libs-1.7.18-2.el5
audit-libs-1.7.18-2.el5
audit-libs-python-1.7.18-2.el5
authconfig-5.3.21-7.el5
autofs-5.0.1-0.rc2.156.el5_7.4
avahi-0.6.16-10.el5_6
avahi-compat-libdns_sd-0.6.16-10.el5_6
basesystem-8.0-5.1.1
bash-3.2-32.el5
bc-1.06-21
BCM95709C_10_100_1000BASET_Quad_Port_NIC_ven_0x14e4_dev_0x1639-a07-1
beecrypt-4.1.2-10.1.1
bind-libs-9.3.6-16.P1.el5_7.1
bind-utils-9.3.6-16.P1.el5_7.1
binutils-2.17.50.0.6-14.el5
bitmap-fonts-0.3-5.1.1
bitstream-vera-fonts-1.10-7
bluez-libs-3.7-1.1
bridge-utils-1.1-3.el5
bzip2-1.0.3-6.el5_5
bzip2-libs-1.0.3-6.el5_5
ccid-1.3.8-1.el5
celt051-0.5.1.3-0.el5
checkpolicy-1.33.1-6.el5
chkconfig-1.3.30.2-2.el5
compat-libstdc++-33-3.2.3-61
compat-libstdc++-33-3.2.3-61
conman-0.1.9.2-8.el5
coolkey-1.1.0-15.el5
coolkey-1.1.0-15.el5
coreutils-5.97-34.el5
cpio-2.6-23.el5_4.1
cpuspeed-1.2.1-10.el5
cracklib-2.8.9-3.3
cracklib-2.8.9-3.3
cracklib-dicts-2.8.9-3.3
crash-4.1.2-8.el5
crontabs-1.10-8
cryptsetup-luks-1.0.3-8.el5
cryptsetup-luks-1.0.3-8.el5
curl-7.15.5-9.el5_7.4
curl-7.15.5-9.el5_7.4
cyrus-sasl-2.1.22-5.el5_4.3
cyrus-sasl-lib-2.1.22-5.el5_4.3
cyrus-sasl-lib-2.1.22-5.el5_4.3
cyrus-sasl-md5-2.1.22-5.el5_4.3
cyrus-sasl-plain-2.1.22-5.el5_4.3
cyrus-sasl-plain-2.1.22-5.el5_4.3
db4-4.3.29-10.el5_5.2
db4-4.3.29-10.el5_5.2
dbus-1.1.2-16.el5_7
dbus-glib-0.73-10.el5_5
dbus-libs-1.1.2-16.el5_7
dbus-python-0.70-9.el5_4
dell_ft_ie_interface-1.0.12-4.18.8.el5
dell_ie_bios-3.1.0-1.13.2.el5
dell_ie_nic_broadcom-1.1.0-6
dell_ie_sas-3.1.0-1.13.2.el5
dell-omsa-repository-2-5
device-mapper-1.02.63-4.el5
device-mapper-1.02.63-4.el5
device-mapper-event-1.02.63-4.el5
device-mapper-multipath-0.4.7-46.el5_7.2
dhcdbd-2.2-2.el5
dhclient-3.0.5-29.el5_7.1
dhcpv6-client-1.0.10-20.el5
diffutils-2.8.1-15.2.3.el5
dmidecode-2.11-1.el5
dmraid-1.0.0.rc13-65.el5
dmraid-events-1.0.0.rc13-65.el5
dos2unix-3.1-27.2.el5
dosfstools-2.11-9.el5
dump-0.4b41-5.el5
e2fsprogs-1.39-33.el5
e2fsprogs-libs-1.39-33.el5
e2fsprogs-libs-1.39-33.el5
e4fsprogs-libs-1.41.12-2.el5
ebtables-2.0.9-5.el5
ed-0.2-39.el5_2
eject-2.1.5-4.2.el5
elfutils-libelf-0.137-3.el5
elinks-0.11.1-6.el5_4.1
ethtool-6-4.el5
expat-1.95.8-8.3.el5_5.3
expat-1.95.8-8.3.el5_5.3
fbset-2.1-22
file-4.17-15.el5_3.1
filesystem-2.4.0-3.el5
findutils-4.2.27-6.el5
fipscheck-1.2.0-1.el5
fipscheck-lib-1.2.0-1.el5
firmware-addon-dell-2.2.2-4.2.319.el5
firmware-tools-2.1.14-4.14.2.el5
freetype-2.2.1-28.el5_7.2
freetype-2.2.1-28.el5_7.2
gamin-0.1.7-8.el5
gamin-python-0.1.7-8.el5
gawk-3.1.5-14.el5
gdbm-1.8.0-26.2.1.el5_6.1
gettext-0.17-1.el5
glib2-2.12.3-4.el5_3.1
glib2-2.12.3-4.el5_3.1
glibc-2.5-65.el5_7.1
glibc-2.5-65.el5_7.1
glibc-common-2.5-65.el5_7.1
gnupg-1.4.5-14.el5_5.1
gnutls-1.4.1-3.el5_4.8
gnutls-1.4.1-3.el5_4.8
gpg-pubkey-23b66a9d-3adb5504
gpg-pubkey-37017186-45761324
gpg-pubkey-5e3d7775-42d297af
gpm-1.20.1-74.1
grep-2.5.1-55.el5
groff-1.18.1.1-11.1
grub-0.97-13.5
gzip-1.3.5-13.el5
hal-0.5.8.1-62.el5
hdparm-6.6-2
hesiod-3.1.0-8
hicolor-icon-theme-0.9-2.1
hmaccalc-0.9.6-3.el5
hwdata-0.213.24-1.el5
ifd-egate-0.05-15
info-4.8-14.el5
initscripts-8.45.38-2.el5
iproute-2.6.18-11.el5
iptables-1.3.5-5.3.el5_4.1
iptables-ipv6-1.3.5-5.3.el5_4.1
iptstate-1.4-2.el5
iputils-20020927-46.el5
irqbalance-0.55-15.el5
iscsi-initiator-utils-6.2.0.872-10.el5
jwhois-3.2.3-12.el5
kbd-1.12-21.el5
kernel-2.6.18-164.11.1.el5
kernel-2.6.18-274.12.1.el5
kernel-2.6.18-274.el5
keyutils-1.2-1.el5
keyutils-libs-1.2-1.el5
keyutils-libs-1.2-1.el5
kpartx-0.4.7-46.el5_7.2
krb5-libs-1.6.1-62.el5
krb5-libs-1.6.1-62.el5
krb5-workstation-1.6.1-62.el5
ksh-20100202-1.el5_6.6
less-436-7.el5
libacl-2.2.39-6.el5
libaio-0.3.106-5
libaio-0.3.106-5
libattr-2.4.32-1.1
libcap-1.10-26
libcmpiCppImpl0-2.0.0Dell-3.1.el5
libdaemon-0.10-5.el5
libdrm-2.0.2-1.1
libdrm-2.0.2-1.1
libevent-1.4.13-1
libgcc-4.1.2-51.el5
libgcc-4.1.2-51.el5
libgcrypt-1.4.4-5.el5
libgcrypt-1.4.4-5.el5
libgomp-4.4.4-13.el5
libgpg-error-1.4-2
libgpg-error-1.4-2
libgssapi-0.10-2
libhugetlbfs-1.3-8.2.el5
libhugetlbfs-1.3-8.2.el5
libICE-1.0.1-2.1
libICE-1.0.1-2.1
libIDL-0.8.7-1.fc6
libidn-0.6.5-1.1
libidn-0.6.5-1.1
libjpeg-6b-37
libjpeg-6b-37
libnl-1.0-0.10.pre5.5
libogg-1.1.3-3.el5
libpcap-0.9.4-15.el5
libpng-1.2.10-7.1.el5_7.5
libpng-1.2.10-7.1.el5_7.5
libselinux-1.33.4-5.7.el5
libselinux-1.33.4-5.7.el5
libselinux-python-1.33.4-5.7.el5
libselinux-utils-1.33.4-5.7.el5
libsemanage-1.9.1-4.4.el5
libsepol-1.15.2-3.el5
libsepol-1.15.2-3.el5
libSM-1.0.1-3.1
libSM-1.0.1-3.1
libsmal0-3.1.0-1.13.1.el5
libsmbios-2.2.26-6.2.el5
libstdc++-4.1.2-51.el5
libstdc++-4.1.2-51.el5
libsysfs-2.1.0-1.el5
libtermcap-2.0.8-46.1
libtermcap-2.0.8-46.1
libtiff-3.8.2-7.el5_6.7
libtiff-3.8.2-7.el5_6.7
libusb-0.1.12-5.1
libuser-0.54.7-2.1.el5_5.2
libutempter-1.1.4-4.el5
libutempter-1.1.4-4.el5
libvolume_id-095-14.27.el5_7.1
libwsman1-2.2.3.9-1.7.2.el5
libXau-1.0.1-3.1
libXau-1.0.1-3.1
libXdmcp-1.0.1-2.1
libXdmcp-1.0.1-2.1
libxml2-2.6.26-2.1.12.el5_7.1
libxml2-2.6.26-2.1.12.el5_7.1
libxml2-python-2.6.26-2.1.12.el5_7.1
libxslt-1.1.17-2.el5_2.2
lm_sensors-2.10.7-9.el5
log4cpp-1.0-9.el5
logrotate-3.7.4-12
logwatch-7.3-9.el5_6
lsof-4.78-3
lvm2-2.02.84-6.el5_7.1
m2crypto-0.16-8.el5
m4-1.4.5-3.el5.1
mailcap-2.1.23-1.fc6
mailx-8.1.1-44.2.2
make-3.81-3.el5
MAKEDEV-3.23-1.2
man-1.6d-2.el5
man-pages-2.39-17.el5
McAfeeVSEForLinux-1.6.0-28488
mcelog-0.9pre-1.32.el5
mcstrans-0.2.11-3.el5
MFEcma-4.5.0-1470
MFErt-2.0-0
mgetty-1.1.33-9.fc6
microcode_ctl-1.17-1.52.el5
mingetty-1.07-5.2.2
mkinitrd-5.1.19.6-71.el5_7.1
mkinitrd-5.1.19.6-71.el5_7.1
mktemp-1.5-23.2.2
mlocate-0.15-1.el5.2
module-init-tools-3.3-0.pre3.1.60.el5_5.1
mozldap-6.0.5-1.el5
mtools-3.9.10-2.fc6
mtr-0.71-3.1
MySQL-client-community-5.0.51a-0.rhel5
MySQL-server-community-5.0.51a-0.rhel5
nano-1.3.12-1.1
nash-5.1.19.6-71.el5_7.1
ncurses-5.5-24.20060715
ncurses-5.5-24.20060715
neon-0.25.5-10.el5_4.1
net-snmp-5.3.2.2-14.el5_7.1
net-snmp-libs-5.3.2.2-14.el5_7.1
net-tools-1.60-81.el5
newt-0.52.2-15.el5
nfs-utils-1.0.9-54.el5
nfs-utils-lib-1.0.8-7.6.el5
nscd-2.5-65.el5_7.1
nspr-4.8.8-1.el5_7
nspr-4.8.8-1.el5_7
nss-3.12.10-7.el5_7
nss-3.12.10-7.el5_7
nss_db-2.2-35.4.el5_5
nss_db-2.2-35.4.el5_5
nss_ldap-253-42.el5_7.4
nss_ldap-253-42.el5_7.4
nss-tools-3.12.10-7.el5_7
ntp-4.2.2p1-15.el5_7.1
ntsysv-1.3.30.2-2.el5
numactl-0.9.8-12.el5_6
numactl-0.9.8-12.el5_6
OpenIPMI-2.0.16-99.dell.1.99.2.el5
OpenIPMI-libs-2.0.16-99.dell.1.99.2.el5
openldap-2.3.43-12.el5_7.10
openldap-2.3.43-12.el5_7.10
openssh-4.3p2-72.el5_7.5
openssh-clients-4.3p2-72.el5_7.5
openssh-server-4.3p2-72.el5_7.5
openssl-0.9.8e-20.el5
openssl-0.9.8e-20.el5
openwsman-client-2.2.3.9-1.7.2.el5
openwsman-server-2.2.3.9-1.7.2.el5
ORBit2-2.14.3-5.el5
pam-0.99.6.2-6.el5_5.2
pam-0.99.6.2-6.el5_5.2
pam_ccreds-3-5
pam_ccreds-3-5
pam_krb5-2.2.14-21.el5
pam_krb5-2.2.14-21.el5
pam_passwdqc-1.0.2-1.2.2
pam_passwdqc-1.0.2-1.2.2
pam_pkcs11-0.5.3-23
pam_pkcs11-0.5.3-23
pam_smb-1.1.7-7.2.1
pam_smb-1.1.7-7.2.1
parted-1.8.1-28.el5
parted-1.8.1-28.el5
passwd-0.73-2
patch-2.5.4-31.el5
pax-3.4-2.el5
pciutils-3.1.7-3.el5
pcmciautils-014-5
pcre-6.6-6.el5_6.1
pcsc-lite-1.4.4-4.el5_5
pcsc-lite-libs-1.4.4-4.el5_5
PERC_6_i_Integrated_ven_0x1000_dev_0x0060_subven_0x1028_subdev_0x1f0c-a14-1
perl-5.8.8-32.el5_7.6
perl-AppConfig-1.52-4
perl-Compress-Zlib-1.42-1.fc6
perl-DBI-1.52-2.el5
perl-HTML-Parser-3.55-1.fc6
perl-HTML-Tagset-3.10-2.1.1
perl-libwww-perl-5.805-1.1.1
perl-rrdtool-1.2.23-1.el5.rf
perl-String-CRC32-1.4-2.fc6
perl-URI-1.35-3
pkinit-nss-0.7.6-1.el5
pm-utils-0.99.3-10.el5
policycoreutils-1.33.12-14.8.el5
popt-1.10.2.3-22.el5_7.2
portmap-4.0-65.2.2.1
prelink-0.4.0-2.el5
procmail-3.22-17.1
procps-3.2.7-17.el5
psacct-6.3.2-44.el5
psmisc-22.2-7.el5_6.2
pygobject2-2.12.1-5.el5
pyOpenSSL-0.6-2.el5
python-2.4.3-44.el5_7.1
python-ctypes-1.0.2-1.1.el5
python-dmidecode-3.10.13-1.el5_5.1
python-elementtree-1.2.6-5
python-iniparse-0.2.3-4.el5
python-libs-2.4.3-44.el5_7.1
python-numeric-23.7-2.2.2.el5_6.1
python-smbios-2.2.26-6.2.el5
python-sqlite-1.1.7-1.2.1
python-urlgrabber-3.1.0-6.el5
qffmpeg-libs-0.4.9-0.16.20080908.el5_5
qpixman-0.13.3-4.el5
quota-3.13-5.el5
readahead-1.3-8.el5
readline-5.1-3.el5
readline-5.1-3.el5
redhat-logos-4.9.16-1
redhat-release-5Server-5.7.0.3
redhat-release-notes-5Server-41
rhel-instnum-1.0.9-1.el5
rhn-check-0.4.20-56.el5
rhn-client-tools-0.4.20-56.el5
rhnlib-2.5.22-6.el5
rhnsd-4.7.0-10.el5
rhn-setup-0.4.20-56.el5
rhpl-0.194.1-1
rmt-0.4b41-5.el5
rng-utils-2.0-4.el5
rootfiles-8.1-1.1.1
rpm-4.4.2.3-22.el5_7.2
rpm-libs-4.4.2.3-22.el5_7.2
rpm-python-4.4.2.3-22.el5_7.2
rrdtool-1.2.23-1.el5.rf
rsync-3.0.6-4.el5_7.1
sblim-sfcb-1.3.7-1.6.4.el5
sblim-sfcc-2.2.1-47.el5
screen-4.0.3-4.el5
secpwgen-1.3-2.el5.rf
sed-4.1.5-8.el5
selinux-policy-2.4.6-316.el5
selinux-policy-targeted-2.4.6-316.el5
setarch-2.0-1.1
setools-3.0-3.el5
setserial-2.17-19.2.2
setup-2.5.58-7.el5
setuptool-1.19.2-1
sgpio-1.2.0_10-2.el5
shadow-utils-4.0.17-18.el5_6.1
slang-2.0.6-4.el5
slrn-0.9.8.1pl1-1.2.2
smartmontools-5.38-2.el5
smbios-utils-2.2.26-6.2.el5
smbios-utils-bin-2.2.26-6.2.el5
smbios-utils-python-2.2.26-6.2.el5
sos-1.7-9.54.el5_7.1
specspo-13-1.el5
sqlite-3.3.6-5
srvadmin-all-6.5.0-1.1.1.el5
srvadmin-argtable2-6.5.0-3.1.el5
srvadmin-base-6.5.0-1.1.1.el5
srvadmin-cm-6.5.0-2247
srvadmin-deng-6.5.0-1.31.1.el5
srvadmin-hapi-6.5.0-1.33.2.el5
srvadmin-hapi-6.5.0-1.33.2.el5
srvadmin-idrac-6.5.0-1.228.2.el5
srvadmin-idracadm-6.5.0-1.228.2.el5
srvadmin-idrac-ivmcli-6.5.0-1.239.1.el5
srvadmin-idrac-vmcli-6.5.0-1.254.1.el5
srvadmin-isvc-6.5.0-1.52.2.el5
srvadmin-itunnelprovider-6.5.0-1.151.1.el5
srvadmin-iws-6.5.0-1.143.3.el5
srvadmin-jre-6.5.0-1.145.1.el5
srvadmin-omacore-6.5.0-1.143.3.el5
srvadmin-omcommon-6.5.0-1.142.2.el5
srvadmin-omilcore-6.5.0-1.452.1.el5
srvadmin-rac4-6.5.0-1.154.2.el5
srvadmin-rac4-populator-6.5.0-1.154.2.el5
srvadmin-rac5-6.5.0-1.149.1.el5
srvadmin-racadm4-6.5.0-1.154.2.el5
srvadmin-racadm5-6.5.0-1.149.1.el5
srvadmin-rac-components-6.5.0-1.228.2.el5
srvadmin-racdrsc-6.5.0-1.228.2.el5
srvadmin-racsvc-6.5.0-1.154.2.el5
srvadmin-smcommon-6.5.0-1.201.2.el5
srvadmin-smweb-6.5.0-1.201.2.el5
srvadmin-standardAgent-6.5.0-1.1.1.el5
srvadmin-storage-6.5.0-1.201.2.el5
srvadmin-storageservices-6.5.0-1.1.1.el5
srvadmin-storelib-6.5.0-1.326.1.el5
srvadmin-storelib-sysfs-6.5.0-1.1.1.el5
srvadmin-sysfsutils-6.5.0-1.1.el5
srvadmin-webserver-6.5.0-1.1.1.el5
srvadmin-xmlsup-6.5.0-1.141.2.el5
strace-4.5.18-5.el5_5.5
stunnel-4.15-2.el5.1
sudo-1.7.2p1-10.el5
svrcore-4.0.4-3.el5
svrcore-4.0.4-3.el5
symlinks-1.2-24.2.2
sysfsutils-2.1.0-1.el5
sysklogd-1.4.1-46.el5
syslinux-3.11-4
sysstat-9.0.4-1
system-config-securitylevel-tui-1.6.29.1-6.el5
systemconfigurator-2.2.11-1
SysVinit-2.86-17.el5
tar-1.15.1-30.el5
tcl-8.4.13-4.el5
tcpdump-3.9.4-15.el5
tcp_wrappers-7.6-40.7.el5
tcp_wrappers-7.6-40.7.el5
tcsh-6.14-17.el5_5.2
telnet-0.17-39.el5
termcap-5.5-1.20060701.1
time-1.7-27.2.2
tmpwatch-2.9.7-1.1.el5.5
traceroute-2.0.1-6.el5
tree-1.5.0-4
tzdata-2011l-4.el5
udev-095-14.27.el5_7.1
udftools-1.0.0b3-0.1.el5
unix2dos-2.2-26.2.3.el5
unzip-5.52-3.el5
usermode-1.88-3.el5.2
util-linux-2.13-0.56.el5
vconfig-1.9-3
vim-common-7.0.109-7.el5
vim-enhanced-7.0.109-7.el5
vim-minimal-7.0.109-7.el5
vixie-cron-4.1-77.el5_4.1
wget-1.11.4-2.el5_4.1
which-2.16-7
wireless-tools-28-2.el5
wireless-tools-28-2.el5
words-3.0-9.1
wpa_supplicant-0.5.10-9.el5
xinetd-2.3.14-13.el5
xz-4.999.9-0.3.beta.20091007git.el5
xz-libs-4.999.9-0.3.beta.20091007git.el5
ypbind-1.19-12.el5_6.1
yp-tools-2.9-1.el5
yum-3.2.22-37.el5
yum-dellsysid-2.2.26-6.2.el5
yum-metadata-parser-1.1.2-3.el5
yum-rhn-plugin-0.5.4-22.el5_7.2
yum-security-1.1.16-16.el5
zip-2.31-2.el5
zlib-1.2.3-4.el5
zlib-1.2.3-4.el5"

echo "Verifying system configuration..."
minimize_packages
patch_repositories
gpgcheck
yum_check_update
review_logs
ssh_key_length
ssh_config
disable_jnjrunbook
pam_sshd_access
enable_accounting
ntp_config
mcafee_schedule
mcafee_crontab
mcafee_installed
mcafee_running
remove_webmin
truststore_exists
mysql_ssl
app_server_ssl
remove_tomcat_user
minimize_services
config_firewall_appserver
# config_firewall_dbserver needed
disable_zeroconf
disable_ipv6
kernel_net_params
logging
syslog
logfile_perms
nodev_partitions
nosuid_nodev_fstab
nosuid_nodev_hal
user_removable_fs
check_shadow_perms
world_write_sticky
unauth_world_write
unauth_suid_sgid
unowned
disable_usb
instance_config_perms
instance_config_ownership
rhost_pam
restrict_at_cron
restrict_crontab_perms
block_system_accounts
ldap_conf
no_home
failed_logins
password_length
password_expiration
password_reuse
password_hashes
no_runbook_user
jnjrunbook_user
no_operations_user
jnjoperations_user
sudoers_config
warning_banner

# Include this script in archivedir so we know what generated the results
cp $0 $archivedir
