#!/bin/bash
#This script automatically installs MISP for CentOS/RHEL 7
#The majority of this script was copied from https://misp.github.io/MISP/INSTALL.rhel7/
#With slight changes here and there
########################################

########################################
# Logging setup. Ganked this entirely from stack overflow. Uses FIFO/pipe magic to log all the output of the script to a file. Also capable of accepting redirects/appends to the file for logging compiler stuff (configure, make and make install) to a log file instead of losing it on a screen buffer. This gives the user cleaner output, while logging everything in the background, for troubleshooting, analysis, or sending it to me for help.

logfile=/var/log/misp_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

########################################
#This line unsets some environment variables just for the shell script to run. This is done to ensure that passwords are NOT logged to your .*history files.
unset HISTFILE MYSQL_HISTFILE

########################################
#Functions, functions everywhere.
#metasploit-like print statements. Gratuitously ganked from  Darkoperator's metasploit install script. status messages, error messages, good status returns. I added in a notification print for areas users should definitely pay attention to.

function print_status ()
{
    echo -e "\x1B[01;34m[*]\x1B[0m $1"
}

function print_good ()
{
    echo -e "\x1B[01;32m[*]\x1B[0m $1"
}

function print_error ()
{
    echo -e "\x1B[01;31m[*]\x1B[0m $1"
}

function print_notification ()
{
	echo -e "\x1B[01;33m[*]\x1B[0m $1"
}

########################################
#Script does a lot of error checking. Decided to insert an error check function. If a task performed returns a non zero status code, something very likely went wrong.

function error_check
{

if [ $? -eq 0 ]; then
	print_good "$1 successfully completed."
else
	print_error "$1 failed. Please check $logfile for more details."
exit 1
fi

}

########################################
#Package installation function.

function install_packages()
{
yum -y update &>> $logfile && yum -y install ${@} &>> $logfile
error_check 'Package installation'
}

########################################
#This script creates a lot of directories by default. This is a function that checks if a directory already exists and if it doesn't creates the directory (including parent dirs if they're missing).

function dir_check()
{

if [ ! -d $1 ]; then
	print_notification "$1 does not exist. Creating.."
	mkdir -p $1
else
	print_notification "$1 already exists. (No problem, We'll use it anyhow)"
fi

}

########################################
##BEGIN MAIN SCRIPT##
#Pre checks: These are a couple of basic sanity checks the script does before proceeding.
########################################

#These lines establish where automisp was executed. The config file _should_ be in this directory. the script exits if the config isn't in the same directory as the automisp shell script.

print_status "Checking for config file.."
execdir=`pwd`
if [ ! -f "$execdir"/automisp.conf ]; then
	print_error "automisp.conf was NOT found in $execdir. The script relies HEAVILY on this config file. Please make sure it is in the same directory you are executing the automisp script from!"
	exit 1
else
	print_good "Found config file."
fi

source "$execdir"/automisp.conf

########################################

print_status "OS Version Check.."
release=`cat /etc/redhat-release | egrep -o [[:digit:]] | head -1`
if [[ $release == "7"* ]]; then
	print_good "OS is RHEL/CentOS 7. Good to go."
else
    print_notification "This is not RHEL/CentOS 7, this script has NOT been tested on other platforms."
	print_notification "You continue at your own risk!(Please report your successes or failures!)"
fi

#root check. Lotta stuff we're doing requires root access.

print_status "Checking for root privs.."
if [ $(whoami) != "root" ]; then
	print_error "This script must be ran with sudo or root privileges."
	exit 1
else
	print_good "We are root."
fi
	 
########################################
#setting the hostname to whatever FQDN is set to

print_status "setting hostname to $FQDN.."
print_notification "you can change this later by running hostnamectl set-hostname [your.hostname.here]"
hostnamectl set-hostname $FQDN &>> $logfile
error_check 'hostname change'

########################################
#using touch to create the file /root/misp_creds if it doesn't already exist, and setting its file permissions to 600 (only root can read)
#creating the misp user and setting its password
#we're doing a custom error check here so that the script doesn't stop execution if the misp user already exists.

touch /root/misp_creds
chmod 600 /root/misp_creds

print_status "creating the misp system user, and setting its password.."
adduser misp &>> $logfile
if [ $? -ne 0 ]; then
	print_notification "Looks like the misp user has already been created"
	print_notification "If you used this script to do it and this is a second run, the creds should be in /root/misp_creds already."
else
	print_notification "misp user created. setting password.."
	echo $MISP_PASSWORD | passwd misp --stdin
	error_check 'misp password reset'
	echo "misp user account name:misp password: $MISP_PASSWORD" >> /root/misp_creds
fi


########################################
# System updates

print_status "Performing yum upgrade (May take a while if this is a fresh install).."
yum -y upgrade &>> $logfile
error_check 'System updates'

########################################
# In order to pull down certain packages, we need need to enable extra repos. This process differs for both RHEL and CentOS. this is where the variable "is_redhat" comes into play.

if [[ $is_redhat == "1" ]]; then
	print_status "Enabling redhat server-optional, server-extras, and server-SCL repos.."
	subscription-manager refresh &>> $logfile
	error_check 'subscription manager refresh'
	subscription-manager repos --enable rhel-7-server-optional-rpms &>> $logfile
	error_check 'optional repo configuration'
	subscription-manager repos --enable rhel-7-server-extras-rpms &>> $logfile
	error_check 'extra repo configuration'
	subscription-manager repos --enable rhel-server-rhscl-7-rpms &>> $logfile
	error_check 'SCL repo configuration'
	yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm &>> $logfile
	error_check 'RHEL EPEL repo installation'
else
	print_status "Installing epel-release and centos-release-scl via yum.."
	declare -a packages=( epel-release centos-release-scl );
	install_packages ${packages[@]}
fi

########################################
# Installing recommended and required packages for RHEL/CentOS
# the misp script has us install expect, but we don't actually need it. You can run all of the mysql_secure_install statements with no user input.
# Also the installer docs need the mysql client, but the rh-mariadb package doesn't actually include the mysql client, so... thats borken, and I fixed it.

print_status "Installing packages: deltarpm  mysql ntpdate neovim gcc git zip rh-git218 httpd24 mod_ssl rh-redis32 rh-mariadb102 libxslt-devel zlib-devel ssdeep-devel rh-php72 rh-php72-php-fpm rh-php72-php-devel rh-php72-php-mysqlnd rh-php72-php-mbstring rh-php72-php-xml rh-php72-php-bcmath rh-php72-php-opcache rh-php72-php-gd rh-python36 haveged devtoolset-7 cmake3 cppcheck gpgme-devel openjpeg-devel gcc-c++ poppler-cpp-devel pkgconfig python-devel redhat-rpm-config rh-ruby22 rubygem-rouge rubygem-asciidoctor zbar-devel opencv-devel.."
print_notification "This is a large number of packages. About 800MB in total. This could take some time depending on your internet connectivity."
declare -a packages=( deltarpm mysql ntpdate neovim gcc git zip rh-git218 httpd24 mod_ssl rh-redis32 rh-mariadb102 libxslt-devel zlib-devel ssdeep-devel rh-php72 rh-php72-php-fpm rh-php72-php-devel rh-php72-php-mysqlnd rh-php72-php-mbstring rh-php72-php-xml rh-php72-php-bcmath rh-php72-php-opcache rh-php72-php-gd rh-python36 haveged devtoolset-7 cmake3 cppcheck gpgme-devel openjpeg-devel gcc-c++ poppler-cpp-devel pkgconfig python-devel redhat-rpm-config rh-ruby22 rubygem-rouge rubygem-asciidoctor zbar-devel opencv-devel );
install_packages ${packages[@]}

########################################
#enabling and starting various services

print_status "enabling and starting redis (rh-redis32-redis) service.."
systemctl enable --now rh-redis32-redis.service &>> $logfile
error_check 'redis startup'

print_status "enabling and startign php (rh-php72-php-fpm) service.."
systemctl enable --now rh-php72-php-fpm.service &>> $logfile
error_check 'php startup'

print_status "enabling and starting the haveged service.."
systemctl enable --now haveged.service &>> $logfile
error_check 'haveged startup'

print_status "syncing time via ntpdate.."
ntpdate pool.ntp.org &>> $logfile
error_check 'time sync'

#########################################
#Setting up MISP and installing it via github
# If the MISP installation directory exists, assume its a botched install, and do it over from scratch.
print_status "Creating MISP directory and installing from github.."
if [ -d $PATH_TO_MISP ]; then
	print_notification "$PATH_TO_MISP already exists, we're going to remove it to do a clean install."
	rm -rf $PATH_TO_MISP  &>> $logfile
	error_check 'removal of MISP install directory'
fi
mkdir $PATH_TO_MISP
chown $WWW_USER:$WWW_USER $PATH_TO_MISP &>> $logfile
cd /var/www &>> $logfile
$SUDO_WWW git clone https://github.com/MISP/MISP.git &>> $logfile
error_check 'misp download'
cd $PATH_TO_MISP &>> $logfile

print_status "Fetching submodules.."
$SUDO_WWW git submodule update --init --recursive &>> $logfile
error_check 'submodule update'
$SUDO_WWW git submodule foreach --recursive git config core.filemode false &>> $logfile
error_check 'submodule foreach check'
$SUDO_WWW git config core.filemode false &>> $logfile
error_check 'submodule filemode check'

#########################################
#Setting up pear PHP modules. difference from the MISP installer script: the dependencies directory no longer exists. I'm sure this is fine (tm)

print_status "Installing pear PHP modules.."
$RUN_PHP -- pear channel-update pear.php.net &>> $logfile
error_check 'pear channel configuration'
$RUN_PHP -- pear install Console_Commandline Crypt_GPG &>> $logfile
error_check 'pear install of console_commandline and crypt_gpg'

#########################################
#Configurating Python3 stuff

print_status "Setting up python virtual environment.."
$SUDO_WWW $RUN_PYTHON -- virtualenv -p python3 $PATH_TO_MISP/venv &>> $logfile
error_check 'virtual environment creation'
dir_check /usr/share/httpd/.cache &>> $logfile
chown $WWW_USER:$WWW_USER /usr/share/httpd/.cache &>> $logfile
error_check '.cache directory creation and permission modification'
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools &>> $logfile
error_check 'installation of pip setuptools'


print_status "Downloading additional dependencies.."
cd $PATH_TO_MISP/app/files/scripts &>> $logfile
$SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git &>> $logfile
error_check 'download of python-cybox'
$SUDO_WWW git clone https://github.com/STIXProject/python-stix.git &>> $logfile
error_check 'download of python-stix'
$SUDO_WWW git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief &>> $logfile
error_check 'download of LIEF'
$SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git &>> $logfile
error_check 'download of mixbox'

cd $PATH_TO_MISP/app/files/scripts/python-cybox &>> $logfile
cd $PATH_TO_MISP/app/files/scripts/python-stix &>> $logfile
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install . &>> $logfile
error_check 'python-stix installation'

cd $PATH_TO_MISP/app/files/scripts/mixbox &>> $logfile
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install . &>> $logfile
error_check 'mixbox installation'

cd $PATH_TO_MISP/cti-python-stix2 &>> $logfile
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install . &>> $logfile
error_check 'cti-python-stix2 installation'

$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U maec zmq redis python-magic git+https://github.com/kbandla/pydeep.git plyara &>> $logfile
error_check 'maec, zmq, redis, python-magic, pydeep, and plyara python module installation'

cd $PATH_TO_MISP/app/files/scripts/lief
if [ ! -d $PATH_TO_MISP/app/files/scripts/lief/build ]; then
	$SUDO_WWW mkdir build &>> $logfile
fi

print_notification "We have to compile LIEF from scratch. This is going to take a long time (20+ minutes or more depending on system resources). You can follow build progress by opening up another terminal and running tail -f /var/log/misp_install.log"
cd $PATH_TO_MISP/app/files/scripts/lief/build
$SUDO_WWW scl enable devtoolset-7 rh-python36 "bash -c 'cmake3 -DLIEF_PYTHON_API=on -DPYTHON_VERSION=3.6 -DPYTHON_EXECUTABLE=$PATH_TO_MISP/venv/bin/python -DLIEF_DOC=off -DCMAKE_BUILD_TYPE=Release ..'" &>> $logfile
error_check 'LIEF pre-build configuration'
$SUDO_WWW make -j3 pyLIEF &>> $logfile
error_check 'compile of LIEF'

echo /var/www/MISP/app/files/scripts/lief/build/api/python |$SUDO_WWW tee /var/www/MISP/venv/lib/python3.6/site-packages/lief.pth &>> $logfile
error_check 'configuration of pyLIEF'

cd $PATH_TO_MISP/PyMISP &>> $logfile
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U . &>> $logfile
error_check 'PyMISP installation'

echo 'source scl_source enable rh-python36' | sudo tee -a /etc/opt/rh/rh-php72/sysconfig/php-fpm &>> $logfile
error_check 'addition of python to php sysconfig'
sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php72/php-fpm.d/www.conf &>> $logfile


#########################################
#configuration items to get CakePHP running, adding php extensions, and reconfiguring php.ini

print_status "Configuring CakePHP.."
print_notification "Creating /etc/gai.conf with ipv4 preference to get around some packagist.org quirks.."
if [[ -e /etc/gai.conf ]]; then
	mv /etc/gai.conf /etc/gai.conf.bak
	error_check 'backup of existing gai.conf'
fi
echo 'precedence ::ffff:0:0/96 100' > /etc/gai.conf
error_check 'gai.conf file creation'
dir_check /usr/share/httpd/.composer
chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP &>> $logfile
chown $WWW_USER:$WWW_USER /usr/share/httpd/.composer &>> $logfile
cd $PATH_TO_MISP/app
$SUDO_WWW $RUN_PHP "php composer.phar require kamisama/cake-resque:4.1.2" &>> $logfile
error_check 'set requirement of cake-resque'
$SUDO_WWW $RUN_PHP "php composer.phar config vendor-dir Vendor" &>> $logfile
error_check 'setting vendor directory'
$SUDO_WWW $RUN_PHP "php composer.phar install" &>> $logfile
error_check 'PHP composer install'
if [[ -e /etc/gai.conf.bak ]]; then
	mv /etc/gai.conf.bak /etc/gai.conf
	error_check 'restoration of previous gai.conf'
else
	rm -rf /etc/gai.conf
	error_check 'removal of gai.conf'
fi

print_status "enabling redis for PHP.."
scl enable rh-php72 'pecl channel-update pecl.php.net' &>> $logfile
error_check 'pecl update channel configuration'
#Discovered if pecl packages are installed and you try to install them again, it doesn't gracefully exit. It tells you the installation fails.
#This makes error checking this on multiple/failed installs more difficult. So my solution is to just run an uninstall statement prior to attempting to install pecl packages.
#fun fact: you can't check the exit code for the uninstall statement, because even if there is nothing to uninstall it returns exit code 0.
scl enable rh-php72 'pecl uninstall redis' &>> $logfile
scl enable rh-php72 'yes no|pecl install redis' &>> $logfile
error_check 'pecl redis module installation'
echo "extension=redis.so" |sudo tee /etc/opt/rh/rh-php72/php-fpm.d/redis.ini &>> $logfile
error_check 'redis.so addition to php'
#likewise, if a symlink exists, ln will fail to create it properly, so we just remove it in advance.
rm -rf /etc/opt/rh/rh-php72/php.d/99-redis.ini &>> $logfile
ln -s /etc/opt/rh/rh-php72/php-fpm.d/redis.ini /etc/opt/rh/rh-php72/php.d/99-redis.ini &>> $logfile
error_check 'symlink of php-fpm.d/redis.ini to php.d/99-redis.ini'

print_status "enabling GNUPG for PHP.."
scl enable rh-php72 'pecl uninstall gnupg' &>> $logfile
scl enable rh-php72 'pecl install gnupg' &>> $logfile
error_check 'pecl gnupg module installation'
echo "extension=gnupg.so" |sudo tee /etc/opt/rh/rh-php72/php-fpm.d/gnupg.ini &>> $logfile
error_check 'gnupg.so addition to php'
rm -rf /etc/opt/rh/rh-php72/php.d/99-gnupg.ini &>> $logfile
ln -s /etc/opt/rh/rh-php72/php-fpm.d/gnupg.ini /etc/opt/rh/rh-php72/php.d/99-gnupg.ini &>> $logfile
error_check 'symlink of php-fpm.d/gnupg.ini to php.d/99-gnupg.ini'

print_status "Reconfiguring max file size, max post size, maximum execution time, and memory limits in php.ini.."
for key in upload_max_filesize post_max_size max_execution_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done
error_check 'php.ini changes'

cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
error_check 'copy of INSTALL/setup/config.php to app/Plugin/CakeResque/Config/config.php'

systemctl restart rh-php72-php-fpm.service
error_check 'restart of php-fpm'

#########################################
#Resetting the file permissions for the MISP directory
#We're using the less restrictive permissions so that updates from the web interface will work hopefully

print_status "Resetting MISP install directory permissions.."
chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
error_check 'recursive ownership reset of MISP install directory to apache user and group'
find $PATH_TO_MISP -type d -exec chmod g=rx {} \;
error_check 'recursive reconfiguration of MISP installation folder permissions to group rx'
chmod -R g+r,o= $PATH_TO_MISP
error_check 'recursive removal of world file permissions in MISP installation folder'

#########################################
#Performing database configuration and setup
#MISP install guide got the name of the service wrong.

print_status "configuring mariadb for use.."
echo [mysqld] |tee /etc/my.cnf.d/bind-address.cnf
echo bind-address=127.0.0.1 | tee -a /etc/my.cnf.d/bind-address.cnf
systemctl enable --now rh-mariadb102-mariadb
error_check 'mariadb startup'

#This section requires a little bit of fancy footwork to ensure that everything works properly.
#I chose to do custom error catching on the mysqladmin and mysql_secure_installation commands because we're not asking for a password with them.
#thats because by default, the rh-mariadb package configures the root user to NOT have a password. and as far as I know, unix socket auth is not being used.
#So I'm assuming that, if either of these commands failed, then the root database user's password has been set.

print_status "Running mysql_secure_installation commands.."
#This blob of mysql commands is removing null users, verifying that remote access as the root database user is disabled for the database, and verifying that any test databases are removed.
scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -e \"DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;\"" &>> $logfile
if [ $? -eq 0 ]; then
	print_good "mysql_secure_installation commands ran successfully."
else
	print_notification "mysql_secure_installation commands failed. I have no choice but to assume that this is because this is because the root mysql user's password has been set previously (or from a previous run of this script), and that this commands have already been run."
	print_notification "if you don't think this is true run the command scl enable rh-mariadb102 \"bash mysql_secure_installation\""
fi

#set the root database user's password. If it fails, assume the script ran once already, or the user already set the password.
mysqladmin -u$DBUSER_ADMIN password $DBPASSWORD_ADMIN &>> $logfile
if [ $? -eq 0 ]; then
	print_good "successfully set $DBUSER_ADMIN database user password."
	echo "database user: $DBUSER_ADMIN password: $DBPASSWORD_ADMIN" >> /root/misp_creds
else
	print_notification "failed to run mysqladmin to set $DBUSER_ADMIN database user password. Either this script has already been ran and the password is set, or you set the password for the user already."
	print_notification "If this script has been ran previously, the credentials should be located in /root/misp_creds"
fi
#this is a string of mysql statements that perform the following tasks:
#drop the MISP database if it exists (catch and clean up failed installs)
#create the MISP database
#drop the MISP database user if it exists (again, to catch failed installs)
#create the misp database user and set that user's creds.
print_status "creating MISP database, database user, assigning privs, and setting its password.."
scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e \"DROP DATABASE IF EXISTS $DBNAME; CREATE DATABASE IF NOT EXISTS $DBNAME; DROP USER IF EXISTS $DBUSER_MISP@localhost; GRANT USAGE on *.* to $DBUSER_MISP@localhost IDENTIFIED by '$DBPASSWORD_MISP'; GRANT ALL PRIVILEGES on $DBNAME.* to '$DBUSER_MISP'@'localhost'; FLUSH PRIVILEGES;\"" &>> $logfile
error_check 'misp database and user creation'
echo "database user: $DBUSER_MISP password: $DBPASSWORD_MISP" >> /root/misp_creds

print_status "creating MISP database structure.."
$SUDO_WWW cat $PATH_TO_MISP/INSTALL/MYSQL.sql | scl enable rh-mariadb102 "mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME" &>> $logfile
error_check 'MISP database structure creation'

#########################################
#selinux stuff
#first we check selinux_status and check to see if "enabled" is returned.
#if true, perform a bunch of selinux config changes to accomodate MISP
#if not, then theres nothing to do here

print_status "Check to see if we have to mess with SELinux.."
if [[ $selinux_status == "enabled" ]]; then
	print_notification "SELinux is enabled. Performing adjustments.."
	chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files &>> $logfile
	error_check 'selinux permission change for MISP/app/files'
	chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/terms &>> $logfile
	error_check 'selinux permission change for MISP/app/files/terms'
	chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/tmp &>> $logfile
	error_check 'selinux permission change for MISP/app/files/scripts/tmp'
	chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Plugin/CakeResque/tmp &>> $logfile
	error_check 'selinux permission change for MISP/app/Plugin/CakeResque/tmp'
	chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/cake &>> $logfile
	error_check 'selinux permission change for MISP/app/Console/cake'
	chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/worker/start.sh &>> $logfile
	error_check 'selinux permission change for MISP/app/Console/worker/start.sh'
	chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/mispzmq/mispzmq.py &>> $logfile
	error_check 'selinux permission change for MISP/app/files/scripts/mispzmq/mispzmq.py'
	chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/mispzmq/mispzmqtest.py &>> $logfile
	error_check 'selinux permission change for MISP/app/files/scripts/mispzmq/mispzmqtest.py'
	chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/lief/build/api/python/lief.so &>> $logfile
	error_check 'selinux permission change for MISP/app/files/scripts/lief/build/api/python/lief.so'
	chcon -t httpd_sys_rw_content_t /tmp &>> $logfile
	error_check 'selinux permission change for /tmp'
	chcon -R -t usr_t $PATH_TO_MISP/venv &>> $logfile
	error_check 'selinux permission change for MISP/venv'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.git &>> $logfile
	error_check 'selinux permission change for MISP/.git'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp &>> $logfile
	error_check 'selinux permission change for MISP/app/tmp'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Lib &>> $logfile
	error_check 'selinux permission change for MISP/app/Lib'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config &>> $logfile
	error_check 'selinux permission change for MISP/app/Config'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/orgs &>> $logfile
	error_check 'selinux permission change for MISP/app/webroot/img/orgs'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/custom &>> $logfile
	error_check 'selinux permission change for MISP/app/webroot/img/custom'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/mispzmq &>> $logfile
	error_check 'selinux permission change for MISP/app/files/scripts/mispzmq'
	setsebool -P httpd_can_network_connect on &>> $logfile
	error_check 'sebool permission change for httpd_can_network_connect'
	setsebool -P httpd_can_sendmail on &>> $logfile
	error_check 'sebool permission change for httpd_can_sendmail'
	print_status "Attempting to perform SELinux changes to enable log rotation of MISP/app/tmp/logs/*.."
	print_notification "The documentation was less than confident about these changes actually working. So this might not actually work."
	#I'm not joking. The docs say "FIXME: The below does not work" and I have no idea how long its been like that. TODO: install logrotate and make use of sealert to see what, if anything is being blocked.
	semanage fcontext -a -t httpd_log_t "$PATH_TO_MISP/app/tmp/logs(/.*)?" &>> $logfile
	error_check 'semanage fcontext permission change for MISP/app/tmp/logs/*'
	chcon -R -t httpd_log_t $PATH_TO_MISP/app/tmp/logs &>> $logfile
	error_check 'selinux permission change for MISP/app/tmp/logs'
	chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp/logs &>> $logfile
	error_check 'selinux permission change for MISP/app/tmp/logs'
	checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te &>> $logfile
	error_check 'semodule check of MISP/INSTALL/misplogrotate.te'
	semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod &>> $logfile
	error_check 'semodule pack of misplogrotate.mod'
	semodule -i /tmp/misplogrotate.pp &>> $logfile
	error_check 'semodule insertion of misplogrotate.pp'
else
	print_notification "Looks like SELinux is disabled."
fi

#########################################
#logrotate stuff, we want to try and enable log rotation for MISP

print_notification "Setting up logrotate for MISP logs.."
cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp &>> $logfile
error_check 'MISP logrotate configuration'
chmod 0640 /etc/logrotate.d/misp &>> $logfile
error_check 'MISP logrotate file permission change'

#########################################
#Setting up SSL stuff
#generating dhparam.pem, a self-signed SSL cert, and "stapling" the dhparam.pem to the self-signed cert
#TODO: allow for letsencrypt to be used?

print_status "Setting up SSL.."

if [[ ! -e "/etc/pki/tls/certs/dhparam.pem" ]]; then
	print_notification "could not find the dhparam.pem file. That means we have to generate one. This will take some time. Count on this taking at least 15 minutes on a moderately powerful system."
	print_notification "if you want to follow the progress and make sure the script hasn't frozen or something, open up another terminal session (or SSH) and tail -f /var/log/misp_install.log"
	openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 4096 &>> $logfile
	error_check 'creation of /etc/pki/tls/certs/dhparam.pem'
fi
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Nevada/L=LasVegas/O=Security/CN=$FQDN" -keyout /etc/pki/tls/private/$FQDN.key  -out /etc/pki/tls/certs/$FQDN.crt &>> $logfile
error_check 'creation of /etc/pki/tls/private/$FQDN.key and /etc/pki/tls/certs/$FQDN.crt'
cat /etc/pki/tls/certs/dhparam.pem | tee -a /etc/pki/tls/certs/$FQDN.crt &>> $logfile
error_check 'added dhparam.pem to misp.local.crt'

#########################################
#setting up httpd site config stuff
#remove the welcome.conf and ssl.conf default files (moving them up a directory)
#then we generate a site config for MISP that listens on port 80 and port 443.
#the port 80 listener directs to port 443 to apply SSL. We also have a bunch of best practices settings for SSL based on cipherli.st configs
#bear in mind that the configs we use are the best we can do with the versions of openSSL and httpd that centOS/RHEL ship via epel/scl.

print_notification "Setting up httpd site config.."

#these are if/then checks that see if /etc/httpd/conf.d welcome.conf and ssl.conf exist. If they do, move them up a directory and back them up.
if [ -f /etc/httpd/conf.d/welcome.conf ]; then
	mv /etc/httpd/conf.d/welcome.conf /etc/httpd/welcome.conf.bak &>> $logfile
	error_check 'removal of welcome.conf'
	print_notification "backup available at: /etc/httpd/welcome.conf.bak"
fi

if [ -f /etc/httpd/conf.d/ssl.conf ]; then
	mv /etc/httpd/conf.d/ssl.conf /etc/httpd/ssl.conf.bak &>> $logfile
	error_check 'removal of ssl.conf'
	print_notification "backup available at: /etc/httpd/ssl.conf.bak"
fi

if [ -f /etc/httpd/conf.d/misp-ssl.conf ]; then
	print_notification "misp-ssl.conf already configured."
else
	echo "#This httpd config file was generated by autoMISP.
<VirtualHost *:80> >> /etc/httpd/conf.d/misp-ssl.conf
    ServerAdmin me@me.local
    ServerName $FQDN
    DocumentRoot /var/www/MISP/app/webroot
    <Directory /var/www/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Order allow,deny
        allow from all
    </Directory>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>
<VirtualHost *:443>
    ServerAdmin me@me.local
    ServerName $FQDN
    DocumentRoot /var/www/MISP/app/webroot
    <Directory /var/www/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Order allow,deny
        allow from all
    </Directory>
    <IfModule \!mod_php5.c>
        SetEnvIf Authorization \"(.*)\" HTTP_AUTHORIZATION=$1
        DirectoryIndex /index.php index.php
        <FilesMatch \.php$>
            SetHandler \"proxy:fcgi://127.0.0.1:9000\"
        </FilesMatch>
    </IfModule>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
    SSLEngine On
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    #This doesnt work for CentOS
    #SSLOpenSSLConfCmd Curves X25519:secp521r1:secp384r1:prime256v1
    SSLHonorCipherOrder On
    #HSTS is commented out because modern browsers wont let you go to a web page where its enabled, but you used a self-signed cert
    #Header always set Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    SSLCompression off
    #according to cipherli.st, you need to be running apache 2.4.11 to use the SessionTickets directive, and as of 9/12/19, the version string returned on my install is 2.4.6
    #SSLSessionTickets Off
    SSLUseStapling on
    #service startup bombed because of this directive, apparently RHEL/CentOS apache doesnt support this yet.	
    SSLCertificateFile /etc/pki/tls/certs/$FQDN.crt
    SSLCertificateKeyFile /etc/pki/tls/private/$FQDN.key
    LogLevel warn
    ErrorLog /var/log/httpd/misp.local_error.log
    CustomLog /var/log/httpd/misp.local_access.log combined
    ServerSignature Off
</VirtualHost>
ServerTokens Prod
#This setting has to be specified outside of the VirtualHost directive
SSLStaplingCache \"shmcb:logs/stapling-cache(150000)\"" > /etc/httpd/conf.d/misp-ssl.conf
error_check 'creation of /etc/httpd/conf.d/misp-ssl.conf'
sed -i 's#\\!mod_php5.c#!mod_php5.c#' /etc/httpd/conf.d/misp-ssl.conf
error_check 'modification of /etc/httpd/conf.d/misp-ssl.conf'
fi

#########################################
#setting up MISP config files
#have to copy the default files and change the file extensions for MISP to recognize them
#installation guidance recommends explicitly setting the file permissions and correct SELinux context for the config.php file in order to make config changes from the web UI
#we're also configuring the database.php and populating it with our configuration data.
#additionally, we're setting our default GPG key here.

print_status "Moving and configuring MISP configuration files.."
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php &>> $logfile
error_check 'bootstrap.php copy'
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php &>> $logfile
error_check 'database.php copy'
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php &>> $logfile
error_check 'core.php copy'
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php &>> $logfile
error_check 'config.php copy'

print_status "Changing permissions of config.php to allow config changes from the web UI.."
chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config/config.php &>> $logfile
error_check 'File permission changes for config.php'
chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config/config.php &>> $logfile
error_check 'SELinux changes for config.php'

echo "<?php
  class DATABASE_CONFIG {
          public \$default = array(
                  'datasource' => 'Database/Mysql',
                  //'datasource' => 'Database/Postgres',
                  'persistent' => false,
                  'host' => '$DBHOST',
                  'login' => '$DBUSER_MISP',
                  'port' => 3306, // MySQL & MariaDB
                  //'port' => 5432, // PostgreSQL
                  'password' => '$DBPASSWORD_MISP',
                  'database' => '$DBNAME',
                  'prefix' => '',
                  'encoding' => 'utf8',
          );
  }" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php &>> $logfile
error_check 'database.php configuration'

print_status "Generating default GPG key. Please be aware that you should probably replace this."
echo "%echo Generating a default key
Key-Type: default
Key-Length: $GPG_KEY_LENGTH
Subkey-Type: default
Name-Real: $GPG_REAL_NAME
Name-Comment: $GPG_COMMENT
Name-Email: $GPG_EMAIL_ADDRESS
Expire-Date: 0
Passphrase: $GPG_PASSPHRASE
# Do a commit here, so that we can later print \"done\"
%commit
%echo done" > /tmp/gen-key-script

#we can't actually check that this command has exited successfully, because it keeps exiting with code 2 as opposed to code 0, in spite of successfully generating a key.
#so to work around this, we'll check to see if secring.gpg exists.
gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script &>> $logfile
if [[  -e "$PATH_TO_MISP/.gnupg/secring.gpg" ]]; then
	print_good 'succesfully generated gpg key'
	echo "Default GPG key passphrase:$GPG_PASSPHRASE" >> /root/misp_creds
	rm -f /tmp/gen-key-script
else
	print_error 'failed to generate gpg key. Please check $logfile for more details.'
fi
gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee $PATH_TO_MISP/app/webroot/gpg.asc &>> $logfile
error_check 'gpg public key export'
chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/gpg.asc &>> $logfile
error_check 'gpg.asc file permission change'
chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.gnupg &>> $logfile
error_check 'gpg.asc selinux context change'

#########################################
#add firewall rules for httpd, and start it up via systemctl

print_status "Adding firewall rules for httpd and enabling the httpd service.."

firewall-cmd --zone=public --add-port=80/tcp --permanent &>> $logfile
error_check 'port 80 firewall-cmd addition'
firewall-cmd --zone=public --add-port=443/tcp --permanent &>> $logfile
error_check 'port 443 firewall-cmd addition'
firewall-cmd --reload &>> $logfile
error_check 'restart of firewalld'

#########################################
#Have to add a listener on port 443 to /etc/httpd/conf/httpd.conf
#Check for a backup file to restore so we don't keep munging up the httpd.conf file.
#If it exists, restore it, then use sed to add the port 443 listener.

if [ -f /etc/httpd/httpd.conf.bak ]; then
	cp /etc/httpd/httpd.conf.bak /etc/httpd/conf/httpd.conf
fi

print_status "Adding Listener on port 443 to httpd.conf.."

sed -i 's#Listen 80#Listen 80\nListen 443#' /etc/httpd/conf/httpd.conf
error_check 'httpd.conf configuration'

systemctl enable --now httpd.service &>> $logfile
error_check 'httpd startup'

#########################################
#Creating persistence for the misp workers via a systemd startup script

print_status "adding startup script for misp background workers (misp-workers.service).."

echo "[Unit]
Description=MISP background workers
After=rh-mariadb102-mariadb.service rh-redis32-redis.service rh-php72-php-fpm.service

[Service]
Type=forking
User=apache
Group=apache
ExecStart=/usr/bin/scl enable rh-php72 rh-redis32 rh-mariadb102 /var/www/MISP/app/Console/worker/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service &>> $logfile
error_check 'creation of misp-workers.service'

chmod +x /var/www/MISP/app/Console/worker/start.sh &>> $logfile
error_check 'execute permission change for /app/Console/worker/start.sh'
systemctl daemon-reload &>> $logfile
error_check 'daemon-reload for misp-workers.service'
systemctl enable --now misp-workers.service &>> $logfile
error_check 'misp-workers startup'

#########################################
#Adding in misp-modules, creating persistence for the misp-modules service

print_status "Installing and configuring MISP modules.."

chmod 2777 /usr/local/src &>> $logfile
error_check 'file permission change for /usr/local/src'
chown root:users /usr/local/src &>> $logfile
error_check 'file ownership change for /usr/local/src'
cd /usr/local/src/ &>> $logfile
$SUDO_WWW git clone https://github.com/MISP/misp-modules.git &>> $logfile
error_check 'download of misp-modules'
cd misp-modules &>> $logfile

$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U -I -r REQUIREMENTS &>> $logfile
error_check 'pip requirement installation for misp-modules'
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U . &>> $logfile
error_check 'pip install of misp-modules'

#This is necessary for misp-modules to actually start and parse the arguments.
#I have no idea why, but trying to pass misp-modules arguments directly via the ExecStart systemd directive
#Causes it to vomit, and refuse to recognize its own arguments. Passing its arguments as a variable seems to work
#So we put the arugments into a file as the "ARG1" variable, and pass that variable as part of the ExecStart directive 
print_status "adding arguments to /var/www/MISP/venv/bin/.misp-modules-args.."
echo "ARG1=-l 127.0.0.1 -s" > $PATH_TO_MISP/venv/bin/.misp-modules-args
error_check 'misp-module argument file creation'

echo "[Unit]
Description=MISP modules
After=misp-workers.service

[Service]
Type=simple
User=apache
Group=apache
WorkingDirectory=/usr/local/src/misp-modules
Environment="PATH=$PATH_TO_MISP/venv/bin"
EnvironmentFile=$PATH_TO_MISP/venv/bin/.misp-modules-args
ExecStart=$PATH_TO_MISP/venv/bin/misp-modules \$ARG1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-modules.service &>> $logfile
error_check 'creation of misp-modules.service'
systemctl daemon-reload &>> $logfile
error_check 'daemon-reload for misp-modules.service'
systemctl enable --now misp-modules &>> $logfile
error_check 'misp-modules startup'

#########################################
#making a bunch of config changes here.
#these commands all run PHP, and start up CakePHP and use setSetting to set a bunch of MISP app directives.
#the first set of commands are for enrichment timeouts.
#The second set are to enable a bunch of enrichment options.
#The third set is to enable a bunch of import module options.
#The fourth set is related to export module options.
print_status "Running CakePHP setSetting to make some config changes.."

print_notification "Setting better enrichment timeouts.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true &>> $logfile
error_check 'timeout setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true &>> $logfile
error_check 'timeout setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300 &>> $logfile
error_check 'timeout setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150 &>> $logfile
error_check 'timeout setSetting command 4 (of 4)'

print_notification "Enabling a a bunch of enrichment options.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true &>> $logfile
error_check 'enrichment setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true &>> $logfile
error_check 'enrichment setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_btc_steroids_enabled" true &>> $logfile
error_check 'enrichment setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_ipasn_enabled" true &>> $logfile
error_check 'enrichment setSetting command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_yara_syntax_validator_enabled" true &>> $logfile
error_check 'enrichment setSetting command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_yara_query_enabled" true &>> $logfile
error_check 'enrichment setSetting command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_pdf_enabled" true &>> $logfile
error_check 'enrichment setSetting command 7'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_docx_enabled" true &>> $logfile
error_check 'enrichment setSetting command 8'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_xlsx_enabled" true &>> $logfile
error_check 'enrichment setSetting command 9'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_pptx_enabled" true &>> $logfile
error_check 'enrichment setSetting command 10'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_ods_enabled" true &>> $logfile
error_check 'enrichment setSetting command 11'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_odt_enabled" true &>> $logfile
error_check 'enrichment setSetting command 12'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1" &>> $logfile
error_check 'enrichment setSetting command 13'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666 &>> $logfile
error_check 'enrichment setSetting command 14 (of 14)'

print_notification "Enabling a bunch of import module options and setting better timeouts for them.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_enable" true &>> $logfile
error_check 'import options setSettings command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1" &>> $logfile
error_check 'import options setSettings command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_port" 6666 &>> $logfile
error_check 'import options setSettings command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_timeout" 300 &>> $logfile
error_check 'import options setSettings command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true &>> $logfile
error_check 'import options setSettings command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_mispjson_enabled" true &>> $logfile
error_check 'import options setSettings command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_openiocimport_enabled" true &>> $logfile
error_check 'import options setSettings command 7'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_threatanalyzer_import_enabled" true &>> $logfile
error_check 'import options setSettings command 8'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true &>> $logfile
error_check 'import options setSettings command 9 (of 9)'

print_notification "Enabling a bunch of export module options and setting better timeouts.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_enable" true &>> $logfile
error_check 'export options setSettings command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1" &>> $logfile
error_check 'export options setSettings command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_port" 6666 &>> $logfile
error_check 'export options setSettings command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_timeout" 300 &>> $logfile
error_check 'export options setSettings command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true &>> $logfile
error_check 'export options setSettings command 5 (of 5)'

#########################################
#Setting core MISP settings via CakePHP setSettings
#The first command initializes MISP users
#The second tells MISP to update its database structure
#The third tells MISP where to find the python binary to execute python stuff.
print_status "Configuring MISP core settings.."

print_notification "running userinit, updating database, and setting the path to the python binary.."
$SUDO_WWW $RUN_PHP -- $CAKE userInit -q &>> $logfile
error_check 'userinit command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateDatabase &>> $logfile
error_check 'updateDatabase command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python" &>> $logfile
error_check 'python setSetting command'

#This set of commands reconfigures global web application timeout settings.
print_notification "Editing Session timeout settings.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.autoRegenerate" 0 &>> $logfile
error_check 'session timeout setSettings command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.timeout" 600 &>> $logfile
error_check 'session timeout setSettings command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.cookieTimeout" 3600 &>> $logfile
error_check 'session timeout setSettings command 3 (of 3)'

#These settings related to the MISP BASEURL configuration
print_notification "Setting MISP BaseURL.."
$SUDO_WWW $RUN_PHP -- $CAKE Baseurl $MISP_BASEURL &>> $logfile
error_check 'BaseURL setSettings command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.external_baseurl" $MISP_BASEURL &>> $logfile
error_check 'BaseURL setSettings command 2'

#these settings are to tell MISP where the GPG stuff is. Kinda useless to set this because we aren't enabling E-mail, but this is fine.
print_notification "Setting GPG setSetting options.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.email" "$GPG_EMAIL_ADDRESS" &>> $logfile
error_check 'GPG setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.homedir" "$PATH_TO_MISP/.gnupg" &>> $logfile
error_check 'GPG setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.password" "$GPG_PASSPHRASE" &>> $logfile
error_check 'GPG setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.binary" "$(which gpg)" &>> $logfile
error_check 'GPG setSetting command 4 (of 4)'

#Installer organization, settings for email, correlations, etc.
print_notification "Setting installer org and some interface tunables.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.host_org_id" 1 &>> $logfile
error_check 'tunable setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.email" "info@admin.test" &>> $logfile
error_check 'tunable setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disable_emailing" true &>> $logfile
error_check 'tunable setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.contact" "info@admin.test" &>> $logfile
error_check 'tunable setSetting command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disablerestalert" true &>> $logfile
error_check 'tunable setSetting command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true &>> $logfile
error_check 'tunable setSetting command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.default_event_tag_collection" 0 &>> $logfile
error_check 'tunable setSetting command 7 (of 7)'

#These are cortex configuration options
print_notification "Setting some configs to make Cortex integration easier.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_enable" false &>> $logfile
error_check 'Cortex setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1" &>> $logfile
error_check 'Cortex setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000 &>> $logfile
error_check 'Cortex setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_timeout" 120 &>> $logfile
error_check 'Cortex setSetting command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_authkey" "" &>> $logfile
error_check 'Cortex setSetting command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false &>> $logfile
error_check 'Cortex setSetting command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false &>> $logfile
error_check 'Cortex setSetting command 7'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true &>> $logfile
error_check 'Cortex setSetting command 8 (of 8)'

#These are settings for plugin sightings
print_notification "Setting some configs for plugin sightings.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_policy" 0 &>> $logfile
error_check 'Plugin sightings setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_anonymise" false &>> $logfile
error_check 'Plugin sightings setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_range" 365 &>> $logfile
error_check 'Plugin sightings setSetting command 3'

#This is a CustomAuth tunable for plugins
print_notification "Setting plugin CustomAuth disable logout to false"
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false &>> $logfile
error_check 'Plugin CustomAuth setSetting command'

print_notification "Configuring RPZ.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP" &>> $logfile
error_check 'RPZ setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1" &>> $logfile
error_check 'RPZ setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00" &>> $logfile
error_check 'RPZ setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h" &>> $logfile
error_check 'RPZ setSetting command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_retry" "30m" &>> $logfile
error_check 'RPZ setSetting command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d" &>> $logfile
error_check 'RPZ setSetting command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h" &>> $logfile
error_check 'RPZ setSetting command 7'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w" &>> $logfile
error_check 'RPZ setSetting command 8'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost." &>> $logfile
error_check 'RPZ setSetting command 9'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ns_alt" "" &>> $logfile
error_check 'RPZ setSetting command 10'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost" &>> $logfile
error_check 'RPZ setSetting command 11 (of 11)'

#these are configuration settings to enable redis support
print_notification "Configuring support for redis.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1" &>> $logfile
error_check 'Redis setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_port" 6379 &>> $logfile
error_check 'Redis setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_database" 13 &>> $logfile
error_check 'Redis setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_password" "" &>> $logfile
error_check 'Redis setSetting command 4 (of 4)'

#These are settings to make MISP a little less angry (red and yellow) on first start
print_notification "Setting some MISP tunables to clear some red/yellow alerts on the status page.."
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.language" "eng" &>> $logfile
error_check 'MISP tunable setSetting command 1'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.proposals_block_attributes" false &>> $logfile
error_check 'MISP tunable setSetting command 2'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Security.password_policy_length" 12 &>> $logfile
error_check 'MISP tunable setSetting command 3'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/' &>> $logfile
error_check 'MISP tunable setSetting command 4'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40 &>> $logfile
error_check 'MISP tunable setSetting command 5'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.extended_alert_subject" false &>> $logfile
error_check 'MISP tunable setSetting command 6'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.default_event_threat_level" 4 &>> $logfile
error_check 'MISP tunable setSetting command 7'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.enableEventBlacklisting" true &>> $logfile
error_check 'MISP tunable setSetting command 8'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true &>> $logfile
error_check 'MISP tunable setSetting command 9'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.log_client_ip" false &>> $logfile
error_check 'MISP tunable setSetting command 10'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.log_auth" false &>> $logfile
error_check 'MISP tunable setSetting command 11'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disableUserSelfManagement" false &>> $logfile
error_check 'MISP tunable setSetting command 12'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_event_alert" false &>> $logfile
error_check 'MISP tunable setSetting command 13'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\"" &>> $logfile
error_check 'MISP tunable setSetting command 14'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_old_event_alert" false &>> $logfile
error_check 'MISP tunable setSetting command 15'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_old_event_alert_age" "" &>> $logfile
error_check 'MISP tunable setSetting command 16'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false &>> $logfile
error_check 'MISP tunable setSetting command 17'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.maintenance_message" "Great things are happening! MISP is undergoing maintenance, but will return shortly." &>> $logfile
error_check 'MISP tunable setSetting command 18'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.attachments_dir" "$PATH_TO_MISP/app/files" &>> $logfile
error_check 'MISP tunable setSetting command 19'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.download_attachments_on_load" true &>> $logfile
error_check 'MISP tunable setSetting command 20'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.title_text" "MISP" &>> $logfile
error_check 'MISP tunable setSetting command 21'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.terms_download" false &>> $logfile
error_check 'MISP tunable setSetting command 22'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.showorgalternate" false &>> $logfile
error_check 'MISP tunable setSetting command 23'
$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.event_view_filter_fields" "id, uuid, value, comment, type, category, Tag.name" &>> $logfile
error_check 'MISP tunable setSetting command 24 (of 24)'

print_notification "Running commands to update Galaxies, Taxonomies, Warning Lists, Notice Lists and Object templates (this may take a while).."
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateGalaxies &>> $logfile
error_check 'Galaxy update command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateTaxonomies &>> $logfile
error_check 'Taxonomy update command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateWarningLists &>> $logfile
error_check 'Warning list update command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateNoticeLists &>> $logfile
error_check 'Notice list update command'
$SUDO_WWW $RUN_PHP -- $CAKE Admin updateObjectTemplates "1337" &>> $logfile
error_check 'Object Template update command'

print_notification "Setting MISP to live.."
$SUDO_WWW $RUN_PHP -- $CAKE Live $MISP_LIVE &>> $logfile
error_check 'MISP live command'

print_status "MISP should be successfully installed."
print_notification "Default creds: admin@admin.test//admin"
print_notification "Don't forget that the creds for the misp system user, misp database user, and the root database user are in /root/misp_creds, and are only readable by the root user."
print_notification "I'd recommend copying the credentials for these users into a password manager of some sort, and deleting the file."
print_notification "The logs for this installation are in/var/log/misp_install.log"
print_notification "Due to the nature of several of the commands entered and the way my janky loggin works, credentials MAY have been saved to the log file. I would recommend archiving it with tighter file permissions, or deleting the file altogether if you no longer have use for it."
print_notification "While we're talking about files to delete, you may want to delete this script when you are done."
exit 0
