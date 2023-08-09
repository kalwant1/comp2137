#!/bin/bash
lannetnum="192.168.16"
mgmtnetnum="172.16.1"
prefix=server
startinghostnum=10
remoteadmin="remoteadmin"
numcontainers=1
puppetinstall=no
verbose=yes

source /etc/os-release

function echoverbose {
    [ "$verbose" = "yes" ] && echo "$@"
}

#define functions for help display and error messages
# This function will send an error message to stderr
# Usage:
#   error-message ["some text to print to stderr"]
#
function error-message {
  local prog
  prog="$(basename '$0')"
  echo "${prog}: ${1:-Unknown Error - a moose bit my sister once...}" >&2
}

# This function will send a message to stderr and exit with a failure status
# Usage:
#   error-exit ["some text to print" [exit-status]]
#
function error-exit {
  error-message "$1"
  exit "${2:-1}"
}

# allow choices on the command line
while [ $# -gt 0 ]; do
    case "$1" in
        --help | -h )
            echo "
Usage: $(basename "$0") [-h | --help] [--fresh] [--prefix targetnameprefix] [--user remoteadminaccountname] [--lannet A.B.C] [--mgmtnet A.B.C] [--count N] [--hostnumbase N] [--puppetinstall]
This script sets up a private network using containers in a Ubuntu hosting machine for educational purposes.
It has an OpenWRT router connecting the hosting OS lan to its wan interface, and 2 virtual networks called lan and mgmt on additional interfaces.
Will install and initialize lxd if necessary.
Will create lan and mgmt virtual networks if necessary using host 2 on each network for the router, both using /24 mask.
Will create openwrt router with lxdbr0 for WAN, lan for lan, and mgmt for private management network.
Creates target containers, named using target name prefix with the container number appended.
Creates a remote admin account with sudo privilege, no passwd access, and ssh access for the user who runs this script.
Adds host names with IP addresses to /etc/hosts inside the containers and in the hosting OS.
The hosting OS will have direct access to all the virtual networks using host number 1.
Can install Puppet tools.
Defaults
fresh:         false
prefix:        server
user:          remoteadmin
lannet:        192.168.16
mgmtnet:       172.16.1
hostnumbase:   10
count:         1
puppetinstall: no
"
#!/bin/bash
# This script creates a virtual network suitable for learning about networking
# created by dennis simpson 2023, all rights reserved

lannetnum="192.168.16"
mgmtnetnum="172.16.1"
prefix=server
startinghostnum=10
remoteadmin="remoteadmin"
numcontainers=1
puppetinstall=no
verbose=yes

source /etc/os-release

function echoverbose {
    [ "$verbose" = "yes" ] && echo "$@"
}


DOCKERS=( docker-edgex-volume docker-core-consul core-config-seed docker-edgex-mongo support-logging \
    support-notifications core-metadata core-data core-command support-scheduler \
    support-rulesengine device-virtual device-bacnet device-bluetooth device-modbus device-mqtt device-snmp)

DOCKERFILE=$1

usage(){
    echo -e "ERROR! Dockerfile name not found."
    echo -e "\tI.E: ./${0} Dockerfile.aarch64"
    exit
}


if [[ -z ${DOCKERFILE} ]]; then
    usage
fi

for m in ${DOCKERS[@]} ;  do
    if [ -d $m ]; then
        echo "Updating git modules... "
        cd $m
        git pull
        cd ..
    else
        echo "Cloning $m"
        git clone https://github.com/edgexfoundry/$m
    fi
    if [ -f $m/docker-files/${DOCKERFILE} ] ; then
        echo "Creating docker image $m"
        cd $m
        docker build . -t edgexfoundry/docker-$m -f docker-files/${DOCKERFILE}
        echo $m
        cd ..

    elif [ -f $m/${DOCKERFILE} ] ; then
        echo "Creating docker image $m"
        cd $m
        docker build . -t edgexfoundry/$m -f ${DOCKERFILE}
        echo $m
        cd ..
    else
        usage
    fi
done


echo "Done!"

            exit
            ;;
        --puppetinstall )
            puppetinstall=yes
            ;;
        --fresh )
	    targets=$(lxc list|grep -o -w "$prefix".)
            echoverbose "Deleting any existing target containers"
            for target in $targets; do
                lxc delete "$target" --force
            done
            echoverbose "Deleting any existing openwrt container"
            lxc delete openwrt --force
            lxc network delete lan
            lxc network delete mgmt
            ;;
        --prefix )
            if [ -z "$2" ]; then
                error-exit "Need a hostname prefix for the --prefix option"
            else
                prefix="$2"
                shift
            fi
            ;;
        --user )
            if [ -z "$2" ]; then
                error-exit "Need a username for the --user option"
            else
                remoteadmin="$2"
                shift
            fi
            ;;
        --lannet )
            if [ -z "$2" ]; then
                error-exit "Need a network number in the format N.N.N for the --lannet option"
            else
                lannetnum="$2"
                shift
            fi
            ;;
        --mgmtnet )
            if [ -z "$2" ]; then
                error-exit "Need a network number in the format N.N.N for the --mgmtnet option"
            else
                mgmtnetnum="$2"
                shift
            fi
            ;;
        --count )
            if [ -z "$2" ]; then
                error-exit "Need a number for the --count option"
            else
                numcontainers="$2"
                shift
            fi
            ;;
        --hostnumbase )
            if [ -z "$2" ]; then
                error-exit "Need a number for the --hostnumbase option"
            else
                startinghostnum="$2"
                shift
            fi
            ;;
    esac
    shift
done

echo "Checking for sudo"
[ "$(id -u)" -eq 0 ] && error-exit "Do not run this script using sudo, it will use sudo when it needs to"
sudo echo "sudo access ok" || exit 1
echoverbose "Adding hostvm to /etc/loghosts file if necessary"
sudo sed -i -e '/ hostvm$/d' -e '$a'"$lannetnum.1 hostvm" /etc/hosts
sudo sed -i -e '/ hostvm-mgmt$/d' -e '$a'"$mgmtnetnum.1 hostvm-mgmt" /etc/hosts
echoverbose "Adding openwrt to /etc/hosts file if necessary"
sudo sed -i -e '/ openwrt$/d' -e '$a'"$lannetnum.2 openwrt" /etc/hosts
sudo sed -i -e '/ openwrt-mgmt$/d' -e '$a'"$mgmtnetnum.2 openwrt-mgmt" /etc/hosts

# install puppet if necessary, includes bolt install
if [ "$puppetinstall" = "yes" ]; then
    if ! systemctl is-active --quiet puppetserver 2>/dev/null; then
        [ -f ~/Downloads/puppet8-release-focal.deb ] ||
            wget -q -O ~/Downloads/puppet8-release-focal.deb https://apt.puppet.com/puppet8-release-focal.deb
        [ -f ~/Downloads/puppet8-release-focal.deb ] || error-exit "Failed to download puppet8 focal apt setup"
        sudo DEBIAN_FRONTEND=noninteractive dpkg -i ~/Downloads/puppet8-release-focal.deb || error-exit "Failed to dpkg install puppet8-release-focal.deb"
        sudo apt-get -qq update || error-exit "Failed apt update"
        sudo NEEDRESTART_MODE=a apt-get -y install puppetserver >/dev/null || error-exit "Failed to apt install puppetserver"
        sudo systemctl start puppetserver || error-exit "Failed to start puppetserver"
        sudo grep -q 'PATH=$PATH:/opt/puppetlabs/bin' /root/.bashrc || sudo sed -i '$aPATH=$PATH:/opt/puppetlabs/bin' /root/.bashrc
    fi
    echoverbose "Ensuring ${prefix}1 apache2 install manifests are present"
    puppetmanifestsdir=/etc/puppetlabs/code/environments/production/manifests
    puppetinitfile="$puppetmanifestsdir/init.pp"
    puppetsitefile="$puppetmanifestsdir/site.pp"
    sudo chgrp student "$puppetmanifestsdir"
    sudo chmod g+w "$puppetmanifestsdir"
    [ -f "$puppetinitfile" ] || cat > "$puppetinitfile" <<EOF
class webserver {
  package { 'apache2': ensure => 'latest', }
  service { 'apache2':
    ensure => 'running',
    enable => true,
    require => Package['apache2'],
  }
#!/bin/bash
# This script creates a virtual network suitable for learning about networking
# created by dennis simpson 2023, all rights reserved

lannetnum="192.168.16"
mgmtnetnum="172.16.1"
prefix=server
startinghostnum=10
remoteadmin="remoteadmin"
numcontainers=1
puppetinstall=no
verbose=yes

source /etc/os-release

function echoverbose {
    [ "$verbose" = "yes" ] && echo "$@"
{
class logserver {
  package { 'rsyslog': ensure => 'latest', }
  package { 'logwatch': ensure => 'latest', }
  service { 'rsyslog':
    ensure => 'running',
    enable => true,
    require => Package['rsyslog'],
}
_logfile=/var/log/${_filename}/${_filename}.log
_pidfile=/tmp/${_filename}.pid
_WAFfile=/var/log/${_filename}/${_filename}.WAF.var
_nvme_namespacefile=/var/log/${_filename}/${_filename}.nvmenamespace.var
_VUsmart_F4_beforefile=/var/log/${_filename}/${_filename}.F4_before.var
_VUsmart_F5_beforefile=/var/log/${_filename}/${_filename}.F5_before.var
_db_not_supported="not logged"

function check_command() {
	# Iterate over all function arguments and check if each argument is an installed command
	while [ $# -gt 0 ] ; do
		# check if a passed argument is an installed command
		if ! command -v "$1" &> /dev/null ; then
			log "[CHECKCOMMAND] Command $1 could not be found"
			# exit the script with error code 1 
			exit 1
		fi
		shift
	done
	return 0
}

function check_nvme_namespace() {
	# Fuction returns true if argument is an existing nvme device namespace
	# argument 1: a namespace
	local _nvme_namespace=$1
	local _ret

	if [[ ${_nvme_namespace} =~ ^nvme[0-9]+n[0-9]+$ ]] ; then
		_ret=$(nvme list 2>/dev/null  | grep "${_nvme_namespace}" 2>&1 >/dev/null)
		# assign the return value of grep to the varialbe ret
		_ret=$?
		if [[ ${_ret} -eq 0 ]] ; then
			# grep returned 0 as it found ${_nvme_namespace}
			log "[CHECKNVMENAMESPACE] nvme device ${_nvme_namespace} exists"
		elif [[ ${_ret} -eq 1 ]] ; then
			# grep returned 1 as it did not find ${_nvme_namespace}
			log "[CHECKNVMENAMESPACE] nvme device does not exist"
			return 1
		else
			log "[CHECKNVMENAMESPACE] grep returned error"
			return 1
		fi
	else
		log "[CHECKNVMENAMESPACE] Bad device name"
		return 1
	fi
	return 0
}

function send_to_db() {
	# Function will send to content of the argument to a database as configured in the global variable _db
	# Supported databases defined in _db
	#	graphite
	#	logfile
	# argument 1: data to be sent
	local _data=$1

	if [ "${_db}" = "graphite" ] ; then
		# send the data to the graphite port and destination
		echo "${_data}" | nc -N ${_nc_graphite_destination} ${_nc_graphite_port}
	elif [ "${_db}" = "logfile" ] ; then
		# send the data the log file
		echo "${_data}"
	elif [ "${_db_not_supported}" != "logged" ] ; then
		# variable _db does not contain a supported database
		# send once the the error to the log file
		_db_not_supported="logged"
		log "[SENDTODB] ${_db} as database is not supported"
	fi
	return 0
}

function get_smart_log() {
	# Function will return the smart log info for the nvme device at an offset
	# argument 1: nvme device
	# argument 2: offset 
	local _local_nvme_namespace=$1
	local _offset=$2
	local _rev_vusmart_hexadecimal

	# get Vendor Unique smart attributes in binary format, get 6 bytes from possition _offset and remove position.
	_vusmart_hexadecimal=$(nvme intel smart-log-add /dev/"${_local_nvme_namespace}" -b | xxd -l 6 -seek "${_offset}" | cut -c 11-19 | sed 's/ //g')
	# reverse the varialbe _vusmart_hexadecimal
	len=${#_vusmart_hexadecimal}
	for((i=len;i>=0;i=i-2)); do _rev_vusmart_hexadecimal="$_rev_vusmart_hexadecimal${_vusmart_hexadecimal:$i:2}"; done
	# convert _vusmart_hexadecimal to capital letter, convert to decimal and remove leading zeros
	_vusmart_decimal=$(echo "ibase=16;${_rev_vusmart_hexadecimal^^}" | bc )
	echo "${_vusmart_decimal}"
	return 0
}

function loop() {
	local _counter=0
	local _hostWrites=1
	local _nandWrites=0
	local _read_bandwidth=0
	local _write_bandwidth=0
	local _readblocks_old=0
	local _writeblocks_old=0
	local _readblocks_new=0
	local _writeblocks_new=0
	local _nvme_namespace=$1

	eval "$(awk '{printf "_readblocks_old=\"%s\" _writeblocks_old=\"%s\"", $3 ,$7}' < /sys/block/"${_nvme_namespace}"/stat)"
	while true; do
		if ! ((_counter % 60)) ; then
			# this block will run every minute
			_VUsmart_E2=$(get_smart_log "${_nvme_namespace}" 0x41)
			_VUsmart_E3=$(get_smart_log "${_nvme_namespace}" 0x4d)
			_VUsmart_E4=$(get_smart_log "${_nvme_namespace}" 0x59)
			_VUsmart_F4=$(get_smart_log "${_nvme_namespace}" 0x89)
			_VUsmart_F5=$(get_smart_log "${_nvme_namespace}" 0x95)
			_media_wear_percentage=$(echo "scale=3;${_VUsmart_E2}/1024" | bc -l)
			send_to_db "smart.media_wear_percentage ${_media_wear_percentage} $(date +%s)"
			send_to_db "smart.host_reads ${_VUsmart_E3} $(date +%s)"
			send_to_db "smart.timed_work_load ${_VUsmart_E4} $(date +%s)"
			_VUsmart_F4_before=$(cat "${_VUsmart_F4_beforefile}")
			_VUsmart_F5_before=$(cat "${_VUsmart_F5_beforefile}")
			if [[ "${_VUsmart_F4_before}" -eq 0 ]]; then
				_VUsmart_F4_before=${_VUsmart_F4}
				echo "${_VUsmart_F4_before}" > "${_VUsmart_F4_beforefile}"
				_VUsmart_F5_before=${_VUsmart_F5}
				echo "${_VUsmart_F5_before}" > "${_VUsmart_F5_beforefile}"
			fi
			if [[ "${_VUsmart_F5}" -eq "${_VUsmart_F5_before}" ]] ; then
				_hostWrites=1
				_nandWrites=0
			else
				_hostWrites=${_VUsmart_F5}-${_VUsmart_F5_before}
				_nandWrites=${_VUsmart_F4}-${_VUsmart_F4_before}
			fi
			_WAF=$(echo "scale=2;(${_nandWrites})/(${_hostWrites})" | bc -l)
			send_to_db "smart.write_amplicifation_factor ${_WAF} $(date +%s)"
			echo "${_WAF}" > "${_WAFfile}"
			# log host write bytes
			send_to_db "smart.host_bytes_written $(echo "${_VUsmart_F5}*32" | bc -l) $(date +%s)"
			# log smart attributes
			_temperature=$(nvme smart-log /dev/"${_nvme_namespace}" 2>stderr | grep temperature | awk '{print $3}')
			send_to_db "smart.temperature ${_temperature} $(date +%s)"
			_percentage_used=$(nvme smart-log /dev/"${_nvme_namespace}" 2>stderr | grep percentage_used | awk '{print $3}' | cut -c -1)
			send_to_db "smart.percentage_used ${_percentage_used} $(date +%s)"
			
			echo "$(date +%s), ${_VUsmart_E2}, ${_VUsmart_E3}, ${_VUsmart_E4}, ${_VUsmart_F4}, ${_VUsmart_F5}, ${_WAF}, ${_temperature}, ${_percentage_used}"
			_counter=0
		fi
		# this block will run every second
		eval "$(awk '{printf "_readblocks_new=\"%s\" _writeblocks_new=\"%s\"", $3 ,$7}' < /sys/block/"${_nvme_namespace}"/stat)"
		_read_bandwidth=$(echo "(${_readblocks_new}-${_readblocks_old})*512/1000/1000" | bc)
		_write_bandwidth=$(echo "(${_writeblocks_new}-${_writeblocks_old})*512/1000/1000" | bc)
		_readblocks_old=${_readblocks_new}
		_writeblocks_old=${_writeblocks_new}

		# add read and write bandwidth to TimeSeriesDataBase
		send_to_db "nvme.readBW ${_read_bandwidth} $(date +%s)"
		send_to_db "nvme.writeBW ${_write_bandwidth} $(date +%s)"

		_counter=$(( _counter + 1 ))
		sleep 1
	done
	return 0
}

function log() {
	echo "$*"
	return 0
}

function retrieve_pid() {
	# echo the process id of the running background process
	# if not running echo 0 as 0 is an invalid pid
	local _pid

	if [ -s "${_pidfile}" ] ; then
		# file ${_pid} is not empty
		_pid=$(cat "${_pidfile}")
		if ps -p "${_pid}" > /dev/null 2>&1 ; then 
			# ${_pid} is running process
			echo "${_pid}"
		else
			# ${_pid} is not a process id or not a ruunning process
			echo 0
		fi
	else
		# file ${_pid} is empty
		echo 0
	fi
	return 0
}

function retrieve_nvme_namespace() {
	# echo the namespace reriteved from the file ${_nvme_namespacefile}
	# only returns the namespace when it exists in the system 
	# if an error found retrun an empty string
	if [ -s "${_nvme_namespacefile}" ] ; then
		# the file ${_nvme_namespacefile} exists
		_nvme_namespace=$(cat "${_nvme_namespacefile}")
		if [[ ${_nvme_namespace} =~ ^nvme[0-9]+n[0-9]+$ ]] ; then
			_ret=$(nvme list 2>/dev/null  | grep "${_nvme_namespace}" 2>&1 >/dev/null)
			# assign the return value of grep to the varialbe ret
			_ret=$?
			if [[ ${_ret} -eq 0 ]] ; then
			# grep returned 0 as it found ${_nvme_namespace}
				echo "${_nvme_namespace}"
			elif [[ ${_ret} -eq 1 ]] ; then
				# grep returned 1 as it did not find ${_nvme_namespace}
				echo ""
			else
				# grep return an error
				echo ""
			fi
		else
			echo ""
		fi
	else
		# the file ${_nvme_namespacefile} does not exists
		echo ""
	fi

	return 0
}

function status() {
	local _pid
	
	_pid=$(retrieve_pid)

	if [[ "${_pid}" -gt 0 ]] ; then
		# background process running
		log "[STATUS] Service ${_service} with pid=${_pid} running"
		return 0
	else
		# background process not running
		log "[STATUS] Service ${_service} not running"
		return 1
	fi
}

function start() {
	local _pid
	local _nvme_namespace
	
	if status >/dev/null 2>&1 ; then
		# background process running
		_pid=$(retrieve_pid)
		log "[START] ${_service} with pid ${_pid} is already running"
	else
		# background process not running
		if [ -s "${_nvme_namespacefile}" ] ; then
			_nvme_namespace=$(retrieve_nvme_namespace)
			if [ "${_nvme_namespace}" == "" ] ; then
				log "[START] Invalid nvme namespce parameter."
				return 1
			else
				log "[START] Logging namespace ${_nvme_namespace}. Log filename ${_logfile}"
				log "[START} ${_nvme_namespacefile} exists and namespace=${_nvme_namespace}"
				if [ -s "${_VUsmart_F4_beforefile}" ] ; then
					_VUsmart_F4_before=$(cat "${_VUsmart_F4_beforefile}")
				else
					_VUsmart_F4_before=0
					echo ${_VUsmart_F4_before} > "${_VUsmart_F4_beforefile}"
				fi

				if [ -s "${_VUsmart_F5_beforefile}" ] ; then
					_VUsmart_F5_before=$(cat "${_VUsmart_F5_beforefile}")
				else
					_VUsmart_F5_before=0
					echo ${_VUsmart_F5_before} > "${_VUsmart_F5_beforefile}"
				fi

				(loop "${_nvme_namespace}" >> "${_logfile}" 2>>"${_logfile}") &
				# write process id to file
				echo $! > "${_pidfile}"

				# check if backgournd process is running
				if ! status ; then 
					log "[START] ${_service} failed to start"
					rm "${_pidfile}"
					return 1
				fi
			fi
		else
			log "[START] ${_nvme_namespacefile} is empty"
			log "[START] Not started, need to set device first"
			log "[START] e.g. $_service setDevice nvme0n1"
			return 1
		fi
	fi
	return 0
}

function stop() {
	local _pid
	
	_pid=$(retrieve_pid)

	if [[ "${_pid}" -gt 0 ]] ; then
		# background process running
		log "[STOP] Stopping ${_service} with pid=${_pid}"
		kill "${_pid}"
		log "[STOP] kill signal sent to pid=${_pid}"
		rm "${_pidfile}"
		return 0
	else
		# ${_pid} is 0, no background process running
		log "[STOP] Service ${_service} not running"
		return 1
	fi
}

function restart() {
	stop
	start
	return 0
}

function resetWorkloadTimer() {
	local _nvme_device
	local _nvme_namespace
	
	if status >/dev/null 2>&1 ; then
		# background process running
		_nvme_namespace=$(retrieve_nvme_namespace)
		if [ "${_nvme_namespace}" == "" ] ; then
			log "[RESETWORKLOADTIMER] Invalid nvme namespce parameter. Workload Timer not reset."
			return 1
		fi
		_nvme_device=${_nvme_namespace/%n[0-9]*/} 
		nvme set-feature -f 0xd5 -v 1 /dev/"${_nvme_device}" > /dev/null 2>&1
		log "[RESETWORKLOADTIMER] Workload Timer Reset on ${_nvme_device} at $(date)"

		echo 0 > "${_VUsmart_F4_beforefile}"
		echo 0 > "${_VUsmart_F5_beforefile}"
		echo 0 > "${_WAFfile}"
		return 0
	else	
		# background process not running
		log "[RESETWORKLOADTIMER] ${_service} is not running. Workload Timer not reset."
		return 1
	fi
}

function WAFinfo() {
	local _nvme_namespace
	local _WAF
	local _market_name
	local _serial_number
	local _tnvmcap
	local _VUsmart_E2
	local _VUsmart_E3
	local _VUsmart_E4
	local _media_wear_percentage
	
	if status >/dev/null 2>&1 ; then
		# background process running
		_nvme_namespace=$(retrieve_nvme_namespace)
		if [ "${_nvme_namespace}" == "" ] ; then
			log "[WAFINFO] Invalid nvme namespce parameter."
			return 1
		fi
		_WAF=$(cat "${_WAFfile}")
		_market_name="$(nvme get-log /dev/"${_nvme_namespace}" -i 0xdd -l 0x512 -b 2>&1 | tr -d '\0')"
		_serial_number=$(nvme id-ctrl /dev/"${_nvme_namespace}" 2>stderr | grep sn | awk '{print $3}')
		_tnvmcap=$(nvme id-ctrl /dev/"${_nvme_namespace}" 2>stderr | grep tnvmcap | awk '{print $3}')
		_VUsmart_E2=$(get_smart_log "${_nvme_namespace}" 0x41)
		_VUsmart_E3=$(get_smart_log "${_nvme_namespace}" 0x4d)
		_VUsmart_E4=$(get_smart_log "${_nvme_namespace}" 0x59)
	
		echo "Drive                            : ${_market_name} $((_tnvmcap/1000/1000/1000))GB"
		echo "Serial number                    : ${_serial_number}"
		echo "Device                           : /dev/${_nvme_namespace}"	
		echo "smart.write_amplification_factor : ${_WAF}"
		if [[ ${_VUsmart_E4} -eq 65535 ]] ; then 
			echo "smart.media_wear_percentage      : Not Available yet"
			echo "smart.host_reads                 : Not Available yet"
			echo "smart.timed_work_load            : less than 60 minutes"
		else
			if [[ ${_VUsmart_E2} -eq 0 ]] ; then
				echo "smart.media_wear_percentage      : <0.001%"
				echo "smart.host_reads                 : ${_VUsmart_E3}%"
				echo "smart.timed_work_load            : ${_VUsmart_E4} minutes"
				echo "Drive life                       : smart.media_wear_percentage to small to calculate Drive life"
			else
				_media_wear_percentage=$(echo "scale=3;${_VUsmart_E2}/1024" | bc -l)
				_drive_life_minutes=$(echo "scale=0;${_VUsmart_E4}*100*1024/${_VUsmart_E2}" | bc -l)
				_drive_life_years=$(echo "scale=3;${_drive_life_minutes}/525600" | bc -l)
				echo "smart.media_wear_percentage      : ${_media_wear_percentage/#./0.}%"
				echo "smart.host_reads                 : ${_VUsmart_E3}%"
				echo "smart.timed_work_load            : ${_VUsmart_E4} minutes"
				echo "Drive life                       : ${_drive_life_years/#./0.} years (${_drive_life_minutes} minutes)"
			fi
		fi
		return 0
	else
		# background process not running
		log "[WAFINFO] ${_service} is not running."
		return 1
	fi
}

function setDevice() {
	local _nvme_namespace=$1
	
	if status >/dev/null 2>&1 ; then
		# background process running
		log "[SETDEVICE] Can't set device. ${_service} is running."
		return 1
	else
		# background process not running
		if check_nvme_namespace "${_nvme_namespace}" ; then 
			echo "${_nvme_namespace}" > "${_nvme_namespacefile}"
			log "[SETDEVICE] Device set to ${_nvme_namespace}"
		else
			echo "" > "${_nvme_namespacefile}"
			log "[SETDEVICE] Could not set device. nvme_namespace ${_nvme_namespace} does not exist."
			return 1
		fi
		return 0
	fi
}

function usage() {
	local _options="[start|stop|restart|status|resetWorkloadTimer|WAFinfo|setDevice]"
	
	echo "Usage: $(basename "$1") ${_options}"
	return 0
}

if [ "$(id -u)" -ne 0 ] ; then
	log "${_service} need to run as root user or as super user"
	exit 1
fi

# Prerequisite commands
check_command awk basename bc grep sed nc nvme

# create a log directory 
mkdir -p /var/log/"${_filename}"

# Create required files if they do not exist
touch "${_logfile}" >/dev/null 2>&1 || log "Error creating ${_logfile}"
touch "${_pidfile}" >/dev/null 2>&1 || log "Error creating ${_pidfile}"
touch "${_nvme_namespacefile}" >/dev/null 2>&1 || log "Error creating ${_nvme_namespacefile}"
touch "${_VUsmart_F4_beforefile}" >/dev/null 2>&1 || log "Error creating ${_VUsmart_F4_beforefile}"
touch "${_VUsmart_F5_beforefile}" >/dev/null 2>&1 || log "Error creating ${_VUsmart_F5_beforefile}"

case "$1" in
	status|Status|STATUS)
		status
		;;
	start|Start|START)
		start
		;;
	stop|Stop|STOP)
		stop
		;;
	restart|Restart|RESTART)
		restart
		;;
	resetWorkloadTimer|ResetWorkloadTimer|resetworkloadtimer|RESETWORKLOADTIMER)
		resetWorkloadTimer
		;;
	WAFinfo|wafinfo|WafInfo|wi|WI)
		WAFinfo
		;;
	setDevice|SetDevice|setdevice|SETDEVICE)
		setDevice "$2"
		;;
	*)
		usage "$0"
		exit 1
		;;
esac


}

class logserver {
  package { 'rsyslog': ensure => 'latest', }
  package { 'logwatch': ensure => 'latest', }
  service { 'rsyslog':
    ensure => 'running',
    enable => true,
    require => Package['rsyslog'],
  }
}
class linuxextras {
  package { 'sl' : ensure => "latest", }
  $mypackages = [ "cowsay", "fortune", "shellcheck", ]
  package { $mypackages : ensure => "latest", }
}
class hostips {
    host { 'hostvm' : ip => "${lannetnum}.1",}
    host { 'hostvm-mgmt' : ip => "${mgmtnetnum}.1", host_aliases => 'puppet'}
    host { 'openwrt' : ip => "${lannetnum}.2",}
    host { 'openwrt-mgmt' : ip => "${mgmtnetnum}.2", }
    host { '${prefix}1' : ip => "${lannetnum}.${startinghostnum}",}
    host { '${prefix}1-mgmt' : ip => "${mgmtnetnum}.${startinghostnum}",}
    host { '${prefix}2' : ip => "${lannetnum}.((${startinghostnum} + 1 ))",}
    host { '${prefix}2-mgmt' : ip => "${mgmtnetnum}.((${startinghostnum} + 1))",}
}
EOF
        [ -f "$puppetsitefile" ] || cat > "$puppetsitefile" <<EOF
node ${prefix}1.home.arpa {
    include webhostserver
    include linuxextras
    include hostips

}#!/bin/bash
# This script creates a virtual network suitable for learning about networking
# created by dennis simpson 2023, all rights reserved

lannetnum="192.168.16"
mgmtnetnum="172.16.1"
prefix=server
startinghostnum=10
remoteadmin="remoteadmin"
numcontainers=1
puppetinstall=no
verbose=yes

source /etc/os-release

function echoverbose {
    [ "$verbose" = "yes" ] && echo "$@"
}

#define functions for help display and error messages
# This function will send an error message to stderr
# Usage:
#   error-message ["some text to print to stderr"]
#
function error-message {
  local prog
  prog="$(basename '$0')"
  echo "${prog}: ${1:-Unknown Error - a moose bit my sister once...}" >&2
}

# This function will send a message to stderr and exit with a failure status
# Usage:
#   error-exit ["some text to print" [exit-status]]
#
function error-exit {
  error-message "$1"
  exit "${2:-1}"
}

# allow choices on the command line
while [ $# -gt 0 ]; do
    case "$1" in
        --help | -h )
            echo "
Usage: $(basename "$0") [-h | --help] [--fresh] [--prefix targetnameprefix] [--user remoteadminaccountname] [--lannet A.B.C] [--mgmtnet A.B.C] [--count N] [--hostnumbase N] [--puppetinstall]
This script sets up a private network using containers in a Ubuntu hosting machine for educational purposes.
It has an OpenWRT router connecting the hosting OS lan to its wan interface, and 2 virtual networks called lan and mgmt on additional interfaces.
Will install and initialize lxd if necessary.
Will create lan and mgmt virtual networks if necessary using host 2 on each network for the router, both using /24 mask.
Will create openwrt router with lxdbr0 for WAN, lan for lan, and mgmt for private management network.
Creates target containers, named using target name prefix with the container number appended.
Creates a remote admin account with sudo privilege, no passwd access, and ssh access for the user who runs this script.
Adds host names with IP addresses to /etc/hosts inside the containers and in the hosting OS.
The hosting OS will have direct access to all the virtual networks using host number 1.
Can install Puppet tools.
Defaults
fresh:         false
prefix:        server
user:          remoteadmin
lannet:        192.168.16
mgmtnet:       172.16.1
hostnumbase:   10
count:         1
puppetinstall: no
"
            exit
            ;;
        --puppetinstall )
            puppetinstall=yes
            ;;
        --fresh )
	    targets=$(lxc list|grep -o -w "$prefix".)
            echoverbose "Deleting any existing target containers"
            for target in $targets; do
                lxc delete "$target" --force
            done
            echoverbose "Deleting any existing openwrt container"
            lxc delete openwrt --force
            lxc network delete lan
            lxc network delete mgmt
            ;;
        --prefix )
            if [ -z "$2" ]; then
                error-exit "Need a hostname prefix for the --prefix option"
            else
                prefix="$2"
                shift
            fi
            ;;
        --user )
            if [ -z "$2" ]; then
                error-exit "Need a username for the --user option"
            else
                remoteadmin="$2"
                shift
            fi
            ;;
        --lannet )
            if [ -z "$2" ]; then
                error-exit "Need a network number in the format N.N.N for the --lannet option"
            else
                lannetnum="$2"
                shift
            fi
            ;;
        --mgmtnet )
            if [ -z "$2" ]; then
                error-exit "Need a network number in the format N.N.N for the --mgmtnet option"
            else
                mgmtnetnum="$2"
                shift
            fi
            ;;
        --count )
            if [ -z "$2" ]; then
                error-exit "Need a number for the --count option"
            else
                numcontainers="$2"
                shift
            fi
            ;;
        --hostnumbase )
            if [ -z "$2" ]; then
                error-exit "Need a number for the --hostnumbase option"
            else
                startinghostnum="$2"
                shift
            fi
            ;;
    esac
    shift
done

echo "Checking for sudo"
[ "$(id -u)" -eq 0 ] && error-exit "Do not run this script using sudo, it will use sudo when it needs to"
sudo echo "sudo access ok" || exit 1
echoverbose "Adding hostvm to /etc/hosts file if necessary"
sudo sed -i -e '/ hostvm$/d' -e '$a'"$lannetnum.1 hostvm" /etc/hosts
sudo sed -i -e '/ hostvm-mgmt$/d' -e '$a'"$mgmtnetnum.1 hostvm-mgmt" /etc/hosts
echoverbose "Adding openwrt to /etc/hosts file if necessary"
sudo sed -i -e '/ openwrt$/d' -e '$a'"$lannetnum.2 openwrt" /etc/hosts
sudo sed -i -e '/ openwrt-mgmt$/d' -e '$a'"$mgmtnetnum.2 openwrt-mgmt" /etc/hosts

# install puppet if necessary, includes bolt install
if [ "$puppetinstall" = "yes" ]; then
    if ! systemctl is-active --quiet puppetserver 2>/dev/null; then
        [ -f ~/Downloads/puppet8-release-focal.deb ] ||
            wget -q -O ~/Downloads/puppet8-release-focal.deb https://apt.puppet.com/puppet8-release-focal.deb
        [ -f ~/Downloads/puppet8-release-focal.deb ] || error-exit "Failed to download puppet8 focal apt setup"
        sudo DEBIAN_FRONTEND=noninteractive dpkg -i ~/Downloads/puppet8-release-focal.deb || error-exit "Failed to dpkg install puppet8-release-focal.deb"
        sudo apt-get -qq update || error-exit "Failed apt update"
        sudo NEEDRESTART_MODE=a apt-get -y install puppetserver >/dev/null || error-exit "Failed to apt install puppetserver"
        sudo systemctl start puppetserver || error-exit "Failed to start puppetserver"
        sudo grep -q 'PATH=$PATH:/opt/puppetlabs/bin' /root/.bashrc || sudo sed -i '$aPATH=$PATH:/opt/puppetlabs/bin' /root/.bashrc
    fi
    echoverbose "Ensuring ${prefix}1 apache2 install manifests are present"
    puppetmanifestsdir=/etc/puppetlabs/code/environments/production/manifests
    puppetinitfile="$puppetmanifestsdir/init.pp"
    puppetsitefile="$puppetmanifestsdir/site.pp"
    sudo chgrp student "$puppetmanifestsdir"
    sudo chmod g+w "$puppetmanifestsdir"
    [ -f "$puppetinitfile" ] || cat > "$puppetinitfile" <<EOF
class webserver {
  package { 'apache2': ensure => 'latest', }
  service { 'apache2':
    ensure => 'running',
    enable => true,
    require => Package['apache2'],
  }
}
class logserver {
  package { 'rsyslog': ensure => 'latest', }
  package { 'logwatch': ensure => 'latest', }
  service { 'rsyslog':
    ensure => 'running',
    enable => true,
    require => Package['rsyslog'],
  }
}
class linuxextras {
  package { 'sl' : ensure => "latest", }
  $mypackages = [ "cowsay", "fortune", "shellcheck", ]
  package { $mypackages : ensure => "latest", }
}
class hostips {
    host { 'hostvm' : ip => "${lannetnum}.1",}
    host { 'hostvm-mgmt' : ip => "${mgmtnetnum}.1", host_aliases => 'puppet'}
    host { 'openwrt' : ip => "${lannetnum}.2",}
    host { 'openwrt-mgmt' : ip => "${mgmtnetnum}.2", }
    host { '${prefix}1' : ip => "${lannetnum}.${startinghostnum}",}
    host { '${prefix}1-mgmt' : ip => "${mgmtnetnum}.${startinghostnum}",}
    host { '${prefix}2' : ip => "${lannetnum}.((${startinghostnum} + 1 ))",}
    host { '${prefix}2-mgmt' : ip => "${mgmtnetnum}.((${startinghostnum} + 1))",}
}
EOF
        [ -f "$puppetsitefile" ] || cat > "$puppetsitefile" <<EOF
node ${prefix}1.home.arpa {
    include webserver
    include linuxextras
    include hostips
}
node ${prefix}2.home.arpa {
    include logserver
    include linuxextras
    include hostips
}
node default {
    include linuxextras
}
EOF

    if ! which bolt >/dev/null; then
        echoverbose "Installing bolt"
        [ -f ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ] ||
            wget -q -O ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb https://apt.puppet.com/puppet-tools-release-"$VERSION_CODENAME".deb
        [ -f ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ] || (echo "Failed to download bolt apt setup" ; exit 1)
        sudo DEBIAN_FRONTEND=noninteractive dpkg -i ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ||
            error-exit "Failed to install puppet-tools-release-$VERSION_CODENAME.deb"
        sudo apt-get -qq update || error-exit "Failed to apt update"
        sudo NEEDRESTART_MODE=a apt-get -y install puppet-bolt >/dev/null || error-exit "Failed to install puppet-bolt"
    fi
    echoverbose "Setting bolt defaults for $(whoami) to access via ssh:remoteadmin@${prefix}N-mgmt"
    if [ ! -f ~/.puppetlabs/etc/bolt/bolt-defaults.yaml ]; then
        [ -d ~/.puppetlabs/etc/bolt ] || mkdir -p ~/.puppetlabs/etc/bolt
        cat >~/.puppetlabs/etc/bolt/bolt-defaults.yaml <<EOF
inventory-config:
  ssh:
    user: remoteadmin
    host-key-check: false
    private-key: ~/.ssh/id_ed25519
EOF
    fi
fi
[ -d /opt/puppetlabs/bin ] && PATH="$PATH:/opt/puppetlabs/bin"

# install lxd and initialize if needed
lxc --version >&/dev/null || sudo apt install lxd || sudo snap install lxd || exit 1
if ! ip a s lxdbr0 >&/dev/null; then
    echoverbose "Initializing lxd"
    sudo lxd init --auto
fi
if ! ip a s lan >&/dev/null; then
    lxc network create lan ipv4.address="$lannetnum".1/24 ipv6.address=none ipv4.dhcp=false ipv6.dhcp=false ipv4.nat=false
fi
if ! ip a s mgmt >&/dev/null; then
    lxc network create mgmt ipv4.address="$mgmtnetnum".1/24 ipv6.address=none ipv4.dhcp=false ipv6.dhcp=false ipv4.nat=false
fi

#create the router container if necessary
if ! lxc info openwrt >&/dev/null ; then
    lxc launch images:openwrt/22.03 openwrt -n ens33
    lxc network attach lan openwrt eth1
    lxc network attach mgmt openwrt eth2
    
    lxc exec openwrt -- sh -c 'echo "
config device
    option name eth1

config interface lan
    option device eth1
    option proto static
    option ipaddr 192.168.16.2
    option netmask 255.255.255.0
    
config device
    option name eth2

config interface private
    option device eth2
    option proto static
    option ipaddr 172.16.1.2
    option netmask 255.255.255.0


fi

node ${prefix}2.home.arpa {
    include logserver
    include linuxextras
    include hostips
}
node default {
    include linuxextras
}
EOF

    if ! which bolt >/dev/null; then
        echoverbose "Installing bolt"
        [ -f ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ] ||
            wget -q -O ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb https://apt.puppet.com/puppet-tools-release-"$VERSION_CODENAME".deb
        [ -f ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ] || (echo "Failed to download bolt apt setup" ; exit 1)
        sudo DEBIAN_FRONTEND=noninteractive dpkg -i ~/Downloads/puppet-tools-release-"$VERSION_CODENAME".deb ||
            error-exit "Failed to install puppet-tools-release-$VERSION_CODENAME.deb"
        sudo apt-get -qq update || error-exit "Failed to apt update"
        sudo NEEDRESTART_MODE=a apt-get -y install puppet-bolt >/dev/null || error-exit "Failed to install puppet-bolt"
    fi
    echoverbose "Setting bolt defaults for $(whoami) to access via ssh:remoteadmin@${prefix}N-mgmt"
    if [ ! -f ~/.puppetlabs/etc/bolt/bolt-defaults.yaml ]; then
        [ -d ~/.puppetlabs/etc/bolt ] || mkdir -p ~/.puppetlabs/etc/bolt
        cat >~/.puppetlabs/etc/bolt/bolt-defaults.yaml <<EOF
inventory-config:
  ssh:
    user: remoteadmin
    host-key-check: false
    private-key: ~/.ssh/id_ed25519
EOF
    fi
fi
[ -d /opt/puppetlabs/bin ] && PATH="$PATH:/opt/puppetlabs/bin"

# install lxd and initialize if needed
lxc --version >&/dev/null || sudo apt install lxd || sudo snap install lxd || exit 1
if ! ip a s lxdbr0 >&/dev/null; then
    echoverbose "Initializing lxd"
    sudo lxd init --auto
fi
if ! ip a s lan >&/dev/null; then
    lxc network create lan ipv4.address="$lannetnum".1/24 ipv6.address=none ipv4.dhcp=false ipv6.dhcp=false ipv4.nat=false
fi
if ! ip a s mgmt >&/dev/null; then
    lxc network create mgmt ipv4.address="$mgmtnetnum".1/24 ipv6.address=none ipv4.dhcp=false ipv6.dhcp=false ipv4.nat=false
fi

#create the router container if necessary
if ! lxc info openwrt >&/dev/null ; then
    lxc launch images:openwrt/22.03 openwrt -n ens33
    lxc network attach lan openwrt eth1
    lxc network attach mgmt openwrt eth2
    
    lxc exec openwrt -- sh -c 'echo "
config device
    option name eth1

config interface lan
    option device eth1
    option proto static
    option ipaddr 192.168.16.2
    option netmask 255.255.255.0
    
config device
    option name eth2

config interface private
    option device eth2
    option proto static
    option ipaddr 172.16.1.2
    option netmask 255.255.255.0

" >>/etc/config/network'
    lxc exec openwrt reboot
fi

# we want $numcontainers containers running
numexisting=$(lxc list -c n --format csv|grep -c "$prefix")
for (( n=0;n<numcontainers - numexisting;n++ )); do
    container="$prefix$((n+1))"
    if lxc info "$container" >& /dev/null; then
        echoverbose "$container already exists"
        continue
    fi
    containerlanip="$lannetnum.$((n + startinghostnum))"
    containermgmtip="$mgmtnetnum.$((n + startinghostnum))"
	lxc launch ubuntu:lts "$container" -n lan
    lxc network attach mgmt "$container" eth1
    echoverbose "Waiting for $container to complete startup"
    while ! lxc exec "$container" -- systemctl is-active --quiet ssh 2>/dev/null; do sleep 1; done

    lxc exec "$container" -- sh -c "cat > /etc/netplan/50-cloud-init.yaml <<EOF
network:
    version: 2
    ethernets:
        eth0:
            addresses: [$containerlanip/24]
            routes:
              - to: default
                via: $lannetnum.2
            nameservers:
                addresses: [$lannetnum.2]
                search: [home.arpa, localdomain]
        eth1:
            addresses: [$containermgmtip/24]
EOF
"
    lxc exec "$container" -- sh -c 'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg'
    lxc exec "$container" netplan apply
    lxc exec "$container" -- sh -c "echo $containerlanip $container >>/etc/hosts"
    lxc exec "$container" -- sh -c "echo $containermgmtip $container-mgmt >>/etc/hosts"
    
    echoverbose "Adding SSH host key for $container"
    
    [ -d ~/.ssh ] || ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""
    [ ! -f ~/.ssh/id_ed25519.pub ] && ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""
    ssh-keygen -q -R "$container" 2>/dev/null >/dev/null
    ssh-keyscan -t ed25519 "$container" >>~/.ssh/known_hosts 2>/dev/null
    ssh-keygen -q -H >/dev/null 2>/dev/null

    echoverbose "Adding remote admin user '$remoteadmin' to $container"
    lxc exec "$container" -- useradd -m -c "SSH remote admin access account" -s /bin/bash -o -u 0 "$remoteadmin"
    lxc exec "$container" mkdir "/home/$remoteadmin/.ssh"
    lxc exec "$container" chmod 700 "/home/$remoteadmin/.ssh"
    lxc file push ~/.ssh/id_ed25519.pub "$container/home/$remoteadmin/.ssh/"
    lxc exec "$container" cp "/home/$remoteadmin/.ssh/id_ed25519.pub" "/home/$remoteadmin/.ssh/authorized_keys"
    lxc exec "$container" chmod 600 "/home/$remoteadmin/.ssh/authorized_keys"
    lxc exec "$container" -- chown -R "$remoteadmin" "/home/$remoteadmin"

    echoverbose "Setting $container hostname"
    lxc exec "$container" hostnamectl set-hostname "$container"
    lxc exec "$container" reboot
    echo "Waiting for $container reboot"
    while ! lxc exec "$container" -- systemctl is-active --quiet ssh 2>/dev/null; do sleep 1; done
    
    echoverbose "Adding $container to /etc/hosts file if necessary"
    sudo sed -i -e "/ $container\$/d" -e "/ $container-mgmt\$/d" /etc/hosts
    sudo sed -i -e '$a'"$containerlanip $container" -e '$a'"$containermgmtip $container-mgmt" /etc/hosts
    
    if [ "$puppetinstall" = "yes" ]; then
        echoverbose "Adding puppet server to /etc/hosts file if necessary"
        grep -q ' puppet$' /etc/hosts || sudo sed -i -e '$a'"$mgmtnetnum.1 puppet" /etc/hosts
        echoverbose "Setting up for puppet8 and installing agent on $container"
        lxc exec "$container" -- wget -q https://apt.puppet.com/puppet8-release-jammy.deb
        lxc exec "$container" -- dpkg -i puppet8-release-"$VERSION_CODENAME".deb
        lxc exec "$container" -- apt-get -qq update
        echoverbose "Restarting snapd.seeded.service can take a long time, do not interrupt it"
        lxc exec "$container" -- sh -c "NEEDRESTART_MODE=a apt-get -y install puppet-agent >/dev/null"
        lxc exec "$container" -- sed -i '$aPATH=$PATH:/opt/puppetlabs/bin' .bashrc
        lxc exec "$container" -- sed -i -e '$'"a$mgmtnetnum.1 puppet" /etc/hosts
        lxc exec "$container" -- /opt/puppetlabs/bin/puppet ssl bootstrap &
    fi

done

if [ "$puppetinstall" = "yes" ]; then
    for ((count=0; count < 10; count++ )); do
        sleep 3
        sudo /opt/puppetlabs/bin/puppetserver ca list --all |grep -q Requested &&
            sudo /opt/puppetlabs/bin/puppetserver ca sign --all &&
            break
    done

    [ $count -eq 10 ] &&
        echo "Timed out waiting for certificate request(s) from containers, wait until you see the green text for certificate requests, then do" &&
        echo "sudo /opt/puppetlabs/bin/puppetserver ca sign --all"
fi
