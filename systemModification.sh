#!/bin/sh
# (Free-)BSD mobile work station network control script. Inspired by:
# - network.sh from vermaden
# - wifimgr from gihnius
# - wifish from bougyman

# Requirements:
# - doas
# - ifconfig
# - wpa_supplicant

# Settings
ROOT=`which doas`

# LAN Network
LAN_IF=em0

# Wireless Network
WLAN_IF=wlan0
WLAN_PH=iwn0
WLAN_TMP_RESULTS=/tmp/${WLAN_IF}.scan

# Support multiple VPNs (ovpn for OpenVPN, oc for OpenConnect)
VPNS="ovpn:frubar oc:avira oc:anexia"

# Resolver IPs (type:ip)
RESOLVERS="local:192.162.16.21/24 resolver:0.0.0.0 google:8.8.8.8 google:8.8.4.4"

__usage() {
	dns=$(echo ${RESOLVERS} | sed 's_:[^ ]*__g' | xargs -n1 | sort -u | xargs)
	vpn=$(echo ${VPNS} | tr ' ' '|')
	cat <<-EOF
	${0} [status|lan|wlan|dns|vpn]

	PARAMS
	  status
	  lan    [start|stop|restart]
	  wlan   [start|stop|restart|scan|rescan|new|list|connect]
	  dns    [${dns}]
	  vpn    [${vpn}]
	EOF
	unset dns vpn
	exit 1
}

__net_status() {
	( netstat -in -f inet; netstat -in -f inet6 ) \
		| grep -Ev "(fe80|lo)"  \
		| sed 's|^Name|^Name|g' \
		| sort | uniq \
		| sed 's|\^Name|Name|g'
}

__lan_start() {
	${ROOT} service netif start ${LAN_IF}
}
__lan_stop() {
	${ROOT} service netif stop ${LAN_IF}
}

__wlan_start() {
	${ROOT} service netif start ${WLAN_IF}
}
__wlan_stop() {
	${ROOT} service netif stop ${WLAN_IF}
}

__wlan_rescan() {
	rm -f ${WLAN_TMP_RESULTS}
	__wlan_scan
}

__wlan_scan() {
	if [ $(stat -f "%m" ${WLAN_TMP_RESULTS} 2>/dev/null || echo 0) -lt $(date -j -v-30M +%s) ]; then
		rm -f ${WLAN_TMP_RESULTS}
	fi
	if [ ! -r ${WLAN_TMP_RESULTS} ]; then
		${ROOT} ifconfig ${WLAN_IF} scan >/dev/null && sleep 2
		${ROOT} ifconfig ${WLAN_IF} list scan | gsed -e 's|\(-[0-9]*\):\-[0-9]*|\1|g' -e 's| \{2,\}|\x0|g' | sort -r -g -t '\0' -k 5 | gawk -F '\0' '
		BEGIN { NR=NR; longest_ssid = 0 }
		/SSID\/MESH ID.*/ { next; }
		{
			line[NR]["ssid"]   = $1
			line[NR]["mac"]    = $2
			line[NR]["chan"]   = $3
			line[NR]["rate"]   = $4
			line[NR]["signal"] = $5
			$1 = $2 = $3 = $4 = $5 = $6 = ""
			line[NR]["caps"]   = $0
			if(length(line[NR]["ssid"]) > longest_ssid)
				longest_ssid = length(line[NR]["ssid"])+10
		}
		END {
			#printf "%-"longest_ssid"s %-6s %-19s %s\n", "SSID", "SIGNAL", "MAC", "CAPABILITIES"
			for(i in line) {
				ssid   = line[i]["ssid"]
				signal = line[i]["signal"]+100
				
				if(ssid ~ /^$/) ssid="HIDDEN"

				printf "%-"longest_ssid"s %-6s %-19s %s\n", ssid, signal, line[i]["mac"], line[i]["caps"]
			}
		}
		' > ${WLAN_TMP_RESULTS}
	fi
	cat ${WLAN_TMP_RESULTS}
}

__wlan_list() {
	wpa_cli list_networks | gawk '
		BEGIN {
			FS="\t";
			printf "%-4s\t%-s\n", "ID", "SSID"
		}
		$1~/^[[:digit:]]/ {
			printf "%-4d\t%-s\n", $1, $2
		}
	'
}

__wlan_connect() {
	wlan_tmp_results="$(__wlan_scan)"
	network_id=$(__wlan_list | while read wlan_list; do
		id="${wlan_list%$'\t'*}"
		ssid="${wlan_list#*$'\t'}"
		if result=$(IFS=$'\n' echo "$wlan_tmp_results}" | grep -e "${ssid}\ \{2,\}"); then
			echo "$id $result"
		fi
	done | grep -e '^[0-9]*\ \{2,\}' | sort -k 3 -r | pick | awk '{ print $1 }')
	wpa_cli select_network ${network_id}
	unset wlan_tmp_results network_id id ssid result
}

__wlan_new() {
	selected=$(__wlan_scan | pick)
	ssid=$(echo ${selected} | sed 's| [0-9][0-9] [a-z0-9].*||g')
	if ! __wlan_list | grep -q "${ssid}$"; then
		network_id=$(wpa_cli add_network | tail -n 1)


		if [ -z "${selected##*RSN*}" ]; then
			while true; do
				stty -echo
				read -p 'Passphrase: ' passphrase
				stty echo
				[ -n "${passphrase}" ] && break
			done

			# WPA2
			wpa_cli set_network ${network_id} key_mgmt WPA-PSK
			wpa_cli set_network ${network_id} proto    WPA2
			wpa_cli set_network ${network_id} psk      "\"${passphrase}\""
		else
			wpa_cli set_network ${network_id} key_mgmt NONE
		fi
		wpa_cli set_network ${network_id} ssid "\"${ssid}\""
		wpa_cli select_network ${network_id}
		wpa_cli save_config
	fi
	unset selected ssid network_id passphrase
}

__dns() {
	for resolver in ${RESOLVERS}; do
		if echo ${resolver} | grep -qe "^${1}"; then
			echo '# Managed by net.sh'
			value=$(echo ${resolver} | gsed 's/\(.*\):\(.*\)/\2/g')
			if [ "${value}" == "0.0.0.0" ]; then
				resolvconf -l
			else
				echo nameserver ${value}
			fi
		fi
	done | ${ROOT} tee /etc/resolv.conf >/dev/null
	unset resolver value
}

# Main
case ${1} in
	lan)
		case ${2} in
			start)   __lan_start               ;;
			stop)    __lan_stop                ;;
			restart) __lan_stop && __lan_start ;;
			*)       __usage                   ;;
		esac
		;;
	wlan)
		case ${2} in
			start)   __wlan_start                ;;
			scan)    __wlan_scan                 ;;
			rescan)  __wlan_rescan               ;;
			list)    __wlan_list                 ;;
			con*)    __wlan_connect              ;;
			new)     __wlan_new                  ;;
			stop)    __wlan_stop                 ;;
			restart) __wlan_stop && __wlan_start ;;
			*)       __usage                     ;;
		esac
		;;
	vpn)
		case ${2} in
			connect)    __vpn_connect ${3}    ;;
			disconnect) __vpn_disconnect ${3} ;;
			status)     __vpn_status          ;;
			*)          __usage               ;;
		esac
		;;
	dns)
		test "${RESOLVERS#*$2}" != "$RESOLVERS" || __usage
		__dns ${2}
		;;
	status) __net_status ;;
	*)      __usage; echo $__vpns      ;;
esac
