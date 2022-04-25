#!/bin/bash
# We use some bash-isms (getopts?)

# Copyright (C) 2007-2015 Red Hat, Inc. All rights reserved.
#
# This file is part of LVM2.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# lvm_dump: This script is used to collect pertinent information for
#           the debugging of lvm issues.

# following external commands are used throughout the script
# echo and test are internal in bash at least
MKDIR=mkdir # need -p
TAR=tar # need czf
RM=rm # need -rf
CP=cp
TAIL=tail # we need -n
LS=ls # need -la
PS=ps # need alx
SED=sed
DD=dd
CUT=cut
DATE=date
BASENAME=basename
UDEVADM=udevadm
UNAME=uname
TR=tr
SOCAT=socat # either socat or nc is needed for dumping lvmetad state
NC=nc

# user may override lvm and dmsetup location by setting LVM_BINARY
# and DMSETUP_BINARY respectively
LVM=${LVM_BINARY-lvm}
DMSETUP=${DMSETUP_BINARY-dmsetup}
LVMETAD_SOCKET=${LVM_LVMETAD_SOCKET-/var/run/lvm/lvmetad.socket}
LVMPOLLD_SOCKET=${LVM_LVMPOLLD_SOCKET-/var/run/lvm/lvmpolld.socket}

die() {
    code=$1; shift
    echo "$@" 1>&2
    exit $code
}

"$LVM" version >& /dev/null || die 2 "Could not run lvm binary '$LVM'"
"$DMSETUP" version >& /dev/null || DMSETUP=:

function usage {
	echo "$0 [options]"
	echo "    -h print this message"
	echo "    -a advanced collection - warning: if lvm is already hung,"
	echo "       then this script may hang as well if -a is used"
	echo "    -c if running clvmd, gather cluster data as well"
	echo "    -d <directory> dump into a directory instead of tarball"
	echo "    -l gather lvmetad state if running"
	echo "    -p gather lvmpolld state if running"
	echo "    -m gather LVM metadata from the PVs"
	echo "    -s gather system info and context"
	echo "    -u gather udev info and context"
	echo ""

	exit 1
}

advanced=0
clustered=0
metadata=0
sysreport=0
udev=0
while getopts :acd:hlpmus opt; do
	case $opt in 
		a)	advanced=1 ;;
		c)	clustered=1 ;;
		d)	userdir=$OPTARG ;;
		h)	usage ;;
		l)	lvmetad=1 ;;
		p)	lvmpolld=1 ;;
		m)	metadata=1 ;;
		s)      sysreport=1 ;;
		u)	udev=1 ;;
		:)	echo "$0: $OPTARG requires a value:"; usage ;;
		\?)     echo "$0: unknown option $OPTARG"; usage ;;
		*)	usage ;;
	esac
done

NOW=`$DATE -u +%G%m%d%k%M%S | $TR -d ' '`
if test -n "$userdir"; then
	dir="$userdir"
else
	dirbase="lvmdump-$HOSTNAME-$NOW"
	dir="$HOME/$dirbase"
fi

test -e $dir && die 3 "Fatal: $dir already exists"
$MKDIR -p $dir || die 4 "Fatal: could not create $dir"

log="$dir/lvmdump.log"

myecho() {
	echo "$@"
	echo "$@" >> "$log"
}

log() {
	echo "$@" >> "$log"
	eval "$@"
}

warnings() {
	if test "$UID" != "0" && test "$EUID" != "0"; then
		myecho "WARNING! Running as non-privileged user, dump is likely incomplete!"
	elif test "$DMSETUP" = ":"; then
		myecho "WARNING! Could not run dmsetup, dump is likely incomplete."
	fi
}

warnings

myecho "Creating dump directory: $dir"
echo " "

if (( $advanced )); then
	myecho "Gathering LVM volume info..."

	myecho "  vgscan..."
	log "\"$LVM\" vgscan -vvvv >> \"$dir/vgscan\" 2>&1"

	myecho "  pvscan..."
	log "\"$LVM\" pvscan -v >> \"$dir/pvscan\" 2>> \"$log\""

	myecho "  lvs..."
	log "\"$LVM\" lvs -a -o +devices >> \"$dir/lvs\" 2>> \"$log\""

	myecho "  pvs..."
	log "\"$LVM\" pvs -a -v >> \"$dir/pvs\" 2>> \"$log\""

	myecho "  vgs..."
	log "\"$LVM\" vgs -v >> \"$dir/vgs\" 2>> \"$log\""
fi

if (( $clustered )); then
	myecho "Gathering cluster info..."

	{
	for i in nodes status services; do
		cap_i=$(echo $i|tr a-z A-Z)
		printf "$cap_i:\n----------------------------------\n"
		log "cman_tool $i 2>> \"$log\""
		echo
	done

	echo "LOCKS:"
	echo "----------------------------------"
	if [ -f /proc/cluster/dlm_locks ]
	then
		echo clvmd > /proc/cluster/dlm_locks
		cat /proc/cluster/dlm_locks
		echo
		echo "RESOURCE DIR:"
		cat /proc/cluster/dlm_dir
		echo
		echo "DEBUG LOG:"
		cat /proc/cluster/dlm_debug
		echo
	fi
	if [ -f /debug/dlm/clvmd ]
	then
		cat /debug/dlm/clvmd
		echo
		echo "WAITERS:"
		cat /debug/dlm/clvmd_waiters
		echo
		echo "MASTER:"
		cat /debug/dlm/clvmd_master
	fi
	} >> $dir/cluster_info
fi

myecho "Gathering LVM & device-mapper version info..."
echo "LVM VERSION:" >> "$dir/versions"
"$LVM" lvs --version >> "$dir/versions" 2>> "$log"
echo "DEVICE MAPPER VERSION:" >> "$dir/versions"
"$DMSETUP" --version >> "$dir/versions" 2>> "$log"
echo "KERNEL VERSION:" >> "$dir/versions"
"$UNAME" -a >> "$dir/versions" 2>> "$log"
echo "DM TARGETS VERSIONS:" >> "$dir/versions"
"$DMSETUP" targets >> "$dir/versions" 2>> "$log"

myecho "Gathering dmsetup info..."
log "\"$DMSETUP\" info -c >> \"$dir/dmsetup_info\" 2>> \"$log\""
log "\"$DMSETUP\" table >> \"$dir/dmsetup_table\" 2>> \"$log\""
log "\"$DMSETUP\" status >> \"$dir/dmsetup_status\" 2>> \"$log\""

# cat as workaround to avoid tty ioctl (selinux)
log "\"$DMSETUP\" ls --tree 2>> \"$log\" | cat >> \"$dir/dmsetup_ls_tree\""

myecho "Gathering process info..."
log "$PS alx >> \"$dir/ps_info\" 2>> \"$log\""

myecho "Gathering console messages..."
log "$TAIL -n 75 /var/log/messages >> \"$dir/messages\" 2>> \"$log\""

myecho "Gathering /etc/lvm info..."
log "$LS -laR /etc/lvm >> \"$dir/etc_lvm_listing\" 2>> \"$log\""
log "$CP -RL --preserve=all /etc/lvm \"$dir/lvm\" 2>> \"$log\""
log "$LVM dumpconfig --type diff --file \"$dir/config_diff\" 2>> \"$log\""
log "$LVM dumpconfig --type missing --file \"$dir/config_missing\" 2>> \"$log\""

myecho "Gathering /dev listing..."
log "$LS -laR /dev >> \"$dir/dev_listing\" 2>> \"$log\""

myecho "Gathering /sys/block listing..."
log "$LS -laR /sys/block >> \"$dir/sysblock_listing\"  2>> \"$log\""
log "$LS -laR /sys/devices/virtual/block >> \"$dir/sysblock_listing\"  2>> \"$log\""

if (( $metadata )); then
	myecho "Gathering LVM metadata from Physical Volumes..."

	log "$MKDIR -p \"$dir/metadata\""

	pvs="$("$LVM" pvs --separator , --noheadings --units s --nosuffix -o \
	    name,pe_start 2>> "$log" | $SED -e 's/^ *//')"
	for line in $pvs
	do
		test -z "$line" && continue
		pv="$(echo $line | $CUT -d, -f1)"
		pe_start="$(echo $line | $CUT -d, -f2)"
		name="$($BASENAME "$pv")"
		myecho "  $pv"
		log "$DD if=$pv \"of=$dir/metadata/$name\" bs=512 count=$pe_start 2>> \"$log\""
	done
fi

if (( $sysreport )); then
	myecho "Gathering system info..."

	sysreport_dir="$dir/sysreport"
	log_lines=10000

	SYSTEMCTL=$(which systemctl 2>> $log)
	JOURNALCTL=$(which journalctl 2>> $log)

	if test -z "$SYSTEMCTL"; then
		myecho "WARNING: systemctl not found"
	elif test -z "$JOURNALCTL"; then
		myecho "WARNING: journalctl not found"
	else
		log "$MKDIR -p \"$sysreport_dir\""
		log "$JOURNALCTL -b --no-pager -o short-precise > \"$sysreport_dir/journal_content\" 2>> \"$log\""
		log "$SYSTEMCTL status -l --no-pager -n $log_lines -o short-precise dm-event.socket dm-event.service \
						   lvm2-monitor.service \
						   lvm2-lvmetad.socket lvm2-lvmetad.service \
						   lvm2-lvmpolld.socket lvm2-lvmpolld.service \
						   lvm2-cluster-activation.service \
						   lvm2-clvmd.service \
						   lvm2-cmirrord.service \
						   > \"$sysreport_dir/systemd_lvm2_services_status\" 2>> \"$log\""
		log "$SYSTEMCTL list-units -l -a --no-legend --no-pager > \"$sysreport_dir/systemd_unit_list\" 2>> \"$log\""
		for unit in $(cat $sysreport_dir/systemd_unit_list | grep lvm2-pvscan | cut -d " " -f 1); do
			log "$SYSTEMCTL status -l --no-pager -n $log_lines -o short-precise $unit >> \"$sysreport_dir/systemd_lvm2_pvscan_service_status\""
		done
	fi
fi

if (( $udev )); then
	myecho "Gathering udev info..."

	udev_dir="$dir/udev"

	log "$MKDIR -p \"$udev_dir\""
	log "$UDEVADM info --version >> \"$udev_dir/version\" 2>> \"$log\""
	log "$UDEVADM info --export-db >> \"$udev_dir/db\" 2>> \"$log\""
	log "$CP -a /etc/udev/udev.conf \"$udev_dir/conf\" 2>> \"$log\""
	log "$LS -la /lib/udev >> \"$udev_dir/lib_dir\" 2>> \"$log\""
	log "$CP -RL --preserve=all /etc/udev/rules.d \"$udev_dir/rules_etc\" 2>> \"$log\""
	log "$CP -RL --preserve=all /lib/udev/rules.d \"$udev_dir/rules_lib\" 2>> \"$log\""
fi

if (( $lvmetad )); then
    (echo 'request="dump"'; echo '##') | {
	if type -p $SOCAT >& /dev/null; then
	    echo "$SOCAT unix-connect:$LVMETAD_SOCKET -" >> "$log"
	    $SOCAT "unix-connect:$LVMETAD_SOCKET" - 2>> "$log"
	elif echo | $NC -U "$LVMETAD_SOCKET"; then
	    echo "$NC -U $LVMETAD_SOCKET" >> "$log"
	    $NC -U "$LVMETAD_SOCKET" 2>> "$log"
	else
	    myecho "WARNING: Neither socat nor nc -U seems to be available." 1>&2
	    echo "# DUMP FAILED"
	    return 1
	fi
    } > "$dir/lvmetad.txt"
fi

if (( $lvmpolld )); then
    (echo 'request="dump"'; echo '##') | {
	if type -p $SOCAT >& /dev/null; then
	    echo "$SOCAT unix-connect:$LVMPOLLD_SOCKET -" >> "$log"
	    $SOCAT "unix-connect:$LVMPOLLD_SOCKET" - 2>> "$log"
	elif echo | $NC -U "$LVMPOLLD_SOCKET"; then
	    echo "$NC -U $LVMPOLLD_SOCKET" >> "$log"
	    $NC -U "$LVMPOLLD_SOCKET" 2>> "$log"
	else
	    myecho "WARNING: Neither socat nor nc -U seems to be available." 1>&2
	    echo "# DUMP FAILED"
	    return 1
	fi
    } > "$dir/lvmpolld.txt"
fi

if test -z "$userdir"; then
	lvm_dump="$dirbase.tgz"
	myecho "Creating report tarball in $HOME/$lvm_dump..."
fi

warnings

if test -z "$userdir"; then
	cd "$HOME"
	"$TAR" czf "$lvm_dump" "$dirbase" 2>/dev/null
	"$RM" -rf "$dir"
fi

exit 0
