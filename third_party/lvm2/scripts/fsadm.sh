#!/bin/bash
#
# Copyright (C) 2007-2012 Red Hat, Inc. All rights reserved.
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
#
# Author: Zdenek Kabelac <zkabelac at redhat.com>
#
# Script for resizing devices (usable for LVM resize)
#
# Needed utilities:
#   mount, umount, grep, readlink, blockdev, blkid, fsck, xfs_check
#
# ext2/ext3/ext4: resize2fs, tune2fs
# reiserfs: resize_reiserfs, reiserfstune
# xfs: xfs_growfs, xfs_info
#
# Return values:
#   0 success
#   1 error
#   2 break detected
#   3 unsupported online filesystem check for given mounted fs

TOOL=fsadm

_SAVEPATH=$PATH
PATH=/sbin:/usr/sbin:/bin:/usr/sbin:$PATH

# utilities
TUNE_EXT=tune2fs
RESIZE_EXT=resize2fs
TUNE_REISER=reiserfstune
RESIZE_REISER=resize_reiserfs
TUNE_XFS=xfs_info
RESIZE_XFS=xfs_growfs

MOUNT=mount
UMOUNT=umount
MKDIR=mkdir
RMDIR=rmdir
BLOCKDEV=blockdev
BLKID=blkid
DATE=date
GREP=grep
READLINK=readlink
READLINK_E="-e"
FSCK=fsck
XFS_CHECK=xfs_check
# XFS_REPAIR -n is used when XFS_CHECK is not found
XFS_REPAIR=xfs_repair

# user may override lvm location by setting LVM_BINARY
LVM=${LVM_BINARY:-lvm}

YES=${_FSADM_YES}
DRY=0
VERB=
FORCE=
EXTOFF=${_FSADM_EXTOFF:-0}
DO_LVRESIZE=0
FSTYPE=unknown
VOLUME=unknown
TEMPDIR="${TMPDIR:-/tmp}/${TOOL}_${RANDOM}$$/m"
DM_DEV_DIR="${DM_DEV_DIR:-/dev}"
BLOCKSIZE=
BLOCKCOUNT=
MOUNTPOINT=
MOUNTED=
REMOUNT=
PROCMOUNTS="/proc/mounts"
NULL="$DM_DEV_DIR/null"

IFS_OLD=$IFS
# without bash $'\n'
NL='
'

tool_usage() {
	echo "${TOOL}: Utility to resize or check the filesystem on a device"
	echo
	echo "  ${TOOL} [options] check device"
	echo "    - Check the filesystem on device using fsck"
	echo
	echo "  ${TOOL} [options] resize device [new_size[BKMGTPE]]"
	echo "    - Change the size of the filesystem on device to new_size"
	echo
	echo "  Options:"
	echo "    -h | --help         Show this help message"
	echo "    -v | --verbose      Be verbose"
	echo "    -e | --ext-offline  unmount filesystem before ext2/ext3/ext4 resize"
	echo "    -f | --force        Bypass sanity checks"
	echo "    -n | --dry-run      Print commands without running them"
	echo "    -l | --lvresize     Resize given device (if it is LVM device)"
	echo "    -y | --yes          Answer \"yes\" at any prompts"
	echo
	echo "  new_size - Absolute number of filesystem blocks to be in the filesystem,"
	echo "             or an absolute size using a suffix (in powers of 1024)."
	echo "             If new_size is not supplied, the whole device is used."

	exit
}

verbose() {
	test -n "$VERB" && echo "$TOOL: $@" || true
}

error() {
	echo "$TOOL: $@" >&2
	cleanup 1
}

dry() {
	if [ "$DRY" -ne 0 ]; then
		verbose "Dry execution $@"
		return 0
	fi
	verbose "Executing $@"
	"$@"
}

cleanup() {
	trap '' 2
	# reset MOUNTPOINT - avoid recursion
	test "$MOUNTPOINT" = "$TEMPDIR" && MOUNTPOINT="" temp_umount
	if [ -n "$REMOUNT" ]; then
		verbose "Remounting unmounted filesystem back"
		dry "$MOUNT" "$VOLUME" "$MOUNTED"
	fi
	IFS=$IFS_OLD
	trap 2

	test "$1" -eq 2 && verbose "Break detected"

	if [ "$DO_LVRESIZE" -eq 2 ]; then
		# start LVRESIZE with the filesystem modification flag
		# and allow recursive call of fsadm
		_FSADM_YES=$YES
		_FSADM_EXTOFF=$EXTOFF
		export _FSADM_YES _FSADM_EXTOFF
		unset FSADM_RUNNING
		test -n "$LVM_BINARY" && PATH=$_SAVEPATH
		dry exec "$LVM" lvresize $VERB $FORCE -r -L${NEWSIZE}b "$VOLUME_ORIG"
	fi

	# error exit status for break
	exit ${1:-1}
}

# convert parameter from Exa/Peta/Tera/Giga/Mega/Kilo/Bytes and blocks
# (2^(60/50/40/30/20/10/0))
decode_size() {
	case "$1" in
	 *[eE]) NEWSIZE=$(( ${1%[eE]} * 1152921504606846976 )) ;;
	 *[pP]) NEWSIZE=$(( ${1%[pP]} * 1125899906842624 )) ;;
	 *[tT]) NEWSIZE=$(( ${1%[tT]} * 1099511627776 )) ;;
	 *[gG]) NEWSIZE=$(( ${1%[gG]} * 1073741824 )) ;;
	 *[mM]) NEWSIZE=$(( ${1%[mM]} * 1048576 )) ;;
	 *[kK]) NEWSIZE=$(( ${1%[kK]} * 1024 )) ;;
	 *[bB]) NEWSIZE=${1%[bB]} ;;
	     *) NEWSIZE=$(( $1 * $2 )) ;;
	esac
	#NEWBLOCKCOUNT=$(round_block_size $NEWSIZE $2)
	NEWBLOCKCOUNT=$(( $NEWSIZE / $2 ))

	if [ $DO_LVRESIZE -eq 1 ]; then
		# start lvresize, but first cleanup mounted dirs
		DO_LVRESIZE=2
		cleanup 0
	fi
}

# detect filesystem on the given device
# dereference device name if it is symbolic link
detect_fs() {
	VOLUME_ORIG=$1
	VOLUME=${1/#"${DM_DEV_DIR}/"/}
	VOLUME=$("$READLINK" $READLINK_E "$DM_DEV_DIR/$VOLUME") || error "Cannot get readlink \"$1\""
	RVOLUME=$VOLUME
	case "$RVOLUME" in
          # hardcoded /dev  since udev does not create these entries elsewhere
	  /dev/dm-[0-9]*)
		read </sys/block/${RVOLUME#/dev/}/dm/name SYSVOLUME 2>&1 && VOLUME="$DM_DEV_DIR/mapper/$SYSVOLUME"
		;;
	esac
	# use null device as cache file to be sure about the result
	# not using option '-o value' to be compatible with older version of blkid
	FSTYPE=$("$BLKID" -c "$NULL" -s TYPE "$VOLUME") || error "Cannot get FSTYPE of \"$VOLUME\""
	FSTYPE=${FSTYPE##*TYPE=\"} # cut quotation marks
	FSTYPE=${FSTYPE%%\"*}
	verbose "\"$FSTYPE\" filesystem found on \"$VOLUME\""
}

# check if the given device is already mounted and where
# FIXME: resolve swap usage and device stacking
detect_mounted()  {
	test -e "$PROCMOUNTS" || error "Cannot detect mounted device \"$VOLUME\""

	MOUNTED=$("$GREP" "^$VOLUME[ \t]" "$PROCMOUNTS")

	# for empty string try again with real volume name
	test -z "$MOUNTED" && MOUNTED=$("$GREP" "^$RVOLUME[ \t]" "$PROCMOUNTS")

	# cut device name prefix and trim everything past mountpoint
	# echo translates \040 to spaces
	MOUNTED=${MOUNTED#* }
	MOUNTED=$(echo -n -e ${MOUNTED%% *})

	# for systems with different device names - check also mount output
	if test -z "$MOUNTED" ; then
		MOUNTED=$(LC_ALL=C "$MOUNT" | "$GREP" "^$VOLUME[ \t]")
		test -z "$MOUNTED" && MOUNTED=$(LC_ALL=C "$MOUNT" | "$GREP" "^$RVOLUME[ \t]")
		MOUNTED=${MOUNTED##* on }
		MOUNTED=${MOUNTED% type *} # allow type in the mount name
	fi

	test -n "$MOUNTED"
}

# get the full size of device in bytes
detect_device_size() {
	# check if blockdev supports getsize64
	"$BLOCKDEV" 2>&1 | "$GREP" getsize64 >"$NULL"
	if test $? -eq 0; then
		DEVSIZE=$("$BLOCKDEV" --getsize64 "$VOLUME") || error "Cannot read size of device \"$VOLUME\""
	else
		DEVSIZE=$("$BLOCKDEV" --getsize "$VOLUME") || error "Cannot read size of device \"$VOLUME\""
		SSSIZE=$("$BLOCKDEV" --getss "$VOLUME") || error "Cannot block size read device \"$VOLUME\""
		DEVSIZE=$(($DEVSIZE * $SSSIZE))
	fi
}

# round up $1 / $2
# could be needed to gaurantee 'at least given size'
# but it makes many troubles
round_up_block_size() {
	echo $(( ($1 + $2 - 1) / $2 ))
}

temp_mount() {
	dry "$MKDIR" -p -m 0000 "$TEMPDIR" || error "Failed to create $TEMPDIR"
	dry "$MOUNT" "$VOLUME" "$TEMPDIR" || error "Failed to mount $TEMPDIR"
}

temp_umount() {
	dry "$UMOUNT" "$TEMPDIR" || error "Failed to umount \"$TEMPDIR\""
	dry "$RMDIR" "${TEMPDIR}" || error "Failed to remove \"$TEMPDIR\""
	dry "$RMDIR" "${TEMPDIR%%m}" || error "Failed to remove \"${TEMPDIR%%m}\""
}

yes_no() {
	echo -n "$@? [Y|n] "

	if [ -n "$YES" ]; then
		echo y ; return 0
	fi

	while read -r -s -n 1 ANS ; do
		case "$ANS" in
		 "y" | "Y" | "") echo y ; return 0 ;;
		 "n" | "N") echo n ; return 1 ;;
		esac
	done
}

try_umount() {
	yes_no "Do you want to unmount \"$MOUNTED\"" && dry "$UMOUNT" "$MOUNTED" && return 0
	error "Cannot proceed with mounted filesystem \"$MOUNTED\""
}

validate_parsing() {
	test -n "$BLOCKSIZE" && test -n "$BLOCKCOUNT" || error "Cannot parse $1 output"
}
####################################
# Resize ext2/ext3/ext4 filesystem
# - unmounted or mounted for upsize
# - unmounted for downsize
####################################
resize_ext() {
	verbose "Parsing $TUNE_EXT -l \"$VOLUME\""
	for i in $(LC_ALL=C "$TUNE_EXT" -l "$VOLUME"); do
		case "$i" in
		  "Block size"*) BLOCKSIZE=${i##*  } ;;
		  "Block count"*) BLOCKCOUNT=${i##*  } ;;
		esac
	done
	validate_parsing "$TUNE_EXT"
	decode_size $1 $BLOCKSIZE
	FSFORCE=$FORCE

	if [ "$NEWBLOCKCOUNT" -lt "$BLOCKCOUNT" -o "$EXTOFF" -eq 1 ]; then
		detect_mounted && verbose "$RESIZE_EXT needs unmounted filesystem" && try_umount
		REMOUNT=$MOUNTED
		if test -n "$MOUNTED" ; then
			# Forced fsck -f for umounted extX filesystem.
			case "$-" in
			  *i*) dry "$FSCK" $YES -f "$VOLUME" ;;
			  *) dry "$FSCK" -f -p "$VOLUME" ;;
			esac
		fi
	fi

	verbose "Resizing filesystem on device \"$VOLUME\" to $NEWSIZE bytes ($BLOCKCOUNT -> $NEWBLOCKCOUNT blocks of $BLOCKSIZE bytes)"
	dry "$RESIZE_EXT" $FSFORCE "$VOLUME" $NEWBLOCKCOUNT
}

#############################
# Resize reiserfs filesystem
# - unmounted for upsize
# - unmounted for downsize
#############################
resize_reiser() {
	detect_mounted && verbose "ReiserFS resizes only unmounted filesystem" && try_umount
	REMOUNT=$MOUNTED
	verbose "Parsing $TUNE_REISER \"$VOLUME\""
	for i in $(LC_ALL=C "$TUNE_REISER" "$VOLUME"); do
		case "$i" in
		  "Blocksize"*) BLOCKSIZE=${i##*: } ;;
		  "Count of blocks"*) BLOCKCOUNT=${i##*: } ;;
		esac
	done
	validate_parsing "$TUNE_REISER"
	decode_size $1 $BLOCKSIZE
	verbose "Resizing \"$VOLUME\" $BLOCKCOUNT -> $NEWBLOCKCOUNT blocks ($NEWSIZE bytes, bs: $NEWBLOCKCOUNT)"
	if [ -n "$YES" ]; then
		echo y | dry "$RESIZE_REISER" -s $NEWSIZE "$VOLUME"
	else
		dry "$RESIZE_REISER" -s $NEWSIZE "$VOLUME"
	fi
}

########################
# Resize XFS filesystem
# - mounted for upsize
# - cannot downsize
########################
resize_xfs() {
	detect_mounted
	MOUNTPOINT=$MOUNTED
	if [ -z "$MOUNTED" ]; then
		MOUNTPOINT=$TEMPDIR
		temp_mount || error "Cannot mount Xfs filesystem"
	fi
	verbose "Parsing $TUNE_XFS \"$MOUNTPOINT\""
	for i in $(LC_ALL=C "$TUNE_XFS" "$MOUNTPOINT"); do
		case "$i" in
		  "data"*) BLOCKSIZE=${i##*bsize=} ; BLOCKCOUNT=${i##*blocks=} ;;
		esac
	done
	BLOCKSIZE=${BLOCKSIZE%%[^0-9]*}
	BLOCKCOUNT=${BLOCKCOUNT%%[^0-9]*}
	validate_parsing "$TUNE_XFS"
	decode_size $1 $BLOCKSIZE
	if [ $NEWBLOCKCOUNT -gt $BLOCKCOUNT ]; then
		verbose "Resizing Xfs mounted on \"$MOUNTPOINT\" to fill device \"$VOLUME\""
		dry "$RESIZE_XFS" $MOUNTPOINT
	elif [ $NEWBLOCKCOUNT -eq $BLOCKCOUNT ]; then
		verbose "Xfs filesystem already has the right size"
	else
		error "Xfs filesystem shrinking is unsupported"
	fi
}

####################
# Resize filesystem
####################
resize() {
	NEWSIZE=$2
	detect_fs "$1"
	detect_device_size
	verbose "Device \"$VOLUME\" size is $DEVSIZE bytes"
	# if the size parameter is missing use device size
	#if [ -n "$NEWSIZE" -a $NEWSIZE <
	test -z "$NEWSIZE" && NEWSIZE=${DEVSIZE}b
	IFS=$NL
	case "$FSTYPE" in
	  "ext3"|"ext2"|"ext4") resize_ext $NEWSIZE ;;
	  "reiserfs") resize_reiser $NEWSIZE ;;
	  "xfs") resize_xfs $NEWSIZE ;;
	  *) error "Filesystem \"$FSTYPE\" on device \"$VOLUME\" is not supported by this tool" ;;
	esac || error "Resize $FSTYPE failed"
	cleanup 0
}

####################################
# Calclulate diff between two dates
#  LC_ALL=C input is expected the
#  only one supported
####################################
diff_dates() {
         echo $(( $("$DATE" -u -d"$1" +%s 2>"$NULL") - $("$DATE" -u -d"$2" +%s 2>"$NULL") ))
}

###################
# Check filesystem
###################
check() {
	detect_fs "$1"
	if detect_mounted ; then
		verbose "Skipping filesystem check for device \"$VOLUME\" as the filesystem is mounted on $MOUNTED";
		cleanup 3
	fi

	case "$FSTYPE" in
	  "ext2"|"ext3"|"ext4")
		IFS_CHECK=$IFS
		IFS=$NL
		for i in $(LC_ALL=C "$TUNE_EXT" -l "$VOLUME"); do
			case "$i" in
			  "Last mount"*) LASTMOUNT=${i##*: } ;;
			  "Last checked"*) LASTCHECKED=${i##*: } ;;
			esac
		done
		case "$LASTMOUNT" in
		  *"n/a") ;; # nothing to do - system was not mounted yet
		  *)
			LASTDIFF=$(diff_dates $LASTMOUNT $LASTCHECKED)
			if test "$LASTDIFF" -gt 0 ; then
				verbose "Filesystem has not been checked after the last mount, using fsck -f"
				FORCE="-f"
			fi
			;;
		esac
		IFS=$IFS_CHECK
	esac

	case "$FSTYPE" in
	  "xfs") if which "$XFS_CHECK" >"$NULL" 2>&1 ; then
			dry "$XFS_CHECK" "$VOLUME"
		 else
			# Replacement for outdated xfs_check
			# FIXME: for small devices we need to force_geometry,
			# since we run in '-n' mode, it shouldn't be problem.
			# Think about better way....
			dry "$XFS_REPAIR" -n -o force_geometry "$VOLUME"
		 fi ;;
	  *)    # check if executed from interactive shell environment
		case "$-" in
		  *i*) dry "$FSCK" $YES $FORCE "$VOLUME" ;;
		  *) dry "$FSCK" $FORCE -p "$VOLUME" ;;
		esac
	esac
}

#############################
# start point of this script
# - parsing parameters
#############################
trap "cleanup 2" 2

# test if we are not invoked recursively
test -n "$FSADM_RUNNING" && exit 0

# test some prerequisities
for i in "$TUNE_EXT" "$RESIZE_EXT" "$TUNE_REISER" "$RESIZE_REISER" \
	"$TUNE_XFS" "$RESIZE_XFS" "$MOUNT" "$UMOUNT" "$MKDIR" \
	"$RMDIR" "$BLOCKDEV" "$BLKID" "$GREP" "$READLINK" \
	"$DATE" "$FSCK" "$XFS_CHECK" "$XFS_REPAIR" "$LVM" ; do
	test -n "$i" || error "Required command definitions in the script are missing!"
done

"$LVM" version >"$NULL" 2>&1 || error "Could not run lvm binary \"$LVM\""
$("$READLINK" -e / >"$NULL" 2>&1) || READLINK_E="-f"
TEST64BIT=$(( 1000 * 1000000000000 ))
test "$TEST64BIT" -eq 1000000000000000 || error "Shell does not handle 64bit arithmetic"
$(echo Y | "$GREP" Y >"$NULL") || error "Grep does not work properly"
test $("$DATE" -u -d"Jan 01 00:00:01 1970" +%s) -eq 1 || error "Date translation does not work"


if [ "$#" -eq 0 ] ; then
	tool_usage
fi

while [ "$#" -ne 0 ]
do
	 case "$1" in
	  "") ;;
	  "-h"|"--help") tool_usage ;;
	  "-v"|"--verbose") VERB="-v" ;;
	  "-n"|"--dry-run") DRY=1 ;;
	  "-f"|"--force") FORCE="-f" ;;
	  "-e"|"--ext-offline") EXTOFF=1 ;;
	  "-y"|"--yes") YES="-y" ;;
	  "-l"|"--lvresize") DO_LVRESIZE=1 ;;
	  "check") CHECK="$2" ; shift ;;
	  "resize") RESIZE="$2"; NEWSIZE="$3" ; shift 2 ;;
	  *) error "Wrong argument \"$1\". (see: $TOOL --help)"
	esac
	shift
done

test "$YES" = "-y" || YES=
test "$EXTOFF" -eq 1 || EXTOFF=0

if [ -n "$CHECK" ]; then
	check "$CHECK"
elif [ -n "$RESIZE" ]; then
	export FSADM_RUNNING="fsadm"
	resize "$RESIZE" "$NEWSIZE"
else
	error "Missing command. (see: $TOOL --help)"
fi
