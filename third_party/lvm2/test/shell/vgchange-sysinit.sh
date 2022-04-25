#!/bin/sh
# Copyright (C) 2011 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

. lib/inittest

test -e LOCAL_CLVMD && skip
test -e LOCAL_LVMPOLLD && skip

which mkfs.ext3 || skip

aux prepare_pvs 2 8

var_lock="$DM_DEV_DIR/$vg1/$lv1"
# keep in sync with aux configured lockingdir
mount_dir="var/lock/lvm"

cleanup_mounted_and_teardown()
{
	umount "$mount_dir" || true
	aux teardown
}

vgcreate $vg1 "$dev1"
vgcreate $vg2 "$dev2"

lvcreate -l 1 -n $lv2 $vg2
vgchange -an $vg2

lvcreate -n $lv1 -l 100%FREE $vg1
mkfs.ext3 -b4096 -j "$var_lock"

trap 'cleanup_mounted_and_teardown' EXIT
mount -n -r "$var_lock" "$mount_dir"

# locking must fail on read-only filesystem
not vgchange -ay $vg2

# no-locking with --sysinit
vgchange --sysinit -ay $vg2
test -b "$DM_DEV_DIR/$vg2/$lv2"

vgchange --sysinit -an $vg2
test ! -b "$DM_DEV_DIR/$vg2/$lv2"

vgchange --ignorelockingfailure -ay $vg2

# TODO maybe also support --ignorelockingfailure ??
vgremove --config 'global{locking_type=0}' -ff $vg2
umount "$mount_dir" || true
vgremove -ff $vg1
