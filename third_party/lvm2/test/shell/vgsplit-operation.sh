#!/bin/sh
# Copyright (C) 2007 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Test vgsplit operation, including different LV types

# disable lvmetad logging as it bogs down test systems
export LVM_TEST_LVMETAD_DEBUG_OPTS=${LVM_TEST_LVMETAD_DEBUG_OPTS-}

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

COMM() {
	LAST_TEST="$@"
}

create_vg_() {
	vgcreate -s 64k "$@"
}

aux prepare_pvs 5 10
# FIXME: paramaterize lvm1 vs lvm2 metadata; most of these tests should run
# fine with lvm1 metadata as well; for now, just add disks 5 and 6 as lvm1
# metadata

#
# vgsplit can be done into a new or existing VG
#
for i in new existing
do
	#
	# We can have PVs or LVs on the cmdline
	#
	for j in PV LV
	do
COMM "vgsplit correctly splits single linear LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2"
		test $i = existing && create_vg_ $vg2 "$dev3" "$dev4"

		lvcreate -an -Zn -l 4 -n $lv1 $vg1 "$dev1"
		if [ $j = PV ]; then
		  vgsplit $vg1 $vg2 "$dev1"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		check pvlv_counts $vg1 1 0 0
		if [ $i = existing ]; then
		   check pvlv_counts $vg2 3 1 0
		else
		   check pvlv_counts $vg2 1 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg2 $vg1

COMM "vgsplit correctly splits single striped LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2"
		test $i = existing && create_vg_ $vg2 "$dev3" "$dev4"

		lvcreate -an -Zn -l 4 -i 2 -n $lv1 $vg1 "$dev1" "$dev2"
		if [ $j = PV ]; then
		  vgsplit $vg1 $vg2 "$dev1" "$dev2"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 4 1 0
		else
		  check pvlv_counts $vg2 2 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg2

COMM "vgsplit correctly splits mirror LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2" "$dev3"
		test $i = existing && create_vg_ $vg2 "$dev4"

		lvcreate -an -Zn -l 64 --type mirror -m1 -n $lv1 $vg1 "$dev1" "$dev2" "$dev3"
		if [ $j = PV ]; then
		  # FIXME: Not an exhaustive check of possible bad combinations
		  not vgsplit $vg1 $vg2 "$dev1" "$dev2"
		  not vgsplit $vg1 $vg2 "$dev1" "$dev3"
		  not vgsplit $vg1 $vg2 "$dev2" "$dev3"
		  vgsplit $vg1 $vg2 "$dev1" "$dev2" "$dev3"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 4 1 0
		else
		  check pvlv_counts $vg2 3 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg2

# RHBZ 875903
COMM "vgsplit correctly splits mirror (log+leg on same dev) into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2" "$dev3"
		test $i = existing && create_vg_ $vg2 "$dev4"

		lvcreate -an -Zn -l 64 --type mirror -m1 -n $lv1 $vg1 "$dev1" "$dev2"
		if [ $j = PV ]; then
		  not vgsplit $vg1 $vg2 "$dev1"
		  not vgsplit $vg1 $vg2 "$dev2"
		  vgsplit $vg1 $vg2 "$dev1" "$dev2"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 3 1 0
		else
		  check pvlv_counts $vg2 2 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg1 $vg2

# Can't use mirrored log without cmirrord
# TODO: Should work for inactive device, needs some fixes....
if test ! -e LOCAL_CLVMD ; then
COMM "vgsplit correctly splits mirror LV with mirrored log into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
		test $i = existing && create_vg_ $vg2 "$dev5"

		lvcreate -an -Zn -l 64 --mirrorlog mirrored --type mirror -m1 -n $lv1 $vg1 \
		    "$dev1" "$dev2" "$dev3" "$dev4"

		if [ $j = PV ]; then
		  # FIXME: Not an exhaustive check of possible bad combinations
		  not vgsplit $vg1 $vg2 "$dev1" "$dev2"
		  not vgsplit $vg1 $vg2 "$dev3" "$dev4"
		  not vgsplit $vg1 $vg2 "$dev1" "$dev3"
		  not vgsplit $vg1 $vg2 "$dev2" "$dev4"
		  vgsplit $vg1 $vg2 "$dev1" "$dev2" "$dev3" "$dev4"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 5 1 0
		else
		  check pvlv_counts $vg2 4 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg2

# RHBZ 875903
COMM "vgsplit correctly splits mirror LV with mirrored log on same devs into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
		test $i = existing && create_vg_ $vg2 "$dev5"

		lvcreate -an -Zn -l 64 --mirrorlog mirrored --type mirror -m1 -n $lv1 $vg1 \
		    "$dev1" "$dev2"

		if [ $j = PV ]; then
		  not vgsplit $vg1 $vg2 "$dev1"
		  not vgsplit $vg1 $vg2 "$dev2"
		  vgsplit $vg1 $vg2 "$dev1" "$dev2"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 3 1 0
		else
		  check pvlv_counts $vg2 2 1 0
		fi
		lvremove -f $vg2/$lv1
		vgremove -f $vg1 $vg2
fi

COMM "vgsplit correctly splits origin and snapshot LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2"
		test $i = existing && create_vg_ $vg2 "$dev3" "$dev4"

		lvcreate -aey -l 64 -i 2 -n $lv1 $vg1 "$dev1" "$dev2"
		lvcreate -l 4 -i 2 -s -n $lv2 $vg1/$lv1
		vgchange -an $vg1
		if [ $j = PV ]; then
		  vgsplit $vg1 $vg2 "$dev1" "$dev2"
		else
		  vgsplit -n $lv1 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 4 2 1
		else
		  check pvlv_counts $vg2 2 2 1
		fi
		lvremove -f $vg2/$lv2
		lvremove -f $vg2/$lv1
		vgremove -f $vg2

COMM "vgsplit correctly splits linear LV but not snap+origin LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2"
		test $i = existing && create_vg_ $vg2 "$dev3"

		lvcreate -aey -l 64 -i 2 -n $lv1 $vg1
		lvcreate -l 4 -i 2 -s -n $lv2 $vg1/$lv1
		vgextend $vg1 "$dev4"
		lvcreate -l 64 -n $lv3 $vg1 "$dev4"
		vgchange -an $vg1
		if [ $j = PV ]; then
		  vgsplit $vg1 $vg2 "$dev4"
		else
		  vgsplit -n $lv3 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg2 2 1 0
		  check pvlv_counts $vg1 2 2 1
		else
		  check pvlv_counts $vg2 1 1 0
		  check pvlv_counts $vg1 2 2 1
		fi
		lvremove -f $vg1/$lv2
		lvremove -f $vg1/$lv1 $vg2/$lv3
		vgremove -f $vg1 $vg2

COMM "vgsplit correctly splits linear LV but not mirror LV into $i VG ($j args)"
		create_vg_ $vg1 "$dev1" "$dev2" "$dev3"
		test $i = existing && create_vg_ $vg2 "$dev5"

		lvcreate -an -Zn -l 64 --type mirror -m1 -n $lv1 $vg1 "$dev1" "$dev2" "$dev3"
		vgextend $vg1 "$dev4"
		lvcreate -an -Zn -l 64 -n $lv2 $vg1 "$dev4"
		if [ $j = PV ]; then
		  vgsplit $vg1 $vg2 "$dev4"
		else
		  vgsplit -n $lv2 $vg1 $vg2
		fi
		if [ $i = existing ]; then
		  check pvlv_counts $vg1 3 1 0
		  check pvlv_counts $vg2 2 1 0
		else
		  check pvlv_counts $vg1 3 1 0
		  check pvlv_counts $vg2 1 1 0
		fi
		vgremove -f $vg1 $vg2
	done
done

#
# Test more complex setups where the code has to find associated PVs and
# LVs to split the VG correctly
#
COMM "vgsplit fails splitting 3 striped LVs into VG when only 1 LV specified"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -an -Zn -l 4 -n $lv1 -i 2 $vg1 "$dev1" "$dev2"
lvcreate -an -Zn -l 4 -n $lv2 -i 2 $vg1 "$dev2" "$dev3"
lvcreate -an -Zn -l 4 -n $lv3 -i 2 $vg1 "$dev3" "$dev4"
not vgsplit -n $lv1 $vg1 $vg2
vgremove -f $vg1

COMM "vgsplit fails splitting one LV with 2 snapshots, only origin LV specified"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -aey -l 16 -n $lv1 $vg1 "$dev1" "$dev2"
lvcreate -l 4 -n $lv2 -s $vg1/$lv1 "$dev3"
lvcreate -l 4 -n $lv3 -s $vg1/$lv1 "$dev4"
check pvlv_counts $vg1 4 3 2
vgchange -an $vg1
not vgsplit -n $lv1 $vg1 $vg2;
lvremove -f $vg1/$lv2 $vg1/$lv3
lvremove -f $vg1/$lv1
vgremove -f $vg1

COMM "vgsplit fails splitting one LV with 2 snapshots, only snapshot LV specified"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -aey -l 16 -n $lv1 $vg1 "$dev1" "$dev2"
lvcreate -l 4 -n $lv2 -s $vg1/$lv1 "$dev3"
lvcreate -l 4 -n $lv3 -s $vg1/$lv1 "$dev4"
check pvlv_counts $vg1 4 3 2
vgchange -an $vg1
not vgsplit -n $lv2 $vg1 $vg2
lvremove -f $vg1/$lv2 $vg1/$lv3
lvremove -f $vg1/$lv1
vgremove -f $vg1

COMM "vgsplit fails splitting one mirror LV, only one PV specified"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -an -Zn -l 16 -n $lv1 --type mirror -m1 $vg1 "$dev1" "$dev2" "$dev3"
check pvlv_counts $vg1 4 1 0
not vgsplit $vg1 $vg2 "$dev2"
vgremove -ff $vg1

COMM "vgsplit fails splitting 1 mirror + 1 striped LV, only striped LV specified"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -an -Zn -l 16 -n $lv1 --type mirror --nosync -m1 $vg1 "$dev1" "$dev2" "$dev3"
lvcreate -an -Zn -l 16 -n $lv2 -i 2 $vg1 "$dev3" "$dev4"
check pvlv_counts $vg1 4 2 0
not vgsplit -n $lv2 $vg1 $vg2 2>err
vgremove -f $vg1

#
# Verify vgsplit rejects active LVs only when active LVs involved in split
#
COMM "vgsplit fails, active mirror involved in split"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -aey -l 16 -n $lv1 --type mirror --nosync -m1 $vg1 "$dev1" "$dev2" "$dev3"
lvcreate -l 16 -n $lv2 $vg1 "$dev4"
lvchange -an $vg1/$lv2
check pvlv_counts $vg1 4 2 0
not vgsplit -n $lv1 $vg1 $vg2;
check pvlv_counts $vg1 4 2 0
vgremove -f $vg1

COMM "vgsplit succeeds, active mirror not involved in split"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -aey -l 16 -n $lv1 --type mirror --nosync -m1 $vg1 "$dev1" "$dev2" "$dev3"
lvcreate -l 16 -n $lv2 $vg1 "$dev4"
lvchange -an $vg1/$lv2
check pvlv_counts $vg1 4 2 0
vgsplit -n $lv2 $vg1 $vg2
check pvlv_counts $vg1 3 1 0
check pvlv_counts $vg2 1 1 0
vgremove -f $vg1 $vg2

COMM "vgsplit fails, active snapshot involved in split"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3" "$dev4"
lvcreate -aey -l 64 -i 2 -n $lv1 $vg1 "$dev1" "$dev2"
lvcreate -l 4 -i 2 -s -n $lv2 $vg1/$lv1
lvcreate -an -Zn -l 64 -i 2 -n $lv3 $vg1 "$dev3" "$dev4"
check pvlv_counts $vg1 4 3 1
not vgsplit -n $lv2 $vg1 $vg2;
check pvlv_counts $vg1 4 3 1
lvremove -f $vg1/$lv2
vgremove -f $vg1

COMM "vgsplit succeeds, active snapshot not involved in split"
create_vg_ $vg1 "$dev1" "$dev2" "$dev3"
lvcreate -aey -l 64 -i 2 -n $lv1 $vg1 "$dev1" "$dev2"
lvcreate -l 4 -s -n $lv2 $vg1/$lv1
vgextend $vg1 "$dev4"
lvcreate -an -Zn -l 64 -n $lv3 $vg1 "$dev4"
check pvlv_counts $vg1 4 3 1
vgsplit -n $lv3 $vg1 $vg2
check pvlv_counts $vg1 3 2 1
check pvlv_counts $vg2 1 1 0
vgchange -an $vg1
lvremove -f $vg1/$lv2
vgremove -f $vg1 $vg2
