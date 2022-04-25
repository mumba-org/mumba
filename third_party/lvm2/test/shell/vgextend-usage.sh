#!/bin/sh
# Copyright (C) 2008 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#
# Exercise various vgextend commands
#

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux prepare_devs 5

for mdatype in 1 2
do

# Explicit pvcreate
pvcreate -M$mdatype "$dev1" "$dev2" "$dev3" "$dev4" "$dev5"
vgcreate -M$mdatype $vg1 "$dev1" "$dev2"
vgextend $vg1 "$dev3" "$dev4" "$dev5"
vgremove -ff $vg1

# Implicit pvcreate
pvremove "$dev1" "$dev2" "$dev3" "$dev4" "$dev5"
vgcreate -M$mdatype $vg1 "$dev1" "$dev2"
vgextend -M$mdatype $vg1 "$dev3" "$dev4" "$dev5"
vgremove -ff $vg1
pvremove "$dev1" "$dev2" "$dev3" "$dev4" "$dev5"

done

# Implicit pvcreate tests, test pvcreate options on vgcreate
# --force, --yes, --metadata{size|copies|type}, --zero
# --dataalignment[offset]
vgcreate $vg "$dev2"
vgextend --force --yes --zero y $vg "$dev1"
vgreduce $vg "$dev1"
pvremove -f "$dev1"

for i in 0 1 2 3
do
# vgcreate (lvm2) succeeds writing LVM label at sector $i
    vgextend --labelsector $i $vg "$dev1"
    dd if="$dev1" bs=512 skip=$i count=1 2>/dev/null | strings | grep LABELONE >/dev/null
    vgreduce $vg "$dev1"
    pvremove -f "$dev1"
done

# pvmetadatacopies
for i in 0 1 2
do
    vgextend --pvmetadatacopies $i $vg "$dev1"
    check pv_field "$dev1" pv_mda_count $i
    vgreduce $vg "$dev1"
    pvremove -f "$dev1"
done

# metadatasize, dataalignment, dataalignmentoffset
#COMM 'pvcreate sets data offset next to mda area'
vgextend --metadatasize 100k --dataalignment 100k $vg "$dev1"
check pv_field "$dev1" pe_start 200.00k
vgreduce $vg "$dev1"
pvremove -f "$dev1"

# data area is aligned to 1M by default,
# data area start is shifted by the specified alignment_offset
pv_align=1052160B # 1048576 + (7*512)
vgextend --metadatasize 128k --dataalignmentoffset 7s $vg "$dev1"
check pv_field "$dev1" pe_start $pv_align --units b
vgremove -f $vg
pvremove -f "$dev1"

# vgextend fails if pv belongs to existing vg
vgcreate $vg1 "$dev1" "$dev3"
vgcreate $vg2 "$dev2"
not vgextend $vg2 "$dev3"
vgremove -f $vg1
vgremove -f $vg2
pvremove -f "$dev1" "$dev2" "$dev3"

#vgextend fails if vg is not resizeable
vgcreate $vg1 "$dev1" "$dev2"
vgchange --resizeable n $vg1
not vgextend $vg1 "$dev3"
vgremove -f $vg1
pvremove -f "$dev1" "$dev2"

# all PVs exist in the VG after extended
pvcreate "$dev1"
vgcreate $vg1 "$dev2"
vgextend $vg1 "$dev1" "$dev3"
check pv_field "$dev1" vg_name $vg1
check pv_field "$dev2" vg_name $vg1
check pv_field "$dev3" vg_name $vg1
vgremove -f $vg1
pvremove -f "$dev1" "$dev2" "$dev3"

echo test vgextend --metadataignore
for mdacp in 1 2; do
for ignore in y n; do
	echo vgextend --metadataignore has proper mda_count and mda_used_count
	vgcreate $vg "$dev3"
	vgextend --metadataignore $ignore --pvmetadatacopies $mdacp $vg "$dev1" "$dev2"
	check pv_field "$dev1" pv_mda_count $mdacp
	check pv_field "$dev2" pv_mda_count $mdacp
	if [ $ignore = y ]; then
		check pv_field "$dev1" pv_mda_used_count 0
		check pv_field "$dev2" pv_mda_used_count 0
	else
		check pv_field "$dev1" pv_mda_used_count $mdacp
		check pv_field "$dev2" pv_mda_used_count $mdacp
	fi
	echo vg has proper vg_mda_count and vg_mda_used_count
	check vg_field $vg vg_mda_count $(($mdacp * 2 + 1))
	if [ $ignore = y ]; then
		check vg_field $vg vg_mda_used_count 1
	else
		check vg_field $vg vg_mda_used_count $(($mdacp * 2 + 1))
	fi
	check vg_field $vg vg_mda_copies unmanaged
	vgremove $vg
	pvremove -ff "$dev1" "$dev2" "$dev3"
done
done
