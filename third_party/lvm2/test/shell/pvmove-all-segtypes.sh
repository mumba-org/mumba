#!/bin/sh
# Copyright (C) 2013 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

test_description="ensure pvmove works with all common segment types"

. lib/inittest

which md5sum || skip

aux prepare_pvs 5 20
vgcreate -s 256k $vg $(cat DEVICES)

# Each of the following tests does:
# 1) Create two LVs - one linear and one other segment type
#    The two LVs will share a PV.
# 2) Move both LVs together
# 3) Move only the second LV by name

# Testing pvmove of linear LV
lvcreate -aey -l 2 -n ${lv1}_foo $vg "$dev1"
lvcreate -aey -l 2 -n $lv1 $vg "$dev1"
check lv_tree_on $vg ${lv1}_foo "$dev1"
check lv_tree_on $vg $lv1 "$dev1"
aux mkdev_md5sum $vg $lv1
pvmove "$dev1" "$dev5"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check lv_tree_on $vg $lv1 "$dev5"
check dev_md5sum $vg $lv1
pvmove -n $lv1 "$dev5" "$dev4"
check lv_tree_on $vg $lv1 "$dev4"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check dev_md5sum $vg $lv1
lvremove -ff $vg

# Testing pvmove of stripe LV
lvcreate -aey -l 2 -n ${lv1}_foo $vg "$dev1"
lvcreate -aey -l 4 -i 2 -n $lv1 $vg "$dev1" "$dev2"
check lv_tree_on $vg ${lv1}_foo "$dev1"
check lv_tree_on $vg $lv1 "$dev1" "$dev2"
aux mkdev_md5sum $vg $lv1
pvmove "$dev1" "$dev5"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check lv_tree_on $vg $lv1 "$dev2" "$dev5"
check dev_md5sum $vg $lv1
pvmove -n $lv1 "$dev5" "$dev4"
check lv_tree_on $vg $lv1 "$dev2" "$dev4"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check dev_md5sum $vg $lv1
lvremove -ff $vg

if test -e LOCAL_CLVMD ; then
#FIXME these tests currently fail end require cmirrord
echo "$(should false)FIXME!!! pvmove in clustered VG not fully supported!"
else

# Testing pvmove of mirror LV
lvcreate -aey -l 2 -n ${lv1}_foo $vg "$dev1"
lvcreate -aey -l 2 --type mirror -m 1 -n $lv1 $vg "$dev1" "$dev2"
check lv_tree_on $vg ${lv1}_foo "$dev1"
check lv_tree_on $vg $lv1 "$dev1" "$dev2"
aux mkdev_md5sum $vg $lv1
pvmove "$dev1" "$dev5"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check lv_tree_on $vg $lv1 "$dev2" "$dev5"
check dev_md5sum $vg $lv1
pvmove -n $lv1 "$dev5" "$dev4"
check lv_tree_on $vg $lv1 "$dev2" "$dev4"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check dev_md5sum $vg $lv1
lvremove -ff $vg

# Dummy LV and snap share dev1, while origin is on dev2
# Testing pvmove of snapshot LV
lvcreate -aey -l 2 -n ${lv1}_foo $vg "$dev1"
lvcreate -aey -l 2 -n $lv1 $vg "$dev2"
lvcreate -s $vg/$lv1 -l 2 -n snap "$dev1"
check lv_tree_on $vg ${lv1}_foo "$dev1"
check lv_tree_on $vg snap "$dev1"
aux mkdev_md5sum $vg snap
pvmove "$dev1" "$dev5"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check lv_tree_on $vg snap "$dev5"
check dev_md5sum $vg snap
pvmove -n snap "$dev5" "$dev4"
check lv_tree_on $vg snap "$dev4"
check lv_tree_on $vg ${lv1}_foo "$dev5"
check dev_md5sum $vg snap
lvremove -ff $vg
fi

vgremove -ff $vg
