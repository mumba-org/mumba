#!/bin/sh
# Copyright (C) 2008-2014 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#
# tests functionality we don't have in other special test files yet
# to improve code coverage
#

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux prepare_pvs 5
get_devs

pvcreate --metadatacopies 0 "$dev2"
pvcreate --metadatacopies 0 "$dev3"

# FIXME takes very long time
#pvck "$dev1"

vgcreate $vg "${DEVICES[@]}"

lvcreate -l 5 -i5 -I256 -n $lv $vg
lvcreate -aey -l 5 -n $lv1 $vg
lvcreate -s -l 5 -n $lv2 $vg/$lv1
pvck "$dev1"

# "-persistent y --major 254 --minor 20"
# "-persistent n"
for i in pr "p rw" "-monitor y" "-monitor n" -refresh; do
	lvchange -$i $vg/$lv
done

lvrename $vg $lv $lv-rename
invalid lvrename $vg
invalid lvrename $vg $vg/$lv-rename $vg1/$lv
invalid lvrename $vg/$lv-rename $vg1/$lv $vg
invalid lvrename $vg/$lv-rename $vg/012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
invalid lvrename $vg/$lv-rename $vg/""
invalid lvrename $vg/$lv-rename "$vg/!@#$%"
invalid lvrename $vg/$lv-rename $vg/$lv-rename
fail lvrename $vg1/$lv-rename $vg1/$lv

vgremove -f $vg


# test pvresize functionality
# missing params
not pvresize
# negative size
not pvresize --setphysicalvolumesize -10M "$dev1"
# not existing device
not pvresize --setphysicalvolumesize 10M "$dev7"
pvresize --setphysicalvolumesize 10M "$dev1"
pvresize "$dev1"


# test various lvm utils
lvm dumpconfig
lvm devtypes
lvm formats
lvm segtypes
lvm tags


# test obsoleted tools
not lvm lvmchange
not lvm lvmsadc
not lvm lvmsar
not lvm pvdata
