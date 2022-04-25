#!/bin/sh
# Copyright (C) 2014 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Test resize of thin volume with external origin

export LVM_TEST_THIN_REPAIR_CMD=${LVM_TEST_THIN_REPAIR_CMD-/bin/false}

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux have_thin 1 2 0 || skip

# Pretend we miss the external_origin_extend feature
aux lvmconf 'global/thin_disabled_features = [ "external_origin_extend" ]'

aux prepare_pvs 2

vgcreate -s 1M $vg $(cat DEVICES)

lvcreate -L10 -n $lv1 $vg

# Prepare thin pool
lvcreate -L20 -T $vg/pool

# Convert $lv1 into thin LV with external origin
lvconvert -T $vg/$lv1 --thinpool $vg/pool --originname ext

lvs -a $vg

# Bigger size is not supported without feature external_origin_extend
not lvresize -L+10 $vg/$lv1

# But reduction works
lvresize -L-5 -f $vg/$lv1
check lv_field $vg/$lv1 lv_size "5.00" --units m --nosuffix

not lvresize -L+15 -y $vg/$lv1
check lv_field $vg/$lv1 lv_size "5.00" --units m --nosuffix

# Try to resize again back up to the size of external origin
lvresize -L+5 -f $vg/$lv1
check lv_field $vg/$lv1 lv_size "10.00" --units m --nosuffix
