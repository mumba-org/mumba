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

# 'Exercise some lvcreate diagnostics'

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

# FIXME  update test to make something useful on <16T
aux can_use_16T || skip

aux prepare_vg 4

lvcreate --type snapshot -s -l 100%FREE -n $lv $vg --virtualsize 1024T

#FIXME this should be 1024T
#check lv_field $vg/$lv size "128.00m"

aux extend_filter_LVMTEST

pvcreate "$DM_DEV_DIR/$vg/$lv"
vgcreate $vg1 "$DM_DEV_DIR/$vg/$lv"

lvcreate -l 100%FREE -n $lv1 $vg1
check lv_field $vg1/$lv1 size "1024.00t"
lvresize -f -l 72%VG $vg1/$lv1
check lv_field $vg1/$lv1 size "737.28t"
lvremove -ff $vg1/$lv1

lvcreate -l 100%VG -n $lv1 $vg1
check lv_field $vg1/$lv1 size "1024.00t"
lvresize -f -l 72%VG $vg1/$lv1
check lv_field $vg1/$lv1 size "737.28t"
lvremove -ff $vg1/$lv1

lvremove -ff $vg/$lv

vgremove -ff $vg
