#!/bin/sh
# Copyright (C) 2015 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Exercise creation of cache and raids

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux have_cache 1 3 0 || skip
aux have_raid 1 0 0 || skip

# FIXME: parallel cache metadata allocator is crashing when used value 8000!
aux prepare_vg 5 80000

aux lvmconf 'global/cache_disabled_features = [ "policy_smq" ]'

# Bug 1110026 & Bug 1095843
# Create RAID1 origin, then cache pool and cache
lvcreate -aey -l 2 --type raid1 -m1 -n $lv2 $vg
lvcreate --cache -l 1 $vg/$lv2
check lv_exists $vg/${lv2}_corig_rimage_0	# ensure images are properly renamed
check active $vg ${lv2}_corig
dmsetup table ${vg}-$lv2 | grep cache		# ensure it is loaded in kernel

vgremove -ff $vg
