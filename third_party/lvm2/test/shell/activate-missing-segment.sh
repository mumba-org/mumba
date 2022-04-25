#!/bin/sh
# Copyright (C) 2010 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Test activation behaviour with devices missing.
# - snapshots and their origins are only activated together; if one fails, both
#   fail
# - partial mirrors are not activated (but maybe they should? maybe we should
#   instead lvconvert --repair them?)
# - linear LVs with bits missing are not activated

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux prepare_vg 2

lvcreate -l100%FREE -n span $vg
vgchange -a n $vg

aux disable_dev "$dev1"
not vgchange -a y $vg
vgchange -a y --partial $vg
check active $vg span

vgremove -ff $vg
