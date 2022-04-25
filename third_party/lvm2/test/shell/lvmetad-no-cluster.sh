#!/bin/sh
# Copyright (C) 2012 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

. lib/inittest

test -e LOCAL_CLVMD || skip
test -e LOCAL_LVMPOLLD && skip

aux prepare_vg 2
aux prepare_lvmetad
vgs -vv 2> errs
cat errs
grep 'use_lvmetad' errs

vgremove -ff $vg
