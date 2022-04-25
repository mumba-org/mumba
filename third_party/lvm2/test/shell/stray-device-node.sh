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

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux prepare_devs 3
cp -r "$dev1" "$DM_DEV_DIR/stray"

vgcreate $vg $(cat DEVICES)
lvcreate -an -Zn --type mirror -m 1 -l 1 -n mirror $vg
aux disable_dev "$dev1"
# FIXME:
# for the .cache use case we need to run pvscan
# to keep clvmd in sync.
pvscan
vgreduce --removemissing --force $vg
aux enable_dev "$dev1"
