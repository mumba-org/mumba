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

. lib/inittest

test -e LOCAL_LVMPOLLD && skip

aux prepare_vg 3

pvchange --metadataignore y "$dev1"

lvcreate -aey --type mirror -m 1 -l 1 -n mirror $vg
lvchange -a n $vg/mirror
lvcreate -l 1 -n lv1 $vg "$dev1"

# try to just change metadata; we expect the new version (with MISSING_PV set
# on the reappeared volume) to be written out to the previously missing PV
aux disable_dev "$dev1"
lvremove $vg/mirror
not vgck $vg 2>&1 | tee log
grep "missing 1 physical volume" log
not lvcreate -aey --type mirror -m 1 -l 1 -n mirror $vg # write operations fail
aux enable_dev "$dev1"
lvcreate -aey --type mirror -m 1 -l 1 -n mirror $vg # no MDA => automatically restored
vgck $vg
