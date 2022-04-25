#!/bin/sh
# Copyright (C) 2008-2012 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

test_description='Hello world for vgcreate with lvmlockd and sanlock'

. lib/inittest

[ -z "$LVM_TEST_LOCK_TYPE_SANLOCK" ] && skip;

aux prepare_pvs 1

vgcreate $SHARED $vg "$dev1"

vgs -o+locktype,lockargs $vg

check vg_field $vg vg_locktype sanlock

vgremove $vg

