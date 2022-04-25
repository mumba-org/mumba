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

test_description='Remove the dlm test setup'

. lib/inittest

[ -z "$LVM_TEST_LOCK_TYPE_DLM" ] && skip;

# FIXME: collect debug logs (only if a test failed?)
# lvmlockctl -d > lvmlockd-debug.txt
# dlm_tool dump > dlm-debug.txt

systemctl stop dlm
systemctl stop corosync
killall lvmlockd
