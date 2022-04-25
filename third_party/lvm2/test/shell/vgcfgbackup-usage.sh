#!/bin/sh
# Copyright (C) 2008-2013 Red Hat, Inc. All rights reserved.
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

aux prepare_pvs 4

pvcreate --metadatacopies 0 "$dev4"

# No automatic backup
aux lvmconf "backup/backup = 0"

# vgcfgbackup handles similar VG names (bz458941)
vg1=${PREFIX}vg00
vg2=${PREFIX}vg01
vgcreate $vg1 "$dev1"
vgcreate $vg2 "$dev2"

# Enforces system backup
test ! -e etc/backup/$vg1
test ! -e etc/backup/$vg2
vgcfgbackup
test -e etc/backup/$vg1
test -e etc/backup/$vg2

aux lvmconf "backup/archive = 1"

vgcfgbackup -f "bak-%s" >out
grep "Volume group \"$vg1\" successfully backed up." out
grep "Volume group \"$vg2\" successfully backed up." out
# increase seqno
lvcreate -an -Zn -l1 $vg1

invalid vgcfgrestore -f "bak-$vg1" $vg1-inv@lid
invalid vgcfgrestore -f "bak-$vg1" $vg1 $vg2

vgcfgrestore -l $vg1 | tee out
test $(grep Description out | wc -l) -eq 2

vgcfgrestore -l -f "bak-$vg1" $vg1

vgremove -ff $vg1 $vg2

# vgcfgbackup correctly stores metadata with missing PVs
# and vgcfgrestore able to restore them when device reappears
pv1_uuid=$(get pv_field "$dev1" pv_uuid)
pv2_uuid=$(get pv_field "$dev2" pv_uuid)
vgcreate $vg $(cat DEVICES)
lvcreate -l1 -n $lv1 $vg "$dev1"
lvcreate -l1 -n $lv2 $vg "$dev2"
lvcreate -l1 -n $lv3 $vg "$dev3"
vgchange -a n $vg
pvcreate -ff -y "$dev1"
pvcreate -ff -y "$dev2"
vgcfgbackup -f "backup.$$" $vg
sed 's/flags = \[\"MISSING\"\]/flags = \[\]/' "backup.$$" > "backup.$$1"
pvcreate -ff -y --norestorefile -u $pv1_uuid "$dev1"
pvcreate -ff -y --norestorefile -u $pv2_uuid "$dev2"

# Try to recover nonexisting vgname
not vgcfgrestore -f "backup.$$1" ${vg}_nonexistent
vgcfgrestore -f "backup.$$1" $vg
vgchange -an $vg
vgremove -f $vg


# vgcfgbackup correctly stores metadata LVM1 with missing PVs
# FIXME: clvmd seems to have problem with metadata format change here
# fix it and remove this vgscan
vgscan
pvcreate -M1 $(cat DEVICES)
vgcreate -M1 -c n $vg $(cat DEVICES)
lvcreate -l1 -n $lv1 $vg "$dev1"
pvremove -ff -y "$dev2"
not lvcreate -l1 -n $lv1 $vg "$dev3"
vgcfgbackup -f "backup.$$" $vg
