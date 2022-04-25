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

# Test repairing of broken thin pool on raid

. lib/inittest

test -e LOCAL_LVMPOLLD && skip
aux have_thin 1 0 0 || skip
aux have_raid 1 4 0 || skip

#
# Main
#

aux prepare_vg 4

lvcreate --type raid1 -L1 -n pool $vg
lvcreate --type raid1 -L2 -n meta $vg
# raid _tdata & _tmeta
lvconvert -y --thinpool $vg/pool --poolmetadata $vg/meta

lvcreate -V1G $vg/pool

# Pool has to be inactive (ATM) for repair
fail lvconvert -y --repair $vg/pool "$dev3"

lvchange -an $vg

check lv_field $vg/pool_tmeta lv_role "private,thin,pool,metadata"

lvconvert -y --repair $vg/pool "$dev3"

lvs -a -o+devices,seg_pe_ranges,role,layout $vg
check lv_field $vg/pool_meta0 lv_role "public"
check lv_field $vg/pool_meta0 lv_layout "raid,raid1"
check lv_field $vg/pool_tmeta lv_layout "linear"
check lv_on $vg pool_tmeta "$dev1"

# Hmm name is generated in order
SPARE=$(lvs --noheadings -a --select "name=~_pmspare" -o name $vg)
SPARE=${SPARE##*[}
SPARE=${SPARE%%]*}

check lv_on $vg $SPARE "$dev3"

lvchange -ay $vg

vgremove -ff $vg
