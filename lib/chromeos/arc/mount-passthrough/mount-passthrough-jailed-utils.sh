#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Defines a wrapper function to run mount-passthrough with minijail0.

# TODO(b/123669632): Remove the argument |force_group_permission| and related
# logic once we start to run the daemon as MediaProvider UID and GID from
# mount-passthrough-jailed-play.
run_mount_passthrough_with_minijail0() {
  if [ $# -ne 13 ]; then
    echo "Usage: $0 source dest fuse_umask fuse_uid fuse_gid"\
      "android_app_access_type daemon_uid daemon_gid"\
      "inherit_supplementary_groups grant_cap_dac_override"\
      "force_group_permission" "enter_concierge_namespace" \
      "max_number_of_open_fds"
    exit 1
  fi

  local source="${1}"
  local dest="${2}"
  local fuse_umask="${3}"
  local fuse_uid="${4}"
  local fuse_gid="${5}"
  local android_app_access_type="${6}"
  local daemon_uid="${7}"
  local daemon_gid="${8}"
  local inherit_supplementary_groups="${9}"
  local grant_cap_dac_override="${10}"
  local force_group_permission="${11}"
  local enter_concierge_namespace="${12}"
  local max_number_of_open_fds="${13}"

  # Specify the maximum number of file descriptors the process can open.
  ulimit -n "${max_number_of_open_fds}"

  # Start constructing minijail0 args...
  set --

  if [ "${enter_concierge_namespace}" = "true" ]; then
    # Enter the concierge namespace.
    set -- "$@" -V /run/namespaces/mnt_concierge
  else
    # Use minimalistic-mountns profile.
    set -- "$@" --profile=minimalistic-mountns
  fi

  # Enter a new cgroup namespace.
  set -- "$@" -N

  # Enter a new UTS namespace.
  set -- "$@" --uts

  # Enter a new VFS namespace and remount /proc read-only.
  set -- "$@" -v -r

  # Enter a new network namespace.
  set -- "$@" -e

  # Enter a new IPC namespace.
  set -- "$@" -l

  # Grant CAP_SYS_ADMIN needed to mount FUSE filesystem.
  # Also, additionally grant CAP_DAC_OVERRIDE when specified so in order to
  # access all files in the source regardless of the daemon's UID and GID.
  if [ "${grant_cap_dac_override}" = "true" ]; then
    set -- "$@" -c 'cap_dac_override,cap_sys_admin+eip'
  else
    set -- "$@" -c 'cap_sys_admin+eip'
  fi

  # Set uid and gid of the daemon.
  set -- "$@" -u "${daemon_uid}" -g "${daemon_gid}"

  # Inherit supplementary groups if specified so.
  if [ "${inherit_supplementary_groups}" = "true" ]; then
    set -- "$@" -G
  fi

  # Allow sharing mounts between CrOS and Android.
  # WARNING: BE CAREFUL not to unexpectedly expose shared mounts in following
  # bind mounts! Always remount them with MS_REC|MS_PRIVATE unless you want to
  # share those mounts explicitly.
  set -- "$@" -K

  local source_in_minijail="${source}"
  local dest_in_minijail="${dest}"

  if [ "${enter_concierge_namespace}" != "true" ]; then
    # Set up the source and destination under /mnt inside the new namespace.
    source_in_minijail=/mnt/source
    dest_in_minijail=/mnt/dest

    # Mount tmpfs on /mnt.
    set -- "$@" -k "tmpfs,/mnt,tmpfs,MS_NOSUID|MS_NODEV|MS_NOEXEC"

    # Bind /dev/fuse to mount FUSE file systems.
    set -- "$@" -b /dev/fuse

    # Mark PRIVATE recursively under (pivot) root, in order not to expose shared
    # mount points accidentally.
    set -- "$@" -k "none,/,none,0x44000"  # private,rec

    # Mount source/dest directories.
    # Note that those directories might be shared mountpoints and we allow them.
    # 0x5000 = bind,rec
    set -- "$@" -k "${source},${source_in_minijail},none,0x5000"
    # 0x84000 = slave,rec
    set -- "$@" -k "${source},${source_in_minijail},none,0x84000"
    # 0x102e = bind,remount,noexec,nodev,nosuid
    set -- "$@" -k "${source},${source_in_minijail},none,0x102e"

    # 0x1000 = bind
    set -- "$@" -k "${dest},${dest_in_minijail},none,0x1000"
    # 0x102e = bind,remount,noexec,nodev,nosuid
    set -- "$@" -k "${dest},${dest_in_minijail},none,0x102e"
  fi

  # Finally, specify command line arguments.
  set -- "$@" -- /usr/bin/mount-passthrough
  set -- "$@" "--source=${source_in_minijail}" "--dest=${dest_in_minijail}" \
      "--fuse_umask=${fuse_umask}" \
      "--fuse_uid=${fuse_uid}" "--fuse_gid=${fuse_gid}" \
      "--android_app_access_type=${android_app_access_type}"

  if [ "${force_group_permission}" = "true" ]; then
    set -- "$@" "--force_group_permission"
  fi

  exec minijail0 "$@"
}
