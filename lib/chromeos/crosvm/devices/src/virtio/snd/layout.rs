// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::virtio::snd::constants::VIRTIO_SND_CHMAP_MAX_SIZE;
use data_model::{DataInit, Le32, Le64};

#[derive(Copy, Clone, Default)]
#[repr(C, packed)]
pub struct virtio_snd_config {
    pub jacks: Le32,
    pub streams: Le32,
    pub chmaps: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_config {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_hdr {
    pub code: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_hdr {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_jack_hdr {
    pub hdr: virtio_snd_hdr,
    pub jack_id: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_jack_hdr {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_event {
    pub hdr: virtio_snd_hdr,
    pub data: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_event {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_query_info {
    pub hdr: virtio_snd_hdr,
    pub start_id: Le32,
    pub count: Le32,
    pub size: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_query_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_info {
    pub hda_fn_nid: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_pcm_info {
    pub hdr: virtio_snd_info,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub formats: Le64,  /* 1 << VIRTIO_SND_PCM_FMT_XXX */
    pub rates: Le64,    /* 1 << VIRTIO_SND_PCM_RATE_XXX */
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,

    pub padding: [u8; 5],
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_pcm_hdr {
    pub hdr: virtio_snd_hdr,
    pub stream_id: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_hdr {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_pcm_set_params {
    pub hdr: virtio_snd_pcm_hdr,
    pub buffer_bytes: Le32,
    pub period_bytes: Le32,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub padding: u8,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_set_params {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_pcm_xfer {
    pub stream_id: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_xfer {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_pcm_status {
    pub status: Le32,
    pub latency_bytes: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_status {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_jack_info {
    pub hdr: virtio_snd_info,
    pub features: Le32, /* 1 << VIRTIO_SND_JACK_F_XXX */
    pub hda_reg_defconf: Le32,
    pub hda_reg_caps: Le32,
    pub connected: u8,
    pub padding: [u8; 7],
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_jack_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_jack_remap {
    pub hdr: virtio_snd_jack_hdr, /* .code = VIRTIO_SND_R_JACK_REMAP */
    pub association: Le32,
    pub sequence: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_jack_remap {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_chmap_info {
    pub hdr: virtio_snd_info,
    pub direction: u8,
    pub channels: u8,
    pub positions: [u8; VIRTIO_SND_CHMAP_MAX_SIZE],
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_chmap_info {}
