// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use base::{error, warn, AsRawDescriptor, IntoRawDescriptor};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use libvda::decode::Event as LibvdaEvent;

use crate::virtio::video::{
    decoder::{backend::*, Capability},
    error::{VideoError, VideoResult},
    format::*,
};

impl TryFrom<Format> for libvda::Profile {
    type Error = VideoError;

    fn try_from(format: Format) -> Result<Self, Self::Error> {
        Ok(match format {
            Format::VP8 => libvda::Profile::VP8,
            Format::VP9 => libvda::Profile::VP9Profile0,
            Format::H264 => libvda::Profile::H264ProfileBaseline,
            _ => {
                error!("specified format {} is not supported by VDA", format);
                return Err(VideoError::InvalidParameter);
            }
        })
    }
}

impl TryFrom<Format> for libvda::PixelFormat {
    type Error = VideoError;

    fn try_from(format: Format) -> Result<Self, Self::Error> {
        Ok(match format {
            Format::NV12 => libvda::PixelFormat::NV12,
            _ => {
                error!("specified format {} is not supported by VDA", format);
                return Err(VideoError::InvalidParameter);
            }
        })
    }
}

impl From<&FramePlane> for libvda::FramePlane {
    fn from(plane: &FramePlane) -> Self {
        libvda::FramePlane {
            offset: plane.offset as i32,
            stride: plane.stride as i32,
        }
    }
}

impl From<libvda::decode::Event> for DecoderEvent {
    fn from(event: libvda::decode::Event) -> Self {
        // We cannot use the From trait here since neither libvda::decode::Response
        // no std::result::Result are defined in the current crate.
        fn vda_response_to_result(resp: libvda::decode::Response) -> VideoResult<()> {
            match resp {
                libvda::decode::Response::Success => Ok(()),
                resp => Err(VideoError::BackendFailure(anyhow!("VDA failure: {}", resp))),
            }
        }

        match event {
            LibvdaEvent::ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect_left,
                visible_rect_top,
                visible_rect_right,
                visible_rect_bottom,
            } => DecoderEvent::ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect: Rect {
                    left: visible_rect_left,
                    top: visible_rect_top,
                    right: visible_rect_right,
                    bottom: visible_rect_bottom,
                },
            },
            LibvdaEvent::PictureReady {
                buffer_id,
                bitstream_id,
                left,
                top,
                right,
                bottom,
            } => DecoderEvent::PictureReady {
                picture_buffer_id: buffer_id,
                bitstream_id,
                visible_rect: Rect {
                    left,
                    top,
                    right,
                    bottom,
                },
            },
            LibvdaEvent::NotifyEndOfBitstreamBuffer { bitstream_id } => {
                DecoderEvent::NotifyEndOfBitstreamBuffer(bitstream_id)
            }
            LibvdaEvent::NotifyError(resp) => DecoderEvent::NotifyError(
                VideoError::BackendFailure(anyhow!("VDA failure: {}", resp)),
            ),
            LibvdaEvent::ResetResponse(resp) => {
                DecoderEvent::ResetCompleted(vda_response_to_result(resp))
            }
            LibvdaEvent::FlushResponse(resp) => {
                DecoderEvent::FlushCompleted(vda_response_to_result(resp))
            }
        }
    }
}

// Used by DecoderSession::get_capabilities().
fn from_pixel_format(
    fmt: &libvda::PixelFormat,
    mask: u64,
    width_range: FormatRange,
    height_range: FormatRange,
) -> FormatDesc {
    let format = match fmt {
        libvda::PixelFormat::NV12 => Format::NV12,
        libvda::PixelFormat::YV12 => Format::YUV420,
    };

    let frame_formats = vec![FrameFormat {
        width: width_range,
        height: height_range,
        bitrates: Vec::new(),
    }];

    FormatDesc {
        mask,
        format,
        frame_formats,
    }
}

pub struct VdaDecoderSession {
    vda_session: libvda::decode::Session,
    format: Option<libvda::PixelFormat>,
}

impl DecoderSession for VdaDecoderSession {
    fn set_output_parameters(&mut self, buffer_count: usize, format: Format) -> VideoResult<()> {
        self.format = Some(libvda::PixelFormat::try_from(format)?);
        Ok(self.vda_session.set_output_buffer_count(buffer_count)?)
    }

    fn decode(
        &mut self,
        bitstream_id: i32,
        resource: GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()> {
        let handle = match resource {
            GuestResourceHandle::VirtioObject(handle) => handle,
            _ => {
                return Err(VideoError::BackendFailure(anyhow!(
                    "VDA backend only supports virtio object resources"
                )))
            }
        };

        Ok(self.vda_session.decode(
            bitstream_id,
            // Steal the descriptor of the resource, as libvda will close it.
            handle.desc.into_raw_descriptor(),
            offset,
            bytes_used,
        )?)
    }

    fn flush(&mut self) -> VideoResult<()> {
        Ok(self.vda_session.flush()?)
    }

    fn reset(&mut self) -> VideoResult<()> {
        Ok(self.vda_session.reset()?)
    }

    fn clear_output_buffers(&mut self) -> VideoResult<()> {
        Ok(())
    }

    fn event_pipe(&self) -> &dyn AsRawDescriptor {
        self.vda_session.pipe()
    }

    fn use_output_buffer(
        &mut self,
        picture_buffer_id: i32,
        resource: GuestResource,
    ) -> VideoResult<()> {
        let handle = match resource.handle {
            GuestResourceHandle::VirtioObject(handle) => handle,
            _ => {
                return Err(VideoError::BackendFailure(anyhow!(
                    "VDA backend only supports virtio object resources"
                )))
            }
        };
        let vda_planes: Vec<libvda::FramePlane> = resource.planes.iter().map(Into::into).collect();

        Ok(self.vda_session.use_output_buffer(
            picture_buffer_id,
            self.format.ok_or(VideoError::BackendFailure(anyhow!(
                "set_output_parameters() must be called before use_output_buffer()"
            )))?,
            // Steal the descriptor of the resource, as libvda will close it.
            handle.desc.into_raw_descriptor(),
            &vda_planes,
            handle.modifier,
        )?)
    }

    fn reuse_output_buffer(&mut self, picture_buffer_id: i32) -> VideoResult<()> {
        Ok(self.vda_session.reuse_output_buffer(picture_buffer_id)?)
    }

    fn read_event(&mut self) -> VideoResult<DecoderEvent> {
        self.vda_session
            .read_event()
            .map(Into::into)
            .map_err(Into::into)
    }
}

/// A VDA decoder backend that can be passed to `Decoder::new` in order to create a working decoder.
pub struct LibvdaDecoder(libvda::decode::VdaInstance);

impl LibvdaDecoder {
    /// Create a decoder backend instance that can be used to instantiate an decoder.
    pub fn new(backend_type: libvda::decode::VdaImplType) -> VideoResult<Self> {
        Ok(Self(libvda::decode::VdaInstance::new(backend_type)?))
    }
}

impl DecoderBackend for LibvdaDecoder {
    type Session = VdaDecoderSession;

    fn new_session(&mut self, format: Format) -> VideoResult<Self::Session> {
        let profile = libvda::Profile::try_from(format)?;

        Ok(VdaDecoderSession {
            vda_session: self.0.open_session(profile).map_err(|e| {
                error!("failed to open a session for {:?}: {}", format, e);
                VideoError::InvalidOperation
            })?,
            format: None,
        })
    }

    fn get_capabilities(&self) -> Capability {
        let caps = libvda::decode::VdaInstance::get_capabilities(&self.0);

        // Raise the first |# of supported raw formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.output_formats.len());

        let mut in_fmts = vec![];
        let mut profiles: BTreeMap<Format, Vec<Profile>> = Default::default();
        for fmt in caps.input_formats.iter() {
            match Profile::from_libvda_profile(fmt.profile) {
                Some(profile) => {
                    let format = profile.to_format();
                    in_fmts.push(FormatDesc {
                        mask,
                        format,
                        frame_formats: vec![FrameFormat {
                            width: FormatRange {
                                min: fmt.min_width,
                                max: fmt.max_width,
                                step: 1,
                            },
                            height: FormatRange {
                                min: fmt.min_height,
                                max: fmt.max_height,
                                step: 1,
                            },
                            bitrates: Vec::new(),
                        }],
                    });
                    match profiles.entry(format) {
                        Entry::Occupied(mut e) => e.get_mut().push(profile),
                        Entry::Vacant(e) => {
                            e.insert(vec![profile]);
                        }
                    }
                }
                None => {
                    warn!(
                        "No virtio-video equivalent for libvda profile, skipping: {:?}",
                        fmt.profile
                    );
                }
            }
        }

        let levels: BTreeMap<Format, Vec<Level>> = if profiles.contains_key(&Format::H264) {
            // We only support Level 1.0 for H.264.
            vec![(Format::H264, vec![Level::H264_1_0])]
                .into_iter()
                .collect()
        } else {
            Default::default()
        };

        // Prepare {min, max} of {width, height}.
        // While these values are associated with each input format in libvda,
        // they are associated with each output format in virtio-video protocol.
        // Thus, we compute max of min values and min of max values here.
        let min_width = caps.input_formats.iter().map(|fmt| fmt.min_width).max();
        let max_width = caps.input_formats.iter().map(|fmt| fmt.max_width).min();
        let min_height = caps.input_formats.iter().map(|fmt| fmt.min_height).max();
        let max_height = caps.input_formats.iter().map(|fmt| fmt.max_height).min();
        let width_range = FormatRange {
            min: min_width.unwrap_or(0),
            max: max_width.unwrap_or(0),
            step: 1,
        };
        let height_range = FormatRange {
            min: min_height.unwrap_or(0),
            max: max_height.unwrap_or(0),
            step: 1,
        };

        // Raise the first |# of supported coded formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.input_formats.len());
        let out_fmts = caps
            .output_formats
            .iter()
            .map(|fmt| from_pixel_format(fmt, mask, width_range, height_range))
            .collect();

        Capability::new(in_fmts, out_fmts, profiles, levels)
    }
}
