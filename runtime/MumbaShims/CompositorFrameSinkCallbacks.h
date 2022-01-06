// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_OMPOSITOR_ALLBACKS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_OMPOSITOR_ALLBACKS_H_

struct HostFrameSinkClientCallbacks {
  void (*OnFirstSurfaceActivation)(void* peer,
                                   uint32_t surface_info_client_id, 
                                   uint32_t surface_info_sink_id,
                                   uint32_t surface_info_parent_sequence_number,
                                   uint32_t surface_info_child_sequence_number,
                                   uint64_t surface_info_token_high, 
                                   uint64_t surface_info_token_low,
                                   float device_scale_factor,
                                   int size_width,
                                   int size_height);

  void (*OnFrameTokenChanged)(void* peer, uint32_t frame_token);
};


#endif