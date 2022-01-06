# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
{
  'targets': [
    {
      # GN version: //content/common:mojo_bindings
      'target_name': 'common_mojo_bindings_mojom',
      'type': 'none',
      'variables': {
        'mojom_files': [
          # NOTE: Sources duplicated in //content/common/BUILD.gn:mojo_bindings.
          'application_setup.mojom',
          #'background_sync_service.mojom',
          #'geolocation_service.mojom',
          #'permission_service.mojom',
          #'presentation/presentation_service.mojom',
          'process_control.mojom',
          #'render_frame_setup.mojom',
          # NOTE: Sources duplicated in
          # //content/public/common/BUILD.gn:mojo_bindings.
          #'background_sync.mojom',
          #'mojo_geoposition.mojom',
          #'permission_status.mojom',
        ],
      },
      'includes': [ '../../third_party/mojo/mojom_bindings_generator_explicit.gypi' ],
    },
    {
      'target_name': 'common_mojo_bindings',
      'type': 'static_library',
      'variables': { 'enable_wexit_time_destructors': 1, },
      'dependencies': [
        'common_mojo_bindings_mojom',
        '../../lib/mojo/mojo_base.gyp:mojo_application_bindings',
        '../../lib/mojo/mojo_base.gyp:mojo_environment_chromium',
        '../../third_party/mojo/mojo_public.gyp:mojo_cpp_bindings',
      ]
    },
  ]
}