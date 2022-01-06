// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/parsed_read_into_options.h"

#include <algorithm>

#include "base/numerics/checked_math.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_region.h"
#include "third_party/blink/renderer/modules/webcodecs/plane_layout.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_read_into_options.h"
//#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

ParsedReadIntoOptions::ParsedReadIntoOptions(VideoFrameReadIntoOptions* options,
                                             media::VideoPixelFormat format,
                                             const gfx::Size& coded_size,
                                             const gfx::Rect& visible_rect,
                                             ExceptionState& exception_state)
    : num_planes(
          static_cast<size_t>(media::VideoFrame::NumPlanes(format))) {
  uint32_t coded_width = static_cast<uint32_t>(coded_size.width());
  uint32_t coded_height = static_cast<uint32_t>(coded_size.height());

  // Parse |region|
  gfx::Rect region = visible_rect;
  if (options->hasRegion()) {
    uint32_t left = options->region().left();
    uint32_t top = options->region().top();
    uint32_t width = options->region().width();
    uint32_t height = options->region().height();

    // Implicitly checks that left <= kMaxDimension.
    if (left >= coded_width) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid region.left %u with codedWidth %u.", left,
                         coded_width));
      return;
    }

    // If left and width are <= kMaxDimension then their sum will not overflow.
    if (width > coded_width || left + width > coded_width) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid region.width %u with region.left %u and "
                         "codedWidth %u.",
                         width, left, coded_width));
      return;
    }

    // Implicitly checks that top <= kMaxDimension.
    if (top >= coded_height) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid region.top %u with codedHeight %u.", top,
                         coded_height));
      return;
    }

    // If top and height are <= kMaxDimension then their sum will not overflow.
    if (height > coded_height || top + height > coded_height) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid region.height %u with region.top %u and "
                         "codedHeight %u.",
                         height, top, coded_height));
      return;
    }

    region = gfx::Rect(left, top, width, height);
  }

  // Region must be non-empty.
  if (region.IsEmpty()) {
    exception_state.ThrowDOMException(
        kConstraintError,
        String::Format("Invalid region with width %d and height %d. Region "
                       "must have nonzero area.",
                       region.width(), region.height()));
    return;
  }

  // Region must be sample-aligned.
  // TODO(crbug.com/1205166): media::VideoFrame does not enforce that visible
  // rects are sample-aligned, so we may have to deal with this case somehow.
  // Options:
  //   - Crop VideoFrame.visibleRegion to sample boundaries and use that.
  //     (May result in differences between rendering paths.)
  //   - Expand or contract the crop to sample boundaries, potentially
  //     per-plane.
  //   - Enforce this restriction on media::VideoFrame and see if anything
  //     breaks.
  for (size_t i = 0; i < num_planes; i++) {
    gfx::Size sample_size = media::VideoFrame::SampleSize(format, i);
    if (region.x() % sample_size.width() != 0) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("region.left %u is not sample-aligned in plane %lu.",
                         region.x(), i));
      return;
    } else if (region.width() % sample_size.width() != 0) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("region.width %u is not sample-aligned in plane %lu.",
                         region.width(), i));
      return;
    } else if (region.y() % sample_size.height() != 0) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("region.top %u is not sample-aligned in plane %lu.",
                         region.y(), i));
      return;
    } else if (region.height() % sample_size.height() != 0) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("region.height %u is not sample-aligned in plane %lu.",
                         region.height(), i));
      return;
    }
  }

  // Parse |layout|.
  bool has_explicit_layout = false;
  if (options->hasLayout()) {
    // TODO(crbug.com/1205169): Consider treating missing planes as implied
    // discard.
    if (options->layout().size() != num_planes) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid layout. Expected %lu planes, found %lu.",
                         num_planes, options->layout().size()));
      return;
    }

    // If the first plane has an offset, assume every plane has an offset and
    // stride.
    has_explicit_layout = options->layout()[0].hasOffset();

    for (size_t i = 0; i < num_planes; i++) {
      if (options->layout()[i].hasOffset() != has_explicit_layout) {
        exception_state.ThrowDOMException(
            kConstraintError,
            String::Format("Invalid layout, plane %lu %s an offset. "
                           "Either all planes must have an offset and stride, "
                           "or all planes must have neither.",
                           i, has_explicit_layout ? "does not have" : "has"));
        return;
      }
      if (options->layout()[i].hasStride() != has_explicit_layout) {
        exception_state.ThrowDOMException(
            kConstraintError,
            String::Format("Invalid layout, plane %lu %s a stride. "
                           "Either all planes must have an offset and stride, "
                           "or all planes must have neither.",
                           i, has_explicit_layout ? "does not have" : "has"));
        return;
      }
      if (has_explicit_layout) {
        planes[i].offset = options->layout()[i].offset();
        planes[i].stride = options->layout()[i].stride();
      }
    }
  }

  // Compute the resulting layout.
  uint32_t end_offset[media::VideoFrame::kMaxPlanes] = {0};
  for (size_t i = 0; i < num_planes; i++) {
    gfx::Size sample_size = media::VideoFrame::SampleSize(format, i);
    uint32_t sample_bytes = media::VideoFrame::BytesPerElement(format, i);

    planes[i].top = region.y() / sample_size.height();
    planes[i].height = region.height() / sample_size.height();
    planes[i].left_bytes = region.x() / sample_size.width() * sample_bytes;
    planes[i].width_bytes = region.width() / sample_size.width() * sample_bytes;

    // If an explicit layout was not provided, planes and rows are tightly
    // packed.
    if (!has_explicit_layout) {
      planes[i].offset = min_buffer_size;
      planes[i].stride = planes[i].width_bytes;
    } else {
      if (planes[i].stride < planes[i].width_bytes) {
        exception_state.ThrowDOMException(
            kConstraintError,
            String::Format("Invalid layout, plane %lu must have stride at least "
                           "%u, found %u.",
                           i, planes[i].width_bytes, planes[i].stride));
        return;
      }
    }

    // Note: this calculation implies that the whole stride is allocated, even
    // on the last row.
    const auto plane_size =
        base::CheckedNumeric<uint32_t>(planes[i].stride) * planes[i].height;
    if (!plane_size.IsValid()) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid layout, plane %lu with stride %u is too "
                         "large.",
                         i, planes[i].stride));
      return;
    }
    const auto plane_end = plane_size + planes[i].offset;
    if (!plane_end.IsValid()) {
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid layout, plane %lu with offset %u and stride "
                         "%u exceeds bounds.",
                         i, planes[i].offset, planes[i].stride));
      return;
    }
    end_offset[i] = plane_end.ValueOrDie();
    min_buffer_size = std::max(min_buffer_size, end_offset[i]);

    // Verify that planes do not overlap.
    for (size_t j = 0; j < i; j++) {
      // If plane A ends before plane B starts, they do not overlap.
      if (end_offset[i] <= planes[j].offset ||
          end_offset[j] <= planes[i].offset) {
        continue;
      }
      exception_state.ThrowDOMException(
          kConstraintError,
          String::Format("Invalid layout, plane %lu overlaps with plane %lu.", i,
                         j));
      return;
    }
  }
}

}  // namespace blink
