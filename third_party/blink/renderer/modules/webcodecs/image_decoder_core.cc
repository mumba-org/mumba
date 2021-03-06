// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/image_decoder_core.h"

#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/time/time.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/shared_buffer.h"
#include "third_party/skia/include/core/SkImage.h"
//#include "third_party/skia/include/core/SkYUVAPixmaps.h"

namespace blink {

namespace {

// media::VideoPixelFormat YUVSubsamplingToMediaPixelFormat(
//     cc::YUVSubsampling sampling,
//     int depth) {
//   // TODO(crbug.com/1073995): Add support for high bit depth format.
//   if (depth != 8)
//     return media::PIXEL_FORMAT_UNKNOWN;

//   switch (sampling) {
//     case cc::YUVSubsampling::k420:
//       return media::PIXEL_FORMAT_I420;
//     case cc::YUVSubsampling::k422:
//       return media::PIXEL_FORMAT_I422;
//     case cc::YUVSubsampling::k444:
//       return media::PIXEL_FORMAT_I444;
//     default:
//       return media::PIXEL_FORMAT_UNKNOWN;
//   }
// }

media::VideoPixelFormat
VideoPixelFormatFromSkColorType(SkColorType sk_color_type, bool is_opaque) {
  //FIXME
  switch (sk_color_type) {
    case kRGBA_8888_SkColorType:
      NOTREACHED();
      //return is_opaque ? media::PIXEL_FORMAT_XBGR : media::PIXEL_FORMAT_ABGR;
    case kBGRA_8888_SkColorType:
      return is_opaque ? media::PIXEL_FORMAT_XRGB : media::PIXEL_FORMAT_ARGB;
    default:
      // TODO(crbug.com/1073995): Add F16 support.
      return media::PIXEL_FORMAT_UNKNOWN;
  }
}

scoped_refptr<media::VideoFrame> WrapExternalDataWithLayout(
    media::VideoPixelFormat format,
    const gfx::Size& coded_size,
    std::vector<int32_t> strides,
    const gfx::Rect& visible_rect,
    const gfx::Size& natural_size,
    uint8_t* data,
    size_t data_size,
    base::TimeDelta timestamp) {
  
  return media::VideoFrame::WrapExternalData(
    format,
    coded_size,
    visible_rect,
    natural_size,
    data,
    data_size,
    timestamp);
}

scoped_refptr<media::VideoFrame> CreateFromSkImage(sk_sp<SkImage> sk_image,
                                            const gfx::Rect& visible_rect,
                                            const gfx::Size& natural_size,
                                            base::TimeDelta timestamp,
                                            bool force_opaque) {
  DCHECK(!sk_image->isTextureBacked());

  // A given SkImage may not exist until it's rasterized.
  if (sk_image->isLazyGenerated())
    sk_image = sk_image->makeRasterImage();

  const auto format = VideoPixelFormatFromSkColorType(
      sk_image->colorType(), sk_image->isOpaque() || force_opaque);
  // if (media::VideoFrameLayout::NumPlanes(format) != 1) {
  //   DLOG(ERROR) << "Invalid SkColorType for CreateFromSkImage";
  //   return nullptr;
  // }

  SkPixmap pm;
  const bool peek_result = sk_image->peekPixels(&pm);
  DCHECK(peek_result);

  auto coded_size = gfx::Size(sk_image->width(), sk_image->height());
  // auto layout = media::VideoFrameLayout::CreateWithStrides(
  //     format, coded_size, std::vector<int32_t>(1, pm.rowBytes()));
  // if (!layout)
  //   return nullptr;

  auto frame = WrapExternalDataWithLayout(
      format, 
      coded_size, 
      std::vector<int32_t>(1, pm.rowBytes()), 
      visible_rect, natural_size,
      // TODO(crbug.com/1161304): We should be able to wrap readonly memory in
      // a VideoFrame instead of using writable_addr() here.
      reinterpret_cast<uint8_t*>(pm.writable_addr()), pm.computeByteSize(),
      timestamp);
  if (!frame)
    return nullptr;

  frame->AddDestructionObserver(base::BindOnce(
      base::DoNothing::Once<sk_sp<SkImage>>(), std::move(sk_image)));
  return frame;
}


}  // namespace

ImageDecoderCore::ImageDecoderCore(
    String mime_type,
    scoped_refptr<SegmentReader> data,
    bool data_complete,
    ImageDecoder::AlphaOption alpha_option,
    const ColorBehavior& color_behavior,
    const SkISize& desired_size)//,
    //ImageDecoder::AnimationOption animation_option)
    : mime_type_(mime_type),
      alpha_option_(alpha_option),
      color_behavior_(color_behavior),
      desired_size_(desired_size),
      //animation_option_(animation_option),
      data_complete_(data_complete),
      segment_reader_(std::move(data)) {
  if (!segment_reader_) {
    stream_buffer_ = SharedBuffer::Create();
    segment_reader_ = SegmentReader::CreateFromSharedBuffer(stream_buffer_);
  }

  Reinitialize();//animation_option_);

//   base::UmaHistogramEnumeration("Blink.WebCodecs.ImageDecoder.Type",
//                                 BitmapImageMetrics::StringToDecodedImageType(
//                                     decoder_->FilenameExtension()));
}

ImageDecoderCore::~ImageDecoderCore() = default;

ImageDecoderCore::ImageMetadata ImageDecoderCore::DecodeMetadata() {
  DCHECK(decoder_);

  ImageDecoderCore::ImageMetadata metadata;
  metadata.data_complete = data_complete_;

  if (!decoder_->IsSizeAvailable()) {
    // Decoding has failed if we have no size and no more data.
    metadata.failed = decoder_->Failed() || data_complete_;
    return metadata;
  }

  metadata.has_size = true;
  metadata.frame_count = SafeCast<uint32_t>(decoder_->FrameCount());
  metadata.repetition_count = decoder_->RepetitionCount();
  metadata.image_has_both_still_and_animated_sub_images =
      false;//decoder_->ImageHasBothStillAndAnimatedSubImages();

  // It's important that |failed| is set last since some of the methods above
  // may trigger operations which can lead to failure.
  metadata.failed = decoder_->Failed();
  return metadata;
}

std::unique_ptr<ImageDecoderCore::ImageDecodeResult> ImageDecoderCore::Decode(
    uint32_t frame_index,
    bool complete_frames_only) {
  DCHECK(decoder_);

  auto result = std::make_unique<ImageDecodeResult>();
  result->frame_index = frame_index;

  if (decoder_->Failed()) {
    result->status = Status::kDecodeError;
    return result;
  }

  if (!decoder_->IsSizeAvailable()) {
    result->status = Status::kNoImage;
    return result;
  }

  if (data_complete_ && frame_index >= decoder_->FrameCount()) {
    result->status = Status::kIndexError;
    return result;
  }

  // Due to implementation limitations YUV support for some formats is only
  // known once all data is received. Animated images are never supported.
  if (decoder_->CanDecodeToYUV() && !have_completed_rgb_decode_ &&
      frame_index == 0u) {
    if (!have_completed_yuv_decode_) {
      MaybeDecodeToYuv();
      if (decoder_->Failed()) {
        result->status = Status::kDecodeError;
        return result;
      }
    }

    if (have_completed_yuv_decode_) {
      result->status = Status::kOk;
      result->frame = yuv_frame_;
      result->complete = true;
      return result;
    }
  }

  auto* image = decoder_->DecodeFrameBufferAtIndex(frame_index);
  if (decoder_->Failed()) {
    result->status = Status::kDecodeError;
    return result;
  }

  if (!image) {
    result->status = Status::kNoImage;
    return result;
  }

  // Nothing to do if nothing has been decoded yet.
  if (image->GetStatus() == ImageFrame::kFrameEmpty) { //||
      //image->GetStatus() == ImageFrame::kFrameInitialized) {
    result->status = Status::kNoImage;
    return result;
  }

  have_completed_rgb_decode_ = true;

  // Only satisfy fully complete decode requests. Treat partial decodes as
  // complete if we've received all the data we ever will.
  const bool is_complete = image->GetStatus() == ImageFrame::kFrameComplete;
  if (!is_complete && complete_frames_only) {
    result->status = Status::kNoImage;
    return result;
  }

  // Prefer FinalizePixelsAndGetImage() since that will mark the underlying
  // bitmap as immutable, which allows copies to be avoided.
  auto sk_image = is_complete ? image->FinalizePixelsAndGetImage()
                              : SkImage::MakeFromBitmap(image->Bitmap());
  if (!sk_image) {
    NOTREACHED() << "Failed to retrieve SkImage for decoded image.";
    result->status = Status::kDecodeError;
    return result;
  }

  if (!is_complete) {
    auto generation_id = image->Bitmap().getGenerationID();
    auto it = incomplete_frames_.find(frame_index);
    if (it == incomplete_frames_.end()) {
      incomplete_frames_.Set(frame_index, generation_id);
    } else {
      // Don't fulfill the promise until a new bitmap is seen.
      if (it->value == generation_id) {
        result->status = Status::kNoImage;
        return result;
      }

      it->value = generation_id;
    }
  } else {
    incomplete_frames_.erase(frame_index);
  }

  // This is zero copy; the VideoFrame points into the SkBitmap.
  const gfx::Size coded_size(sk_image->width(), sk_image->height());
  auto frame = CreateFromSkImage(sk_image, gfx::Rect(coded_size),
                                 coded_size, media::kNoTimestamp,
                                 true);
  if (!frame) {
    NOTREACHED() << "Failed to create VideoFrame from SkImage.";
    result->status = Status::kDecodeError;
    return result;
  }

  // frame->metadata()->transformation = ImageOrientationToVideoTransformation(
  //     decoder_->Orientation().Orientation());

  // Only animated images have frame durations.
  // if (decoder_->FrameCount() > 1 ||
  //     decoder_->RepetitionCount() != kAnimationNone) {
  //   frame->metadata()->frame_duration =
  //       decoder_->FrameDurationAtIndex(frame_index);
  // }

  result->status = Status::kOk;
  result->sk_image = std::move(sk_image);
  result->frame = std::move(frame);
  result->complete = is_complete;
  return result;
}

void ImageDecoderCore::AppendData(size_t data_size,
                                  std::unique_ptr<uint8_t[]> data,
                                  bool data_complete) {
  DCHECK(stream_buffer_);
  DCHECK(stream_buffer_);
  DCHECK(!data_complete_);
  data_complete_ = data_complete;
  if (data) {
    stream_buffer_->Append(reinterpret_cast<const char*>(data.get()),
                           data_size);
  } else {
    DCHECK_EQ(data_size, 0u);
  }

  // We may not have a decoder if Clear() was called while data arrives.
  if (decoder_)
    decoder_->SetData(stream_buffer_, data_complete_);
}

void ImageDecoderCore::Clear() {
  decoder_.reset();
  incomplete_frames_.clear();
  yuv_frame_ = nullptr;
  have_completed_rgb_decode_ = false;
  have_completed_yuv_decode_ = false;
}

void ImageDecoderCore::Reinitialize() {
   // ImageDecoder::AnimationOption animation_option) {
  Clear();
  //animation_option_ = animation_option;
  decoder_ = ImageDecoder::CreateByMimeType(
      mime_type_, segment_reader_, data_complete_, alpha_option_,
      color_behavior_, desired_size_);//, animation_option_);
  DCHECK(decoder_);
}

void ImageDecoderCore::MaybeDecodeToYuv() {
  // DCHECK(!have_completed_rgb_decode_);
  // DCHECK(!have_completed_yuv_decode_);

  // const auto format = YUVSubsamplingToMediaPixelFormat(
  //     decoder_->GetYUVSubsampling(), decoder_->GetYUVBitDepth());
  // if (format == media::PIXEL_FORMAT_UNKNOWN)
  //   return;

  // // In the event of a partial decode |yuv_frame_| may have been created, but
  // // not populated with image data. To avoid thrashing as bytes come in, only
  // // create the frame once.
  // if (!yuv_frame_) {
  //   const auto coded_size =
  //       gfx::Size(decoder_->DecodedYUVSize(cc::YUVIndex::kY));

  //   // Plane sizes are guaranteed to fit in an int32_t by
  //   // ImageDecoder::SetSize(); since YUV is 1 byte-per-channel, we can just
  //   // check width * height.
  //   DCHECK(coded_size.GetCheckedArea().IsValid());
  //   auto layout = media::VideoFrameLayout::CreateWithStrides(
  //       format, coded_size,
  //       {static_cast<int32_t>(decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kY)),
  //        static_cast<int32_t>(decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kU)),
  //        static_cast<int32_t>(
  //            decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kV))});
  //   if (!layout)
  //     return;

  //   yuv_frame_ = media::VideoFrame::CreateFrameWithLayout(
  //       *layout, gfx::Rect(coded_size), coded_size, media::kNoTimestamp,
  //       /*zero_initialize_memory=*/false);
  //   if (!yuv_frame_)
  //     return;
  // }

  // void* planes[cc::kNumYUVPlanes] = {yuv_frame_->data(0), yuv_frame_->data(1),
  //                                    yuv_frame_->data(2)};
  // size_t row_bytes[cc::kNumYUVPlanes] = {
  //     yuv_frame_->stride(0), yuv_frame_->stride(1), yuv_frame_->stride(2)};

  // // TODO(crbug.com/1073995): Add support for high bit depth format.
  // const auto color_type = kGray_8_SkColorType;

  // auto image_planes =
  //     std::make_unique<ImagePlanes>(planes, row_bytes, color_type);
  // decoder_->SetImagePlanes(std::move(image_planes));
  // decoder_->DecodeToYUV();
  // if (decoder_->Failed() || !decoder_->HasDisplayableYUVData())
  //   return;

  // have_completed_yuv_decode_ = true;

  // gfx::ColorSpace gfx_cs;
  // if (auto sk_cs = decoder_->ColorSpaceForSkImages())
  //   gfx_cs = gfx::ColorSpace(*sk_cs);

  // const auto skyuv_cs = decoder_->GetYUVColorSpace();
  // DCHECK_NE(skyuv_cs, kIdentity_SkYUVColorSpace);

  // if (!gfx_cs.IsValid()) {
  //   if (skyuv_cs == kJPEG_Full_SkYUVColorSpace) {
  //     gfx_cs = gfx::ColorSpace::CreateJpeg();
  //   } else if (skyuv_cs == kRec601_Limited_SkYUVColorSpace) {
  //     gfx_cs = gfx::ColorSpace::CreateREC601();
  //   } else if (skyuv_cs == kRec709_Limited_SkYUVColorSpace ||
  //              skyuv_cs == kRec709_Full_SkYUVColorSpace) {
  //     gfx_cs = gfx::ColorSpace::CreateREC709();
  //   }
  // }

  // if (gfx_cs.IsValid()) {
  //   yuv_frame_->set_color_space(YUVColorSpaceToGfxColorSpace(
  //       skyuv_cs, gfx_cs.GetPrimaryID(), gfx_cs.GetTransferID()));
  //   return;
  // }

  // DCHECK(skyuv_cs == kBT2020_8bit_Full_SkYUVColorSpace ||
  //        skyuv_cs == kBT2020_8bit_Limited_SkYUVColorSpace ||
  //        skyuv_cs == kBT2020_10bit_Full_SkYUVColorSpace ||
  //        skyuv_cs == kBT2020_10bit_Limited_SkYUVColorSpace ||
  //        skyuv_cs == kBT2020_12bit_Full_SkYUVColorSpace ||
  //        skyuv_cs == kBT2020_12bit_Limited_SkYUVColorSpace)
  //     << "Unexpected SkYUVColorSpace: " << skyuv_cs;

  // auto transfer_id = gfx::ColorSpace::TransferID::BT709;
  // if (skyuv_cs == kBT2020_10bit_Full_SkYUVColorSpace ||
  //     skyuv_cs == kBT2020_10bit_Limited_SkYUVColorSpace) {
  //   transfer_id = gfx::ColorSpace::TransferID::BT2020_10;
  // } else if (skyuv_cs == kBT2020_12bit_Full_SkYUVColorSpace ||
  //            skyuv_cs == kBT2020_12bit_Limited_SkYUVColorSpace) {
  //   transfer_id = gfx::ColorSpace::TransferID::BT2020_12;
  // }

  // yuv_frame_->set_color_space(YUVColorSpaceToGfxColorSpace(
  //     skyuv_cs, gfx::ColorSpace::PrimaryID::BT2020, transfer_id));
}

}  // namespace blink
