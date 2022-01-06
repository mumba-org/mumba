// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"

#include <string>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/raster_interface.h"
//#include "media/base/async_destroy_video_encoder.h"
#include "media/base/bind_to_current_loop.h"
#include "media/base/mime_util.h"
//#include "media/base/offloading_video_encoder.h"
#include "media/base/video_codecs.h"
#include "media/base/video_color_space.h"
#include "media/base/video_encoder.h"
#include "media/base/video_util.h"
#include "media/video/gpu_video_accelerator_factories.h"
//#include "media/video/video_encode_accelerator_adapter.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_avc_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_support.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"
#include "third_party/blink/renderer/modules/webcodecs/video_encode_accelerator_adapter.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/noncopyable.h"

//#if BUILDFLAG(ENABLE_OPENH264)
#include "media/video/openh264_video_encoder.h"
//#endif

//#if BUILDFLAG(ENABLE_LIBVPX)
#include "media/video/vpx_video_encoder.h"
//#endif

namespace blink {

template <>
struct CrossThreadCopier<media::Status>
    : public CrossThreadCopierPassThrough<media::Status> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<blink::VideoEncoderSupport>
    : public CrossThreadCopierPassThrough<blink::VideoEncoderSupport> {};


namespace {

// Use this function in cases when we can't immediately delete |ptr| because
// there might be its methods on the call stack.
template <typename T>
void DeleteLater(ScriptState* state, std::unique_ptr<T> ptr) {
  DCHECK(state->ContextIsValid());
  auto* context = ExecutionContext::From(state);
  auto runner = context->GetTaskRunner(TaskType::kInternalDefault);
  runner->DeleteSoon(FROM_HERE, std::move(ptr));
}

bool IsAcceleratedConfigurationSupported(
    media::VideoCodecProfile profile,
    const media::VideoEncoder::Options& options,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  if (!gpu_factories || !gpu_factories->IsGpuVideoAcceleratorEnabled())
    return false;

  // No support for temporal SVC in accelerated encoders yet.
  if (options.temporal_layers > 1)
    return false;

  auto supported_profiles =
      gpu_factories->GetVideoEncodeAcceleratorSupportedProfiles();

  bool found_supported_profile = false;
  for (auto& supported_profile : supported_profiles) {
    if (supported_profile.profile != profile)
      continue;

    // if (supported_profile.min_resolution.width() > options.frame_size.width() ||
    //     supported_profile.min_resolution.height() >
    //         options.frame_size.height()) {
    //   continue;
    // }

    if (supported_profile.max_resolution.width() < options.frame_size.width() ||
        supported_profile.max_resolution.height() <
            options.frame_size.height()) {
      continue;
    }

    double max_supported_framerate =
        double{supported_profile.max_framerate_numerator} /
        supported_profile.max_framerate_denominator;
    if (options.framerate.has_value() &&
        options.framerate.value() > max_supported_framerate) {
      continue;
    }

    found_supported_profile = true;
    break;
  }
  return found_supported_profile;
}

std::unique_ptr<media::VideoEncoder> CreateAcceleratedVideoEncoder(
    media::VideoCodecProfile profile,
    const media::VideoEncoder::Options& options,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  if (!IsAcceleratedConfigurationSupported(profile, options, gpu_factories))
    return nullptr;
  auto task_runner = base::ThreadTaskRunnerHandle::Get();
  // return std::make_unique<
  //     media::AsyncDestroyVideoEncoder<media::VideoEncodeAcceleratorAdapter>>(
  //     std::make_unique<media::VideoEncodeAcceleratorAdapter>(
  //         gpu_factories, std::move(task_runner)));
  return std::make_unique<media::VideoEncodeAcceleratorAdapter>(gpu_factories, std::move(task_runner));
}

std::unique_ptr<media::VideoEncoder> CreateVpxVideoEncoder() {
//#if BUILDFLAG(ENABLE_LIBVPX)
  return std::make_unique<media::VpxVideoEncoder>();
//#else
//  return nullptr;
//#endif  // BUILDFLAG(ENABLE_LIBVPX)
}

std::unique_ptr<media::VideoEncoder> CreateOpenH264VideoEncoder() {
//#if BUILDFLAG(ENABLE_OPENH264)
  return std::make_unique<media::OpenH264VideoEncoder>();
//#else
//  return nullptr;
//#endif  // BUILDFLAG(ENABLE_OPENH264)
}

VideoEncoderTraits::ParsedConfig* ParseConfigStatic(
    const VideoEncoderConfig& config,
    ExceptionState& exception_state) {
  constexpr int kMaxSupportedFrameSize = 8000;
  auto* result = new VideoEncoderTraits::ParsedConfig();

  result->options.frame_size.set_height(config.height());
  if (config.height() == 0 || config.height() > kMaxSupportedFrameSize) {
    exception_state.ThrowTypeError(String::Format(
        "Invalid height; expected range from %d to %d, received %d.", 1,
        kMaxSupportedFrameSize, config.height()));
    return nullptr;
  }

  result->options.frame_size.set_width(config.width());
  if (config.width() == 0 || config.width() > kMaxSupportedFrameSize) {
    exception_state.ThrowTypeError(String::Format(
        "Invalid width; expected range from %d to %d, received %d.", 1,
        kMaxSupportedFrameSize, config.width()));
    return nullptr;
  }

  if (config.alpha() == "keep") {
    exception_state.ThrowDOMException(
        kNotSupportedError,
        "Alpha encoding is not currently supported.");
    return nullptr;
  }

  if (config.hasDisplayWidth() && config.hasDisplayHeight()) {
    result->display_size.emplace(config.displayWidth(),
                                 config.displayHeight());
  }

  if (config.hasFramerate()) {
    constexpr double kMinFramerate = .0001;
    constexpr double kMaxFramerate = 1'000'000'000;
    if (std::isnan(config.framerate()) ||
        config.framerate() < kMinFramerate ||
        config.framerate() > kMaxFramerate) {
      exception_state.ThrowTypeError(String::Format(
          "Invalid framerate; expected range from %f to %f, received %f.",
          kMinFramerate, kMaxFramerate, config.framerate()));
      return nullptr;
    }
    result->options.framerate = config.framerate();
  }

  if (config.hasBitrate())
    result->options.bitrate = config.bitrate();

  // https://w3c.github.io/webrtc-svc/
  if (config.hasScalabilityMode()) {
    if (config.scalabilityMode() == "L1T2") {
      result->options.temporal_layers = 2;
    } else if (config.scalabilityMode() == "L1T3") {
      result->options.temporal_layers = 3;
    } else {
      exception_state.ThrowTypeError("Unsupported scalabilityMode.");
      return nullptr;
    }
  }

  // The IDL defines a default value of "allow".
  DCHECK(config.hasHardwareAcceleration());

  result->hw_pref = StringToHardwarePreference(config.hardwareAcceleration());

  bool is_codec_ambiguous = true;
  result->codec = media::kUnknownVideoCodec;
  result->profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;
  result->color_space = media::VideoColorSpace::REC709();
  result->level = 0;
  result->codec_string = config.codec();

  bool parse_succeeded = media::ParseVideoCodecString(
      "", config.codec().Utf8().data(), &is_codec_ambiguous, &result->codec,
      &result->profile, &result->level, &result->color_space);

  if (!parse_succeeded || is_codec_ambiguous) {
    exception_state.ThrowTypeError("Unknown codec.");
    return nullptr;
  }

  // We are done with the parsing.
  if (!config.hasAvc())
    return result;

  // We should only get here with H264 codecs.
  if (result->codec != media::VideoCodec::kCodecH264) {
    exception_state.ThrowTypeError(
        "'avc' field can only be used with AVC codecs");
    return nullptr;
  }

  std::string avc_format = std::string(config.avc().format().Utf8().data());
  if (avc_format == "avc") {
    result->options.avc.produce_annexb = false;
  } else if (avc_format == "annexb") {
    result->options.avc.produce_annexb = true;
  } else {
    NOTREACHED();
  }

  return result;
}

bool VerifyCodecSupportStatic(VideoEncoderTraits::ParsedConfig& config,
                              ExceptionState* exception_state) {
  switch (config.codec) {
    case media::kCodecVP8:
      break;

    case media::kCodecVP9:
      if (config.profile == media::VideoCodecProfile::VP9PROFILE_PROFILE1 ||
          config.profile == media::VideoCodecProfile::VP9PROFILE_PROFILE3) {
        if (exception_state) {
          exception_state->ThrowDOMException(
              kNotSupportedError, "Unsupported vp9 profile.");
        }
        return false;
      }
      break;

    case media::kCodecH264:
      break;

    default:
      if (exception_state) {
        exception_state->ThrowDOMException(kNotSupportedError,
                                           "Unsupported codec type.");
      }
      return false;
  }

  return true;
}

VideoEncoderConfig CopyConfig(const VideoEncoderConfig& config) {
  VideoEncoderConfig result;
  result.setCodec(config.codec());
  result.setWidth(config.width());
  result.setHeight(config.height());

  if (config.hasDisplayWidth())
    result.setDisplayWidth(config.displayWidth());

  if (config.hasDisplayHeight())
    result.setDisplayHeight(config.displayHeight());

  if (config.hasFramerate())
    result.setFramerate(config.framerate());

  if (config.hasBitrate())
    result.setBitrate(config.bitrate());

  if (config.hasScalabilityMode())
    result.setScalabilityMode(config.scalabilityMode());

  if (config.hasHardwareAcceleration())
    result.setHardwareAcceleration(config.hardwareAcceleration());

  if (config.hasAvc() && config.avc().format()) {
    AvcEncoderConfig avc;
    avc.setFormat(config.avc().format());
    result.setAvc(avc);
  }

  return result;
}

scoped_refptr<viz::RasterContextProvider> GetRasterContextProvider() {
  auto wrapper = SharedGpuContext::ContextProviderWrapper();
  if (!wrapper)
    return nullptr;

  if (auto* provider = wrapper->ContextProvider())
    return base::WrapRefCounted(provider->RasterContextProvider());

  return nullptr;
}

void DeleteArrayBufferContents(void* data) {
    delete[] static_cast<uint8_t*>(data);
}

std::pair<SkColorType, GrGLenum> GetSkiaAndGlColorTypesForPlane(
    media::VideoPixelFormat format,
    size_t plane) {
  // TODO(eugene): There is some strange channel switch during RGB readback.
  // When frame's pixel format matches GL and Skia color types we get reversed
  // channels. But why?
  switch (format) {
    // case PIXEL_FORMAT_NV12:
    //   if (plane == VideoFrame::kUVPlane)
    //     return {kR8G8_unorm_SkColorType, GL_RG8_EXT};
    //   if (plane == VideoFrame::kYPlane)
    //     return {kAlpha_8_SkColorType, GL_R8_EXT};
    //   break;
    // case media::PIXEL_FORMAT_XBGR:
    //   if (plane == media::VideoFrame::kARGBPlane)
    //     return {kRGBA_8888_SkColorType, GL_RGBA8_OES};
    //   break;
    // case media::PIXEL_FORMAT_ABGR:
    //   if (plane == media::VideoFrame::kARGBPlane)
    //     return {kRGBA_8888_SkColorType, GL_RGBA8_OES};
    //   break;
    case media::PIXEL_FORMAT_XRGB:
      if (plane == media::VideoFrame::kARGBPlane)
        return {kBGRA_8888_SkColorType, GL_BGRA8_EXT};
      break;
    case media::PIXEL_FORMAT_ARGB:
      if (plane == media::VideoFrame::kARGBPlane)
        return {kBGRA_8888_SkColorType, GL_BGRA8_EXT};
      break;
    default:
      break;
  }
  NOTREACHED();
  return {kUnknown_SkColorType, 0};
}

scoped_refptr<media::VideoFrame> ReadbackTextureBackedFrameToMemorySyncGLES(
    const media::VideoFrame& txt_frame,
    gpu::raster::RasterInterface* ri,
    //GrDirectContext* gr_context,
    GrContext* gr_context,
    media::VideoFramePool* pool) {
  DCHECK(gr_context);

  if (txt_frame.NumTextures() > 2 || txt_frame.NumTextures() < 1) {
    DLOG(ERROR) << "Readback is not possible for this frame";//: "
                //<< txt_frame.AsHumanReadableString();
    return nullptr;
  }

  media::VideoPixelFormat result_format = txt_frame.format();
  if (txt_frame.NumTextures() == 1 && result_format == media::PIXEL_FORMAT_NV12) {
    // Even though |txt_frame| format is NV12 and it is NV12 in GPU memory,
    // the texture is a RGB view that is produced by a shader on the fly.
    // So we currently we currently can only read it back as RGB.
    result_format = media::PIXEL_FORMAT_ARGB;
  }

  scoped_refptr<media::VideoFrame> result =
      pool
          ? pool->CreateFrame(result_format, txt_frame.coded_size(),
                              txt_frame.visible_rect(),
                              txt_frame.natural_size(), txt_frame.timestamp())
          : media::VideoFrame::CreateFrame(
                result_format, txt_frame.coded_size(), txt_frame.visible_rect(),
                txt_frame.natural_size(), txt_frame.timestamp());
  result->set_color_space(txt_frame.ColorSpace());
  result->metadata()->MergeMetadataFrom(txt_frame.metadata());

  size_t planes = media::VideoFrame::NumPlanes(result->format());
  for (size_t plane = 0; plane < planes; plane++) {
    const gpu::MailboxHolder& holder = txt_frame.mailbox_holder(plane);
    if (holder.mailbox.IsZero())
      return nullptr;
    ri->WaitSyncTokenCHROMIUM(holder.sync_token.GetConstData());

    int width = media::VideoFrame::Columns(plane, result->format(),
                                    result->coded_size().width());
    int height = result->rows(plane);

    auto texture_id = ri->CreateAndConsumeForGpuRaster(holder.mailbox);
    if (holder.mailbox.IsSharedImage()) {
      ri->BeginSharedImageAccessDirectCHROMIUM(
          texture_id, GL_SHARED_IMAGE_ACCESS_MODE_READ_CHROMIUM);
    }

    auto cleanup_fn = [](GLuint texture_id, bool shared,
                         gpu::raster::RasterInterface* ri) {
      if (shared)
        ri->EndSharedImageAccessDirectCHROMIUM(texture_id);
      ri->DeleteGpuRasterTexture(texture_id);
    };
    base::ScopedClosureRunner cleanup(base::BindOnce(
        cleanup_fn, texture_id, holder.mailbox.IsSharedImage(), ri));

    GrGLenum texture_format;
    SkColorType sk_color_type;
    std::tie(sk_color_type, texture_format) =
        GetSkiaAndGlColorTypesForPlane(result->format(), plane);
    GrGLTextureInfo gl_texture_info;
    gl_texture_info.fID = texture_id;
    gl_texture_info.fTarget = holder.texture_target;
    gl_texture_info.fFormat = texture_format;

    GrBackendTexture texture(width, height, GrMipMapped::kNo, gl_texture_info);
    auto image = SkImage::MakeFromTexture(
        gr_context, texture, kTopLeft_GrSurfaceOrigin, sk_color_type,
        kOpaque_SkAlphaType, nullptr /* colorSpace */);

    if (!image) {
      DLOG(ERROR) << "Can't create SkImage from texture!"
                  << " plane:" << plane;
      return nullptr;
    }

    auto info =
        SkImageInfo::Make(width, height, sk_color_type, kOpaque_SkAlphaType);
    SkPixmap pixmap(info, result->data(plane), result->row_bytes(plane));
    if (!image->readPixels(pixmap, 0, 0,
                           SkImage::kDisallow_CachingHint)) {
      DLOG(ERROR) << "Plane readback failed."
                  << " plane:" << plane << " width: " << width
                  << " height: " << height
                  << " minRowBytes: " << info.minRowBytes();
      return nullptr;
    }
  }

  return result;
}

scoped_refptr<media::VideoFrame> ReadbackTextureBackedFrameToMemorySyncOOP(
    const media::VideoFrame& txt_frame,
    gpu::raster::RasterInterface* ri,
    media::VideoFramePool* pool) {
  if (txt_frame.NumTextures() > 2 || txt_frame.NumTextures() < 1) {
    DLOG(ERROR) << "Readback is not possible for this frame";//: "
                //<< txt_frame.AsHumanReadableString();
    return nullptr;
  }

  media::VideoPixelFormat result_format = txt_frame.format();
  if (txt_frame.NumTextures() == 1 && result_format == media::PIXEL_FORMAT_NV12) {
    // Even though |txt_frame| format is NV12 and it is NV12 in GPU memory,
    // the texture is a RGB view that is produced by a shader on the fly.
    // So we currently we currently can only read it back as RGB.
    result_format = media::PIXEL_FORMAT_ARGB;
  }

  scoped_refptr<media::VideoFrame> result =
      pool
          ? pool->CreateFrame(result_format, txt_frame.coded_size(),
                              txt_frame.visible_rect(),
                              txt_frame.natural_size(), txt_frame.timestamp())
          : media::VideoFrame::CreateFrame(
                result_format, txt_frame.coded_size(), txt_frame.visible_rect(),
                txt_frame.natural_size(), txt_frame.timestamp());
  result->set_color_space(txt_frame.ColorSpace());
  result->metadata()->MergeMetadataFrom(txt_frame.metadata());

  size_t planes = media::VideoFrame::NumPlanes(result->format());
  for (size_t plane = 0; plane < planes; plane++) {
    const gpu::MailboxHolder& holder = txt_frame.mailbox_holder(plane);
    if (holder.mailbox.IsZero()) {
      DLOG(ERROR) << "Can't readback video frame with Zero texture on plane "
                  << plane;
      return nullptr;
    }
    ri->WaitSyncTokenCHROMIUM(holder.sync_token.GetConstData());

    int width = media::VideoFrame::Columns(plane, result->format(),
                                    result->coded_size().width());
    int height = result->rows(plane);

    GrGLenum texture_format;
    SkColorType sk_color_type;
    std::tie(sk_color_type, texture_format) =
        GetSkiaAndGlColorTypesForPlane(result->format(), plane);

    auto info =
        SkImageInfo::Make(width, height, sk_color_type, kOpaque_SkAlphaType);

    ri->ReadbackImagePixels(holder.mailbox, info, info.minRowBytes(), 0, 0,
                            result->data(plane));
    if (ri->GetError() != GL_NO_ERROR) {
      DLOG(ERROR) << "Plane readback failed."
                  << " plane:" << plane << " width: " << width
                  << " height: " << height
                  << " minRowBytes: " << info.minRowBytes()
                  << " error: " << ri->GetError();
      return nullptr;
    }
  }

  return result;
}

scoped_refptr<media::VideoFrame> ReadbackTextureBackedFrameToMemorySync(
    const media::VideoFrame& txt_frame,
    gpu::raster::RasterInterface* ri,
    //GrDirectContext* gr_context,
    GrContext* gr_context,
    media::VideoFramePool* pool) {
  DCHECK(ri);

  if (gr_context) {
    return ReadbackTextureBackedFrameToMemorySyncGLES(txt_frame, ri, gr_context,
                                                      pool);
  }
  return ReadbackTextureBackedFrameToMemorySyncOOP(txt_frame, ri, pool);
}

}  // namespace

// static
const char* VideoEncoderTraits::GetNameForDevTools() {
  return "VideoEncoder(WebCodecs)";
}

// static
const char* VideoEncoderTraits::GetName() {
  return "VideoEncoder";
}

// static
VideoEncoder* VideoEncoder::Create(ScriptState* script_state,
                                   const VideoEncoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result = new VideoEncoder(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

VideoEncoder::VideoEncoder(ScriptState* script_state,
                           const VideoEncoderInit* init,
                           ExceptionState& exception_state)
    : Base(script_state, init, exception_state) {
  // UseCounter::Count(ExecutionContext::From(script_state),
  //                   WebFeature::kWebCodecs);
}

VideoEncoder::~VideoEncoder() = default;

VideoEncoder::ParsedConfig* VideoEncoder::ParseConfig(
    const VideoEncoderConfig& config,
    ExceptionState& exception_state) {
  return ParseConfigStatic(config, exception_state);
}

bool VideoEncoder::VerifyCodecSupport(ParsedConfig* config,
                                      ExceptionState& exception_state) {
  return VerifyCodecSupportStatic(*config, &exception_state);
}

void VideoEncoder::UpdateEncoderLog(std::string encoder_name,
                                    bool is_hw_accelerated) {
  // TODO(https://crbug.com/1139089) : Add encoder properties.
  // media::MediaLog* log = logger_->log();

  // log->SetProperty<media::MediaLogProperty::kVideoEncoderName>(encoder_name);
  // log->SetProperty<media::MediaLogProperty::kIsPlatformVideoEncoder>(
  //     is_hw_accelerated);
}

std::unique_ptr<media::VideoEncoder> VideoEncoder::CreateMediaVideoEncoder(
    const ParsedConfig& config,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  switch (config.hw_pref) {
    case HardwarePreference::kRequire: {
      auto result = CreateAcceleratedVideoEncoder(
          config.profile, config.options, gpu_factories);
      if (result)
        UpdateEncoderLog("AcceleratedVideoEncoder", true);
      return result;
    }
    case HardwarePreference::kAllow:
      if (auto result = CreateAcceleratedVideoEncoder(
              config.profile, config.options, gpu_factories)) {
        UpdateEncoderLog("AcceleratedVideoEncoder", true);
        return result;
      }
      FALLTHROUGH;
    case HardwarePreference::kDeny: {
      std::unique_ptr<media::VideoEncoder> result;
      switch (config.codec) {
        case media::kCodecVP8:
        case media::kCodecVP9:
          result = CreateVpxVideoEncoder();
          UpdateEncoderLog("VpxVideoEncoder", false);
          break;
        case media::kCodecH264:
          result = CreateOpenH264VideoEncoder();
          UpdateEncoderLog("OpenH264VideoEncoder", false);
          break;
        default:
          return nullptr;
      }
      if (!result)
        return nullptr;
      //return std::make_unique<media::OffloadingVideoEncoder>(std::move(result));
      return result;
    }

    default:
      NOTREACHED();
      return nullptr;
  }
}

void VideoEncoder::ContinueConfigureWithGpuFactories(
    Request* request,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  DCHECK(active_config_);
  DCHECK_EQ(request->type, Request::Type::kConfigure);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  media_encoder_ = CreateMediaVideoEncoder(*active_config_, gpu_factories);
  if (!media_encoder_) {
    HandleError(logger_->MakeException(
        "Encoder creation error.",
        media::Status(media::StatusCode::kEncoderInitializationError,
                      "Unable to create encoder (most likely unsupported "
                      "codec/acceleration requirement combination)")));
    return;
  }

  auto output_cb = ConvertToBaseCallback(CrossThreadBind(
      &VideoEncoder::CallOutputCallback, WrapCrossThreadWeakPersistent(this),
      // We can't use |active_config_| from |this| because it can change by
      // the time the callback is executed.
      WrapCrossThreadPersistent(active_config_.Get()), reset_count_));

  auto done_callback = [](VideoEncoder* self, Request* req,
                          media::VideoCodec codec, media::Status status) {
    if (!self || self->reset_count_ != req->reset_count)
      return;
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    DCHECK(self->active_config_);

    if (!status.is_ok()) {
      self->HandleError(self->logger_->MakeException(
          "Encoder initialization error.", status));
    } else {
      UMA_HISTOGRAM_ENUMERATION("Blink.WebCodecs.VideoEncoder.Codec", codec,
                                media::kVideoCodecMax + 1);
    }

    self->stall_request_processing_ = false;
    self->ProcessRequests();
  };

  media_encoder_->Initialize(
      active_config_->profile, active_config_->options, std::move(output_cb),
      ConvertToBaseCallback(CrossThreadBind(
          done_callback, WrapCrossThreadWeakPersistent(this),
          WrapCrossThreadPersistent(request), active_config_->codec)));
}

bool VideoEncoder::CanReconfigure(ParsedConfig& original_config,
                                  ParsedConfig& new_config) {
  // Reconfigure is intended for things that don't require changing underlying
  // codec implementation and can be changed on the fly.
  return original_config.codec == new_config.codec &&
         original_config.profile == new_config.profile &&
         original_config.level == new_config.level &&
         original_config.color_space == new_config.color_space &&
         original_config.hw_pref == new_config.hw_pref;
}

void VideoEncoder::ProcessEncode(Request* request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, CodecState::kConfigured);
  DCHECK(media_encoder_);
  DCHECK_EQ(request->type, Request::Type::kEncode);
  DCHECK_GT(requested_encodes_, 0);

  auto done_callback = [](VideoEncoder* self, Request* req,
                          media::Status status) {
    if (!self || self->reset_count_ != req->reset_count)
      return;
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (!status.is_ok()) {
      self->HandleError(
          self->logger_->MakeException("Encoding error.", status));
    }
    self->ProcessRequests();
  };

  scoped_refptr<media::VideoFrame> frame = request->input->frame();

  // Currently underlying encoders can't handle frame backed by textures,
  // so let's readback pixel data to CPU memory.
  if (frame->HasTextures()) {// && !frame->HasGpuMemoryBuffer()) {
    scoped_refptr<viz::RasterContextProvider> raster_context_provider = GetRasterContextProvider();
    if (raster_context_provider) {
      viz::RasterContextProvider::ScopedRasterContextLock scoped_context(
          raster_context_provider.get());
      auto* ri = scoped_context.RasterInterface();
      auto* gr_context = raster_context_provider->GrContext();
      if (ri) {
        frame = ReadbackTextureBackedFrameToMemorySync(*frame, ri, gr_context, &readback_frame_pool_);
      } else {
        frame = nullptr;
      }
    } else {
      frame = nullptr;
    }

  // return media::ReadbackTextureBackedFrameToMemorySync(
  //     *source_frame, ri, gr_context, &pool_for_mapped_frames_);
  //   auto wrapper = SharedGpuContext::ContextProviderWrapper();
  //   if (wrapper && wrapper->ContextProvider()) {
  //       auto* gr_context = wrapper->ContextProvider()->GetGrContext();
  //       gpu::gles2::GLES2Interface* interface = wrapper->ContextProvider()->ContextGL();
  //     if (interface) {
  //       frame = ReadbackTextureBackedFrameToMemorySync(*frame, interface, gr_context,
  //                                                     &readback_frame_pool_);
  //     } else {
  //       frame = nullptr;
  //     }
    //   raster_provider = wrapper->ContextProvider()->RasterContextProvider();
    // if (raster_provider) {
    //   auto* ri = raster_provider->RasterInterface();
    //   auto* gr_context = raster_provider->GrContext();

    //   frame = ReadbackTextureBackedFrameToMemorySync(*frame, ri, gr_context,
    //                                                  &readback_frame_pool_);
    // } else {
    //   frame = nullptr;
    // }
    //}

    if (!frame) {
      auto status = media::Status(media::StatusCode::kEncoderFailedEncode,
                                  "Can't readback frame textures.");
      auto task_runner = base::ThreadTaskRunnerHandle::Get();
      task_runner->PostTask(
          FROM_HERE,
          ConvertToBaseCallback(CrossThreadBind(
              done_callback, WrapCrossThreadWeakPersistent(this),
              WrapCrossThreadPersistent(request), std::move(status))));
      return;
    }
  }

  // Currently underlying encoders can't handle alpha channel, so let's
  // wrap a frame with an alpha channel into a frame without it.
  // For example such frames can come from 2D canvas context with alpha = true.
  if (frame->storage_type() == media::VideoFrame::STORAGE_OWNED_MEMORY &&
      frame->format() == media::PIXEL_FORMAT_I420A) {
    frame = media::WrapAsI420VideoFrame(std::move(frame));
  }

  bool keyframe = request->encodeOpts->keyFrame(); //request->encodeOpts->hasKeyFrameNonNull() &&
                  //request->encodeOpts->keyFrameNonNull();
  --requested_encodes_;
  media_encoder_->Encode(frame, keyframe,
                         ConvertToBaseCallback(CrossThreadBind(
                             done_callback, WrapCrossThreadWeakPersistent(this),
                             WrapCrossThreadPersistent(request))));

  // We passed a copy of frame() above, so this should be safe to close here.
  request->input->close();
}

void VideoEncoder::ProcessConfigure(Request* request) {
  DCHECK_NE(state_, CodecState::kClosed);
  DCHECK_EQ(request->type, Request::Type::kConfigure);
  DCHECK(active_config_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  stall_request_processing_ = true;

  if (active_config_->hw_pref == HardwarePreference::kDeny) {
    ContinueConfigureWithGpuFactories(request, nullptr);
    return;
  }

  RetrieveGpuFactoriesWithKnownEncoderSupport(CrossThreadBind(
      &VideoEncoder::ContinueConfigureWithGpuFactories,
      WrapCrossThreadWeakPersistent(this), WrapCrossThreadPersistent(request)));
}

void VideoEncoder::ProcessReconfigure(Request* request) {
  DCHECK_EQ(state_, CodecState::kConfigured);
  DCHECK_EQ(request->type, Request::Type::kReconfigure);
  DCHECK(active_config_);
  DCHECK(media_encoder_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto reconf_done_callback = [](VideoEncoder* self, Request* req,
                                 media::Status status) {
    if (!self || self->reset_count_ != req->reset_count)
      return;
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    DCHECK(self->active_config_);

    if (status.is_ok()) {
      self->stall_request_processing_ = false;
      self->ProcessRequests();
    } else {
      // Reconfiguration failed. Either encoder doesn't support changing options
      // or it didn't like this particular change. Let's try to configure it
      // from scratch.
      req->type = Request::Type::kConfigure;
      self->ProcessConfigure(req);
    }
  };

  auto flush_done_callback = [](VideoEncoder* self, Request* req,
                                decltype(reconf_done_callback) reconf_callback,
                                media::Status status) {
    if (!self || self->reset_count_ != req->reset_count)
      return;
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (!status.is_ok()) {
      self->HandleError(self->logger_->MakeException(
          "Encoder initialization error.", status));
      self->stall_request_processing_ = false;
      return;
    }

    auto output_cb =
        ConvertToBaseCallback(CrossThreadBind(
            &VideoEncoder::CallOutputCallback,
            WrapCrossThreadWeakPersistent(self),
            // We can't use |active_config_| from |this| because it can change
            // by the time the callback is executed.
            WrapCrossThreadPersistent(self->active_config_.Get()),
            self->reset_count_));

    self->first_output_after_configure_ = true;
    self->media_encoder_->ChangeOptions(
        self->active_config_->options, std::move(output_cb),
        ConvertToBaseCallback(CrossThreadBind(
            reconf_callback, WrapCrossThreadWeakPersistent(self),
            WrapCrossThreadPersistent(req))));
  };

  stall_request_processing_ = true;
  media_encoder_->Flush(WTF::Bind(
      flush_done_callback, WrapCrossThreadWeakPersistent(this),
      WrapCrossThreadPersistent(request), std::move(reconf_done_callback)));
}

void VideoEncoder::CallOutputCallback(
    ParsedConfig* active_config,
    uint32_t reset_count,
    media::VideoEncoderOutput output,
    base::Optional<media::VideoEncoder::CodecDescription> codec_desc) {
  DCHECK(active_config);
  if (!script_state_->ContextIsValid() || !output_callback_ ||
      state_ != CodecState::kConfigured ||
      reset_count != reset_count_)
    return;

  
  WTF::ArrayBufferContents data(WTF::ArrayBufferContents::DataHandle(output.data.release(), output.size, DeleteArrayBufferContents), WTF::ArrayBufferContents::kNotShared);
  auto* dom_array = DOMArrayBuffer::Create(data);
  auto* chunk = new EncodedVideoChunk(
      output.timestamp, output.key_frame, dom_array);

  EncodedVideoChunkMetadata metadata;
  if (active_config->options.temporal_layers > 0)
    metadata.setTemporalLayerId(output.temporal_id);

  if (first_output_after_configure_ || codec_desc.has_value()) {
    first_output_after_configure_ = false;
    VideoDecoderConfig decoder_config;
    decoder_config.setCodec(active_config->codec_string);
    decoder_config.setCodedHeight(active_config->options.frame_size.height());
    decoder_config.setCodedWidth(active_config->options.frame_size.width());

    VideoFrameRegion visible_region;
    decoder_config.setVisibleRegion(visible_region);
    visible_region.setTop(0);
    visible_region.setLeft(0);
    visible_region.setHeight(active_config->options.frame_size.height());
    visible_region.setWidth(active_config->options.frame_size.width());

    if (active_config->display_size.has_value()) {
      decoder_config.setDisplayHeight(
          active_config->display_size.value().height());
      decoder_config.setDisplayWidth(
          active_config->display_size.value().width());
    } else {
      decoder_config.setDisplayHeight(visible_region.height());
      decoder_config.setDisplayWidth(visible_region.width());
    }

    if (codec_desc.has_value()) {
      auto* desc_array_buf = DOMArrayBuffer::Create(codec_desc.value().data(),
                                                    codec_desc.value().size());
      decoder_config.setDescription(
          ArrayBufferOrArrayBufferView::FromArrayBuffer(desc_array_buf));
    }
    metadata.setDecoderConfig(decoder_config);
  }

  ScriptState::Scope scope(script_state_);
  output_callback_->InvokeAndReportException(nullptr, chunk, metadata);
}

static void isConfigSupportedWithSoftwareOnly(
    ScriptPromiseResolver* resolver,
    VideoEncoderSupport support,
    VideoEncoderTraits::ParsedConfig* config) {
  std::unique_ptr<media::VideoEncoder> software_encoder;
  switch (config->codec) {
    case media::kCodecVP8:
    case media::kCodecVP9:
      software_encoder = CreateVpxVideoEncoder();
      break;
    case media::kCodecH264:
      software_encoder = CreateOpenH264VideoEncoder();
      break;
    default:
      break;
  }
  if (!software_encoder) {
    support.setSupported(false);
    resolver->Resolve(support);
    return;
  }

  auto done_callback = [](std::unique_ptr<media::VideoEncoder> sw_encoder,
                          ScriptPromiseResolver* resolver,
                          VideoEncoderSupport support, media::Status status) {
    support.setSupported(status.is_ok());
    resolver->Resolve(support);
    DeleteLater(resolver->GetScriptState(), std::move(sw_encoder));
  };

  auto output_callback = base::DoNothing::Repeatedly<
      media::VideoEncoderOutput,
      base::Optional<media::VideoEncoder::CodecDescription>>();

  auto* software_encoder_raw = software_encoder.get();
  software_encoder_raw->Initialize(
      config->profile, config->options, std::move(output_callback),
      ConvertToBaseCallback(
          CrossThreadBind(done_callback, 
                          WTF::Passed(std::move(software_encoder)),
                          WrapCrossThreadPersistent(resolver),
                          support)));
}

static void isConfigSupportedWithHardwareOnly(
    ScriptPromiseResolver* resolver,
    VideoEncoderSupport support,
    VideoEncoderTraits::ParsedConfig* config,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  bool supported = IsAcceleratedConfigurationSupported(
      config->profile, config->options, gpu_factories);
  support.setSupported(supported);
  resolver->Resolve(support);
}

class FindAnySupportedFunction final : public blink::ScriptFunction {
 public:
  static v8::Local<v8::Function> CreateFunction(
      blink::ScriptState* script_state) {
    FindAnySupportedFunction* self =
        new FindAnySupportedFunction(script_state);
    return self->BindToV8Function();
  }

  void Trace(blink::Visitor* visitor) override {
    blink::ScriptFunction::Trace(visitor);
  }

 private:
  FindAnySupportedFunction(blink::ScriptState* script_state)
      : blink::ScriptFunction(script_state){}

  blink::ScriptValue Call(blink::ScriptValue value) override {
      v8::Isolate* isolate = GetScriptState()->GetIsolate();
      NonThrowableExceptionState exception_state;
      HeapVector<VideoEncoderSupport> supports =
          NativeValueTraits<IDLSequence<VideoEncoderSupport>>::NativeValue(
              isolate, value.V8Value(), exception_state);
      VideoEncoderSupport result;
      for (auto& support : supports) {
        result = support;
        if (result.supported())
          break;
      }
      return ScriptValue::From(GetScriptState(), result);
  }
 
};

// static
ScriptPromise VideoEncoder::isConfigSupported(ScriptState* script_state,
                                              const VideoEncoderConfig& config,
                                              ExceptionState& exception_state) {
  auto* parsed_config = ParseConfigStatic(config, exception_state);
  if (!parsed_config) {
    DCHECK(exception_state.HadException());
    return ScriptPromise();
  }
  //auto* config_copy = CopyConfig(*config);

  // Run very basic coarse synchronous validation
  if (!VerifyCodecSupportStatic(*parsed_config, nullptr)) {
    VideoEncoderSupport support;
    support.setConfig(config);
    support.setSupported(false);
    return ScriptPromise::Cast(script_state, ToV8(support, script_state));
  }

  // Create promises for resolving hardware and software encoding support and
  // put them into |promises|. Simultaneously run both versions of
  // isConfigSupported(), each version fulfills its own promise.
  Vector<ScriptPromise> promises;
  if (parsed_config->hw_pref != HardwarePreference::kDeny) {
    // Hardware support not denied, detect support by hardware encoders.
    auto* resolver = ScriptPromiseResolver::Create(script_state);
    promises.push_back(resolver->Promise());
    VideoEncoderSupport support;
    support.setConfig(config);
    auto gpu_retrieved_callback = CrossThreadBind(
        isConfigSupportedWithHardwareOnly, WrapCrossThreadPersistent(resolver),
        std::move(support),
        WrapCrossThreadPersistent(parsed_config));
    RetrieveGpuFactoriesWithKnownEncoderSupport(
        std::move(gpu_retrieved_callback));
  }

  if (parsed_config->hw_pref != HardwarePreference::kRequire) {
    // Hardware support not required, detect support by software encoders.
    auto* resolver = ScriptPromiseResolver::Create(script_state);
    promises.push_back(resolver->Promise());
    VideoEncoderSupport support;
    support.setConfig(config);
    isConfigSupportedWithSoftwareOnly(resolver, std::move(support), parsed_config);
  }

  // Wait for all |promises| to resolve and check if any of them have
  // support=true.
  return ScriptPromise::All(script_state, promises).Then(FindAnySupportedFunction::CreateFunction(script_state));
}

}  // namespace blink
