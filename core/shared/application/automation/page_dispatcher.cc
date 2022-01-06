// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define INSIDE_BLINK 1
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_regexp.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/user_gesture_indicator.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/imports/html_import_loader.h"
#include "third_party/blink/renderer/core/html/imports/html_imports_controller.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/loader/scheduled_navigation.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/shared_buffer.h"
#include "third_party/blink/renderer/core/inspector/inspector_page_agent.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

#include "core/shared/application/automation/page_dispatcher.h"

#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "ipc/ipc_sync_channel.h"

#pragma clang attribute push
#pragma clang diagnostic ignored "-Wignored-attributes"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wmacro-redefined"
#define V8_BASE_MACROS_H_
#define STATIC_ASSERT(test) static_assert(test, #test)
#include "v8/src/inspector/v8-regex.h"
#pragma clang attribute pop

namespace application {

namespace {

v8_inspector::StringView ToV8InspectorStringView(const StringView& string) {
  if (string.IsNull())
    return v8_inspector::StringView();
  if (string.Is8Bit())
    return v8_inspector::StringView(
        reinterpret_cast<const uint8_t*>(string.Characters8()),
        string.length());
  return v8_inspector::StringView(
      reinterpret_cast<const uint16_t*>(string.Characters16()),
      string.length());
}

v8_inspector::String16 CreateSearchRegexSource(const v8_inspector::String16& text) {
  v8_inspector::String16Builder result;

  for (size_t i = 0; i < text.length(); i++) {
    UChar c = text[i];
    if (c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}' ||
        c == '+' || c == '-' || c == '*' || c == '.' || c == ',' || c == '?' ||
        c == '\\' || c == '^' || c == '$' || c == '|') {
      result.append('\\');
    }
    result.append(c);
  }

  return result.toString();
}

std::unique_ptr<std::vector<size_t>> LineEndings(const v8_inspector::String16& text) {
  std::unique_ptr<std::vector<size_t>> result(new std::vector<size_t>());

  const v8_inspector::String16 lineEndString = "\n";
  size_t start = 0;
  while (start < text.length()) {
    size_t lineEnd = text.find(lineEndString, start);
    if (lineEnd == v8_inspector::String16::kNotFound) break;

    result->push_back(lineEnd);
    start = lineEnd + 1;
  }
  result->push_back(text.length());

  return result;
}

std::vector<std::pair<int, v8_inspector::String16>> ScriptRegexpMatchesByLines(
    const v8_inspector::V8Regex& regex, const v8_inspector::String16& text) {
  std::vector<std::pair<int, v8_inspector::String16>> result;
  if (text.isEmpty()) return result;

  std::unique_ptr<std::vector<size_t>> endings(LineEndings(text));
  size_t size = endings->size();
  size_t start = 0;
  for (size_t lineNumber = 0; lineNumber < size; ++lineNumber) {
    size_t lineEnd = endings->at(lineNumber);
    v8_inspector::String16 line = text.substring(start, lineEnd - start);
    if (line.length() && line[line.length() - 1] == '\r')
      line = line.substring(0, line.length() - 1);

    int matchLength;
    if (regex.match(line, 0, &matchLength) != -1)
      result.push_back(std::pair<int, v8_inspector::String16>(lineNumber, line));

    start = lineEnd + 1;
  }
  return result;
}

std::unique_ptr<v8_inspector::V8Regex> CreateSearchRegex(
  const v8_inspector::String16& query,
  bool caseSensitive, 
  bool isRegex) {
  v8_inspector::String16 regexSource = isRegex ? query : CreateSearchRegexSource(query);
  return std::unique_ptr<v8_inspector::V8Regex>(
      new v8_inspector::V8Regex(nullptr, regexSource, caseSensitive));
}

blink::Resource* CachedResource(blink::LocalFrame* frame,
                                const std::string& url,
                                blink::InspectorResourceContentLoader* loader) {
  blink::KURL kurl(String::FromUTF8(url.data()));
  blink::Document* document = frame->GetDocument();
  if (!document)
    return nullptr;

  blink::Resource* cached_resource = document->Fetcher()->CachedResource(kurl);
  if (!cached_resource) {
    blink::HeapVector<blink::Member<blink::Document>> all_imports =
        PageDispatcher::ImportsForFrame(frame);
    for (blink::Document* import : all_imports) {
      cached_resource = import->Fetcher()->CachedResource(kurl);
      if (cached_resource)
        break;
    }
  }
  if (!cached_resource) {
    cached_resource = blink::GetMemoryCache()->ResourceForURL(
        kurl, document->Fetcher()->GetCacheIdentifier());
  }
  if (!cached_resource)
    cached_resource = loader->ResourceForURL(kurl);
  return cached_resource;
}

std::vector<std::string> GetEnabledWindowFeatures(
    const blink::WebWindowFeatures& window_features) {
    std::vector<std::string> feature_strings;
    if (window_features.x_set) {
      String left_str = String::Format("left=%d", static_cast<int>(window_features.x));
      feature_strings.push_back(std::string(left_str.Utf8().data(), left_str.length()));
    }
    if (window_features.y_set) {
      String top_str = String::Format("top=%d", static_cast<int>(window_features.y));
      feature_strings.push_back(std::string(top_str.Utf8().data(), top_str.length()));
    }
    if (window_features.width_set) {
      String width_str = String::Format("width=%d", static_cast<int>(window_features.width));
      feature_strings.push_back(std::string(width_str.Utf8().data(), width_str.length()));
    }
    if (window_features.height_set) {
      String height_str = String::Format("height=%d", static_cast<int>(window_features.height));
      feature_strings.push_back(std::string(height_str.Utf8().data(), height_str.length()));
    }
    if (window_features.menu_bar_visible)
      feature_strings.push_back("menubar");
    if (window_features.tool_bar_visible)
      feature_strings.push_back("toolbar");
    if (window_features.status_bar_visible)
      feature_strings.push_back("status");
    if (window_features.scrollbars_visible)
      feature_strings.push_back("scrollbars");
    if (window_features.resizable)
      feature_strings.push_back("resizable");
    if (window_features.noopener)
      feature_strings.push_back("noopener");
    if (window_features.background)
      feature_strings.push_back("background");
    if (window_features.persistent)
      feature_strings.push_back("persistent");
    return feature_strings;
}

automation::NavigationReason ScheduledNavigationReasonToProtocol(blink::ScheduledNavigation::Reason reason) {
  using ReasonEnum = automation::NavigationReason;
      
  switch (reason) {
    case blink::ScheduledNavigation::Reason::kFormSubmissionGet:
      return ReasonEnum::kNAVIGATION_FORM_SUBMISSION_GET;
    case blink::ScheduledNavigation::Reason::kFormSubmissionPost:
      return ReasonEnum::kNAVIGATION_FORM_SUBMISSION_POST;
    case blink::ScheduledNavigation::Reason::kHttpHeaderRefresh:
      return ReasonEnum::kNAVIGATION_HTTP_HEADER_REFRESH;
    case blink::ScheduledNavigation::Reason::kFrameNavigation:
      return ReasonEnum::kNAVIGATION_SCRIPT_INITIATED;
    case blink::ScheduledNavigation::Reason::kMetaTagRefresh:
      return ReasonEnum::kNAVIGATION_META_TAG_REFRESH;
    case blink::ScheduledNavigation::Reason::kPageBlock:
      return ReasonEnum::kNAVIGATION_PAGE_BLOCK_INTERSTITIAL;
    case blink::ScheduledNavigation::Reason::kReload:
      return ReasonEnum::kNAVIGATION_RELOAD;
    default:
      NOTREACHED();
  }
  return ReasonEnum::kNAVIGATION_RELOAD;
}


} // namespace

static bool PrepareResourceBuffer(blink::Resource* cached_resource,
                                  bool* has_zero_size) {
  if (!cached_resource)
    return false;

  if (cached_resource->GetDataBufferingPolicy() == blink::kDoNotBufferData)
    return false;

  // Zero-sized resources don't have data at all -- so fake the empty buffer,
  // instead of indicating error by returning 0.
  if (!cached_resource->EncodedSize()) {
    *has_zero_size = true;
    return true;
  }

  *has_zero_size = false;
  return true;
}

static bool HasTextContent(blink::Resource* cached_resource) {
  blink::Resource::Type type = cached_resource->GetType();
  return type == blink::Resource::kCSSStyleSheet || type == blink::Resource::kXSLStyleSheet ||
         type == blink::Resource::kScript || type == blink::Resource::kRaw ||
         type == blink::Resource::kImportResource || type == blink::Resource::kMainResource;
}

static void MaybeEncodeTextContent(const String& text_content,
                                   const char* buffer_data,
                                   size_t buffer_size,
                                   String* result,
                                   bool* base64_encoded) {
  if (!text_content.IsNull() &&
      !text_content.Utf8(WTF::kStrictUTF8Conversion).IsNull()) {
    *result = text_content;
    *base64_encoded = false;
  } else if (buffer_data) {
    *result = Base64Encode(buffer_data, buffer_size);
    *base64_encoded = true;
  } else if (text_content.IsNull()) {
    *result = "";
    *base64_encoded = false;
  } else {
    DCHECK(!text_content.Is8Bit());
    *result = Base64Encode(text_content.Utf8(WTF::kLenientUTF8Conversion));
    *base64_encoded = true;
  }
}

static void MaybeEncodeTextContent(const String& text_content,
                                   scoped_refptr<const blink::SharedBuffer> buffer,
                                   String* result,
                                   bool* base64_encoded) {
  if (!buffer) {
    return MaybeEncodeTextContent(text_content, nullptr, 0, result,
                                  base64_encoded);
  }

  const blink::SharedBuffer::DeprecatedFlatData flat_buffer(std::move(buffer));
  return MaybeEncodeTextContent(text_content, flat_buffer.Data(),
                                flat_buffer.size(), result, base64_encoded);
}

static std::unique_ptr<blink::TextResourceDecoder> CreateResourceTextDecoder(
    const String& mime_type,
    const String& text_encoding_name) {
  if (!text_encoding_name.IsEmpty()) {
    return blink::TextResourceDecoder::Create(blink::TextResourceDecoderOptions(
        blink::TextResourceDecoderOptions::kPlainTextContent,
        WTF::TextEncoding(text_encoding_name)));
  }
  if (blink::DOMImplementation::IsXMLMIMEType(mime_type)) {
    blink::TextResourceDecoderOptions options(blink::TextResourceDecoderOptions::kXMLContent);
    options.SetUseLenientXMLDecoding();
    return blink::TextResourceDecoder::Create(options);
  }
  if (DeprecatedEqualIgnoringCase(mime_type, "text/html")) {
    return blink::TextResourceDecoder::Create(blink::TextResourceDecoderOptions(
        blink::TextResourceDecoderOptions::kHTMLContent, UTF8Encoding()));
  }
  if (blink::MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type) ||
      blink::DOMImplementation::IsJSONMIMEType(mime_type)) {
    return blink::TextResourceDecoder::Create(blink::TextResourceDecoderOptions(
        blink::TextResourceDecoderOptions::kPlainTextContent, UTF8Encoding()));
  }
  if (blink::DOMImplementation::IsTextMIMEType(mime_type)) {
    return blink::TextResourceDecoder::Create(blink::TextResourceDecoderOptions(
        blink::TextResourceDecoderOptions::kPlainTextContent,
        WTF::TextEncoding("ISO-8859-1")));
  }
  return std::unique_ptr<blink::TextResourceDecoder>();
}

static void CachedResourcesForDocument(blink::Document* document,
                                       blink::HeapVector<blink::Member<blink::Resource>>& result,
                                       bool skip_xhrs) {
  const blink::ResourceFetcher::DocumentResourceMap& all_resources =
      document->Fetcher()->AllResources();
  for (const auto& resource : all_resources) {
    blink::Resource* cached_resource = resource.value.Get();
    if (!cached_resource)
      continue;

    // Skip images that were not auto loaded (images disabled in the user
    // agent), fonts that were referenced in CSS but never used/downloaded, etc.
    if (cached_resource->StillNeedsLoad())
      continue;
    if (cached_resource->GetType() == blink::Resource::kRaw && skip_xhrs)
      continue;
    result.push_back(cached_resource);
  }
}

static blink::HeapVector<blink::Member<blink::Resource>> CachedResourcesForFrame(
  blink::LocalFrame* frame, bool skip_xhrs) {
  blink::HeapVector<blink::Member<blink::Resource>> result;
  blink::Document* root_document = frame->GetDocument();
  blink::HeapVector<blink::Member<blink::Document>> loaders = PageDispatcher::ImportsForFrame(frame);
  CachedResourcesForDocument(root_document, result, skip_xhrs);
  for (size_t i = 0; i < loaders.size(); ++i) {
    CachedResourcesForDocument(loaders[i], result, skip_xhrs);
  }

  return result;
}

class InspectorPageAgentImpl : public blink::InspectorPageAgent,
                               public blink::InspectorPageAgent::Client {
public:
  InspectorPageAgentImpl(PageDispatcher* dispatcher): 
    // InspectorPageAgent(InspectedFrames*,
   //                     Client*,
   //                     InspectorResourceContentLoader*,
   //                     v8_inspector::V8InspectorSession*);

    blink::InspectorPageAgent(dispatcher->page_instance_->inspected_frames(),
                              this, 
                              dispatcher->page_instance_->inspector_resource_content_loader(),
                              nullptr),
    dispatcher_(dispatcher) {}

  void DidClearDocumentOfWindowObject(blink::LocalFrame* frame) override {
    dispatcher_->DidClearDocumentOfWindowObject(frame);
  }
  void DidNavigateWithinDocument(blink::LocalFrame* frame) override {
    dispatcher_->DidNavigateWithinDocument(frame);
  }
  void DomContentLoadedEventFired(blink::LocalFrame* frame) override {
    dispatcher_->DomContentLoadedEventFired(frame);
  }
  void LoadEventFired(blink::LocalFrame* frame) override {
    dispatcher_->LoadEventFired(frame);
  }
  void WillCommitLoad(blink::LocalFrame* frame, blink::DocumentLoader* loader) override {
    dispatcher_->WillCommitLoad(frame, loader);
  }
  void FrameAttachedToParent(blink::LocalFrame* frame) override {
    dispatcher_->FrameAttachedToParent(frame);
  }
  void FrameDetachedFromParent(blink::LocalFrame* frame) override {
    dispatcher_->FrameDetachedFromParent(frame);
  }
  void FrameStartedLoading(blink::LocalFrame* frame, blink::FrameLoadType load_type) override {
    dispatcher_->FrameStartedLoading(frame, load_type);
  }
  void FrameStoppedLoading(blink::LocalFrame* frame) override {
    dispatcher_->FrameStoppedLoading(frame);
  }
  void FrameScheduledNavigation(blink::LocalFrame* frame, blink::ScheduledNavigation* navigation) override {
    dispatcher_->FrameScheduledNavigation(frame, navigation);
  }
  void FrameClearedScheduledNavigation(blink::LocalFrame* frame) override {
    dispatcher_->FrameClearedScheduledNavigation(frame);
  }
  void WillRunJavaScriptDialog() override {
    dispatcher_->WillRunJavaScriptDialog();
  }
  void DidRunJavaScriptDialog() override {
    dispatcher_->DidRunJavaScriptDialog();
  }
  void DidResizeMainFrame() override {
    dispatcher_->DidResizeMainFrame();
  }
  void DidChangeViewport() override {
    dispatcher_->DidChangeViewport();
  }
  void PaintTiming(blink::Document* document, const char* name, double timestamp) override {
    dispatcher_->PaintTiming(document, name, timestamp);
  }
  
  void Will(const blink::probe::UpdateLayout& layout) override {
    dispatcher_->Will(layout);
  }

  void Did(const blink::probe::UpdateLayout& layout) override {
    dispatcher_->Did(layout);
  }
  void Will(const blink::probe::RecalculateStyle& style) override {
    dispatcher_->Will(style);
  }
  void Did(const blink::probe::RecalculateStyle& style) override {
    dispatcher_->Did(style);
  }
  void WindowOpen(blink::Document* document,
                  const String& url,
                  const AtomicString& window_name,
                  const blink::WebWindowFeatures& window_features,
                  bool user_gesture) override {
    dispatcher_->WindowOpen(document, url, window_name, window_features, user_gesture);  
  }

  void PageLayoutInvalidated(bool resized) override {
    dispatcher_->PageLayoutInvalidated(resized);
  }

private:
  PageDispatcher* dispatcher_;
};

// static
std::vector<automation::SearchMatchPtr> PageDispatcher::SearchInTextByLines(
  const v8_inspector::String16& text,
  const v8_inspector::String16& query, 
  bool case_sensitive,
  bool is_regex) {
  std::unique_ptr<v8_inspector::V8Regex> regex = CreateSearchRegex(query, case_sensitive, is_regex);
  std::vector<std::pair<int, v8_inspector::String16>> matches =
      ScriptRegexpMatchesByLines(*regex.get(), text);

  std::vector<automation::SearchMatchPtr> result;
  for (const auto& match : matches) {
    automation::SearchMatchPtr m = automation::SearchMatch::New();
    m->line_number = match.first;
    m->line_content = match.second.utf8();
    result.push_back(std::move(m));
  }
  return result;
}

// static 
String PageDispatcher::ResourceTypeJson(
    PageDispatcher::ResourceType resource_type) {
  switch (resource_type) {
    case kDocumentResource:
      return "Document";
    case kFontResource:
      return "Font";
    case kImageResource:
      return "Image";
    case kMediaResource:
      return "Media";
    case kScriptResource:
      return "Script";
    case kStylesheetResource:
      return "Stylesheet";
    case kTextTrackResource:
      return "TextTrack";
    case kXHRResource:
      return "XHR";
    case kFetchResource:
      return "Fetch";
    case kEventSourceResource:
      return "EventSource";
    case kWebSocketResource:
      return "WebSocket";
    case kManifestResource:
      return "Manifest";
    case kOtherResource:
      return "Other";
  }
  return "Other";
}

// static
blink::KURL PageDispatcher::UrlWithoutFragment(const blink::KURL& url) {
  blink::KURL result = url;
  result.RemoveFragmentIdentifier();
  return result;
}

// static 
automation::ResourceType PageDispatcher::ToAutomationResourceType(PageDispatcher::ResourceType resource_type) {
  switch (resource_type) {
    case kDocumentResource:
      return automation::ResourceType::kRESOURCE_TYPE_DOCUMENT;
    case kFontResource:
      return automation::ResourceType::kRESOURCE_TYPE_FONT;
    case kImageResource:
      return automation::ResourceType::kRESOURCE_TYPE_IMAGE;
    case kMediaResource:
      return automation::ResourceType::kRESOURCE_TYPE_MEDIA;
    case kScriptResource:
      return automation::ResourceType::kRESOURCE_TYPE_SCRIPT;
    case kStylesheetResource:
      return automation::ResourceType::kRESOURCE_TYPE_STYLESHEET;
    case kTextTrackResource:
      return automation::ResourceType::kRESOURCE_TYPE_TEXTTRACK;
    case kXHRResource:
      return automation::ResourceType::kRESOURCE_TYPE_XHR;
    case kFetchResource:
      return automation::ResourceType::kRESOURCE_TYPE_FETCH;
    case kEventSourceResource:
      return automation::ResourceType::kRESOURCE_TYPE_EVENTSOURCE;
    case kWebSocketResource:
      return automation::ResourceType::kRESOURCE_TYPE_WEBSOCKET;
    case kManifestResource:
      return automation::ResourceType::kRESOURCE_TYPE_MANIFEST;
    case kOtherResource:
      return automation::ResourceType::kRESOURCE_TYPE_OTHER;
  }
  return automation::ResourceType::kRESOURCE_TYPE_OTHER;
}

// static
bool PageDispatcher::SharedBufferContent(
    scoped_refptr<const blink::SharedBuffer> buffer,
    const String& mime_type,
    const String& text_encoding_name,
    String* result,
    bool* base64_encoded) {
  if (!buffer)
    return false;

  String text_content;
  std::unique_ptr<blink::TextResourceDecoder> decoder =
      CreateResourceTextDecoder(mime_type, text_encoding_name);
  WTF::TextEncoding encoding(text_encoding_name);

  const blink::SharedBuffer::DeprecatedFlatData flat_buffer(std::move(buffer));
  if (decoder) {
    text_content = decoder->Decode(flat_buffer.Data(), flat_buffer.size());
    text_content = text_content + decoder->Flush();
  } else if (encoding.IsValid()) {
    text_content = encoding.Decode(flat_buffer.Data(), flat_buffer.size());
  }

  MaybeEncodeTextContent(text_content, flat_buffer.Data(), flat_buffer.size(),
                         result, base64_encoded);
  return true;
}

// static
blink::HeapVector<blink::Member<blink::Document>> PageDispatcher::ImportsForFrame(
    blink::LocalFrame* frame) {
  blink::HeapVector<blink::Member<blink::Document>> result;
  blink::Document* root_document = frame->GetDocument();

  if (blink::HTMLImportsController* controller = root_document->ImportsController()) {
    for (size_t i = 0; i < controller->LoaderCount(); ++i) {
      if (blink::Document* document = controller->LoaderAt(i)->GetDocument())
        result.push_back(document);
    }
  }

  return result;
}

// static 
PageDispatcher::ResourceType PageDispatcher::ToResourceType(const blink::Resource::Type resource_type) {
  switch (resource_type) {
    case blink::Resource::kImage:
      return PageDispatcher::kImageResource;
    case blink::Resource::kFont:
      return PageDispatcher::kFontResource;
    case blink::Resource::kAudio:
    case blink::Resource::kVideo:
      return PageDispatcher::kMediaResource;
    case blink::Resource::kManifest:
      return PageDispatcher::kManifestResource;
    case blink::Resource::kTextTrack:
      return PageDispatcher::kTextTrackResource;
    case blink::Resource::kCSSStyleSheet:
    // Fall through.
    case blink::Resource::kXSLStyleSheet:
      return PageDispatcher::kStylesheetResource;
    case blink::Resource::kScript:
      return PageDispatcher::kScriptResource;
    case blink::Resource::kImportResource:
    // Fall through.
    case blink::Resource::kMainResource:
      return PageDispatcher::kDocumentResource;
    default:
      break;
  }
  return PageDispatcher::kOtherResource;
}

// static
bool PageDispatcher::CachedResourceContent(blink::Resource* cached_resource,
                                           String* result,
                                           bool* base64_encoded) {
  bool has_zero_size;
  if (!PrepareResourceBuffer(cached_resource, &has_zero_size))
    return false;

  if (!HasTextContent(cached_resource)) {
    scoped_refptr<const blink::SharedBuffer> buffer =
        has_zero_size ? blink::SharedBuffer::Create()
                      : cached_resource->ResourceBuffer();
    if (!buffer)
      return false;

    const blink::SharedBuffer::DeprecatedFlatData flat_buffer(std::move(buffer));
    *result = Base64Encode(flat_buffer.Data(), flat_buffer.size());
    *base64_encoded = true;
    return true;
  }

  if (has_zero_size) {
    *result = "";
    *base64_encoded = false;
    return true;
  }

  DCHECK(cached_resource);
  switch (cached_resource->GetType()) {
    case blink::Resource::kCSSStyleSheet:
      MaybeEncodeTextContent(
          ToCSSStyleSheetResource(cached_resource)
              ->SheetText(nullptr, blink::CSSStyleSheetResource::MIMETypeCheck::kLax),
          cached_resource->ResourceBuffer(), result, base64_encoded);
      return true;
    case blink::Resource::kScript:
      MaybeEncodeTextContent(
          cached_resource->ResourceBuffer()
              ? ToScriptResource(cached_resource)->DecodedText()
              : ToScriptResource(cached_resource)->SourceText(),
          cached_resource->ResourceBuffer(), result, base64_encoded);
      return true;
    default:
      String text_encoding_name =
          cached_resource->GetResponse().TextEncodingName();
      if (text_encoding_name.IsEmpty() &&
          cached_resource->GetType() != blink::Resource::kRaw)
        text_encoding_name = "WinLatin1";
      return PageDispatcher::SharedBufferContent(
          cached_resource->ResourceBuffer(),
          cached_resource->GetResponse().MimeType(), text_encoding_name, result,
          base64_encoded);
  }

}

// static
String PageDispatcher::CachedResourceTypeJson(const blink::Resource& cached_resource) {
  return PageDispatcher::ResourceTypeJson(PageDispatcher::ToResourceType(cached_resource.GetType()));
}

// static 
void PageDispatcher::Create(automation::PageRequest request, ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance) {
  new PageDispatcher(std::move(request), dispatcher, page_instance);
}

PageDispatcher::PageDispatcher(automation::PageRequest request, ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance): 
  application_id_(-1),
  dispatcher_(dispatcher),
  page_instance_(page_instance),
  binding_(this),
  enabled_(false),
  reloading_(false),
  screencast_enabled_(false) {
  
}

PageDispatcher::PageDispatcher(ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance): 
  application_id_(-1),
  dispatcher_(dispatcher),
  page_instance_(page_instance),
  binding_(this), 
  enabled_(false),
  reloading_(false),
  screencast_enabled_(false) {
  

}

PageDispatcher::~PageDispatcher() {
  page_agent_impl_ = nullptr;
}

automation::PageClient* PageDispatcher::GetClient() const {
  return page_client_ptr_.get();
}

void PageDispatcher::Init(IPC::SyncChannel* channel) {
  //DLOG(INFO) << "PageDispatcher::Init: channel->GetRemoteAssociatedInterface(&page_client_ptr_)";
  channel->GetRemoteAssociatedInterface(&page_client_ptr_);
}

void PageDispatcher::Bind(automation::PageAssociatedRequest request) {
  //DLOG(INFO) << "PageDispatcher::BindAssociated";
  binding_.Bind(std::move(request)); 
}

void PageDispatcher::Register(int32_t application_id) {
  //DLOG(INFO) << "PageDispatcher::Register (application process): registering application " << application_id;
  application_id_ = application_id;
}

void PageDispatcher::Enable() {
  //DLOG(INFO) << "PageDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  page_instance_->probe_sink()->addInspectorPageAgent(page_agent_impl_.Get());
  enabled_ = true;
}

void PageDispatcher::Disable() {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  enabled_ = false;
  pending_script_to_evaluate_on_load_once_ = std::string();
  page_instance_->probe_sink()->removeInspectorPageAgent(page_agent_impl_.Get());
  page_instance_->inspector_resource_content_loader()->Cancel(
    page_instance_->inspector_resource_content_loader_id());

  StopScreencast();

  FinishReload();
}

void PageDispatcher::AddScriptToEvaluateOnNewDocument(const std::string& source, AddScriptToEvaluateOnNewDocumentCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  // FIXME: running the scripts are dependent on the events called by the observed frames
  //        those events are not plugged in, so the scripts will never get called
  std::string identifier;
  page_instance_->AddScript(identifier, source);
  std::move(callback).Run(identifier);
}

void PageDispatcher::RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  page_instance_->RemoveScript(identifier);
}

void PageDispatcher::SetAutoAttachToCreatedPages(bool auto_attach) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
}

void PageDispatcher::SetLifecycleEventsEnabled(bool enabled) {
  if (!enabled) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }

  for (blink::LocalFrame* frame : *page_instance_->inspected_frames()) {
    blink::Document* document = frame->GetDocument();
    blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
    if (!document || !loader)
      continue;

    blink::DocumentLoadTiming& timing = loader->GetTiming();
    TimeTicks commit_timestamp = timing.ResponseEnd();
    if (!commit_timestamp.is_null()) {
      DispatchLifecycleEvent(
        frame, 
        loader, 
        "commit",
        TimeTicksInSeconds(commit_timestamp));
    }

    TimeTicks domcontentloaded_timestamp =
        document->GetTiming().DomContentLoadedEventEnd();
    if (!domcontentloaded_timestamp.is_null()) {
      DispatchLifecycleEvent(
        frame, 
        loader, 
        "DOMContentLoaded",
        TimeTicksInSeconds(domcontentloaded_timestamp));
    }

    TimeTicks load_timestamp = timing.LoadEventEnd();
    if (!load_timestamp.is_null()) {
      DispatchLifecycleEvent(
        frame, 
        loader, 
        "load", 
        TimeTicksInSeconds(load_timestamp));
    }

    blink::IdlenessDetector* idleness_detector = frame->GetIdlenessDetector();
    TimeTicks network_almost_idle_timestamp =
        idleness_detector->GetNetworkAlmostIdleTime();
    if (!network_almost_idle_timestamp.is_null()) {
      DispatchLifecycleEvent(
        frame, 
        loader, 
        "networkAlmostIdle",
        TimeTicksInSeconds(network_almost_idle_timestamp));
    }
    TimeTicks network_idle_timestamp = idleness_detector->GetNetworkIdleTime();
    if (!network_idle_timestamp.is_null()) {
      DispatchLifecycleEvent(
        frame, 
        loader, 
        "networkIdle",
        TimeTicksInSeconds(network_idle_timestamp));
    }

  }
}
void PageDispatcher::Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  pending_script_to_evaluate_on_load_once_ = script_to_evaluate_on_load;
  reloading_ = true;
  // GetMainFrame()->Reload(ignore_cache
  //                         ? blink::kFrameLoadTypeReloadBypassingCache
  //                         : blink::kFrameLoadTypeReload,
  //                        blink::ClientRedirectPolicy::kNotClientRedirect);
  dispatcher_->Reload(ignore_cache);
}

void PageDispatcher::SetAdBlockingEnabled(bool enabled) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }

  // it does nothing on purpose
  //DLOG(INFO) << "Page::SetAdBlockingEnabled: DOES NOTHING";
}

void PageDispatcher::Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, NavigateCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  //DLOG(INFO) << "Page::Navigate: EXPERIMENTAL, see if it works";
  dispatcher_->BeginNavigation(url);
  // theres also dispatcher_->OpenURL(const GURL& url);
  // see which id the right one
}

void PageDispatcher::StopLoading() {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  //DLOG(INFO) << "Page::StopLoading: EXPERIMENTAL, see if it works";
  dispatcher_->Stop();
}

void PageDispatcher::GetNavigationHistory(GetNavigationHistoryCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  //DLOG(INFO) << "Page::GetNavigationHistory: not implemented";
}

void PageDispatcher::NavigateToHistoryEntry(int32_t entry_id) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  //DLOG(INFO) << "Page::NavigateToHistoryEntry: not implemented";
}

void PageDispatcher::GetCookies(GetCookiesCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
}

void PageDispatcher::DeleteCookie(const std::string& cookie_name, const std::string& url) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
}

void PageDispatcher::FinishReload() {
  if (!reloading_)
    return;
  reloading_ = false;
}

void PageDispatcher::GetResourceTree(GetResourceTreeCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  std::move(callback).Run(BuildObjectForResourceTree(GetMainFrame()));
}

void PageDispatcher::GetFrameTree(GetFrameTreeCallback callback) {
  //DLOG(INFO) << "PageDispatcher::GetFrameTree";
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  std::move(callback).Run(BuildObjectForFrameTree(GetMainFrame()));
}

void PageDispatcher::GetResourceContent(const std::string& frame_id, const std::string& url, GetResourceContentCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  page_instance_->inspector_resource_content_loader()->EnsureResourcesContentLoaded(
      page_instance_->inspector_resource_content_loader_id(),
      WTF::Bind(
          &PageDispatcher::GetResourceContentAfterResourcesContentLoaded,
          WTF::Unretained(this), frame_id, url,
          WTF::Passed(std::move(callback))));
}

void PageDispatcher::GetResourceContentAfterResourcesContentLoaded(
  const std::string& frame_id, 
  const std::string& url,
  GetResourceContentCallback callback) {
  blink::LocalFrame* frame =
      blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  if (!frame) {
    //DLOG(ERROR) << "No frame for given id found";
    return;
  }
  String content;
  bool base64_encoded;
  if (PageDispatcher::CachedResourceContent(
        CachedResource(frame, url, page_instance_->inspector_resource_content_loader()),
        &content, &base64_encoded)) {
    std::string content_str(reinterpret_cast<const char *>(content.Characters8()), content.length());
    std::move(callback).Run(std::move(content_str), base64_encoded);
  } else {
    //DLOG(ERROR) << "No resource with given URL found";
    //callback->sendFailure(Response::Error("No resource with given URL found"));
  }
}

void PageDispatcher::SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, SearchInResourceCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Page is not enabled.";
    return;
  }
  page_instance_->inspector_resource_content_loader()->EnsureResourcesContentLoaded(
      page_instance_->inspector_resource_content_loader_id(),
      WTF::Bind(&PageDispatcher::SearchContentAfterResourcesContentLoaded,
                WTF::Unretained(this), frame_id, url, query,
                case_sensitive,
                is_regex,
                WTF::Passed(std::move(callback))));
}

void PageDispatcher::SetDocumentContent(const std::string& frame_id, const std::string& html) {
  //DLOG(INFO) << "PageDispatcher::SetDocumentContent (application): frame_id = " << frame_id;
  blink::LocalFrame* frame =
      blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  if (!frame) {
    //DLOG(ERROR) << "No frame for given id found";
    return;
  }

  blink::Document* document = frame->GetDocument();
  if (!document) {
    //DLOG(ERROR) << "No Document instance to set HTML for";
    return;
  }
  //DLOG(INFO) << "PageDispatcher::SetDocumentContent (application): calling document->SetContent()";
  document->SetContent(String::FromUTF8(html.data()));
}

void PageDispatcher::SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {

}

void PageDispatcher::ClearDeviceMetricsOverride() {

}

void PageDispatcher::SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) {

}

void PageDispatcher::ClearGeolocationOverride() {

}

void PageDispatcher::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {

}

void PageDispatcher::ClearDeviceOrientationOverride() {

}

void PageDispatcher::SetTouchEmulationEnabled(bool enabled, const std::string& configuration) {

}

void PageDispatcher::CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, CaptureScreenshotCallback callback) {

}

void PageDispatcher::PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, PrintToPDFCallback callback) {

}

void PageDispatcher::StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) {
  // FIXME: implement
  screencast_enabled_ = true;
}

void PageDispatcher::StopScreencast() {
  // FIXME: implement
  screencast_enabled_ = false;
}

void PageDispatcher::ScreencastFrameAck(int32_t session_id) {
  //DLOG(INFO) << "PageDispatcher::ScreencastFrameAck: Not implemented";
}

void PageDispatcher::HandleJavaScriptDialog(bool accept, const std::string& prompt_text) {
  //DLOG(INFO) << "PageDispatcher::HandleJavaScriptDialog: Not implemented";
}

void PageDispatcher::GetAppManifest(GetAppManifestCallback callback) {
  //DLOG(INFO) << "PageDispatcher::GetAppManifest: Not implemented";
}

void PageDispatcher::RequestAppBanner() {
  //DLOG(INFO) << "PageDispatcher::RequestAppBanner: Not implemented";
}

void PageDispatcher::GetLayoutMetrics(GetLayoutMetricsCallback callback) {
  // callback = (LayoutViewport layout_viewport, VisualViewport visual_viewport, gfx.mojom.Rect content_size);
  blink::LocalFrame* main_frame = GetMainFrame();

  automation::LayoutViewportPtr rlayout_viewport = automation::LayoutViewport::New();  
  automation::VisualViewportPtr rvisual_viewport = automation::VisualViewport::New(); 
  gfx::Rect rcontent_size;
  
  blink::VisualViewport& visual_viewport = main_frame->GetPage()->GetVisualViewport();

  main_frame->GetDocument()->UpdateStyleAndLayoutIgnorePendingStylesheets();

  blink::IntRect visible_contents =
      main_frame->View()->LayoutViewportScrollableArea()->VisibleContentRect();
  
  rlayout_viewport->page_x = visible_contents.X();
  rlayout_viewport->page_y = visible_contents.Y();
  rlayout_viewport->client_width = visible_contents.Width();
  rlayout_viewport->client_height = visible_contents.Width();

  blink::LocalFrameView* frame_view = main_frame->View();
  blink::ScrollOffset page_offset = frame_view->GetScrollableArea()->GetScrollOffset();
  float page_zoom = main_frame->PageZoomFactor();
  blink::FloatRect visible_rect = visual_viewport.VisibleRect();
  float scale = visual_viewport.Scale();
  float scrollbar_width =
      frame_view->LayoutViewportScrollableArea()->VerticalScrollbarWidth() /
      scale;
  float scrollbar_height =
      frame_view->LayoutViewportScrollableArea()->HorizontalScrollbarHeight() /
      scale;

  blink::IntSize content_size = frame_view->GetScrollableArea()->ContentsSize();
  
  rcontent_size.set_x(0);
  rcontent_size.set_y(0);
  rcontent_size.set_width(content_size.Width());
  rcontent_size.set_width(content_size.Height());
  
  rvisual_viewport->offset_x = blink::AdjustForAbsoluteZoom::AdjustScroll(visible_rect.X(), page_zoom);
  rvisual_viewport->offset_y = blink::AdjustForAbsoluteZoom::AdjustScroll(visible_rect.Y(), page_zoom);
  rvisual_viewport->page_x = blink::AdjustForAbsoluteZoom::AdjustScroll(page_offset.Width(), page_zoom);
  rvisual_viewport->page_y = blink::AdjustForAbsoluteZoom::AdjustScroll(page_offset.Height(), page_zoom); 
  rvisual_viewport->client_width = visible_rect.Width() - scrollbar_width;
  rvisual_viewport->client_height = visible_rect.Height() - scrollbar_height;
  rvisual_viewport->scale = scale;

  std::move(callback).Run(std::move(rlayout_viewport), std::move(rvisual_viewport), std::move(rcontent_size)); 
}

void PageDispatcher::CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, CreateIsolatedWorldCallback callback) {
  blink::LocalFrame* frame =
      blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  if (!frame) {
    //DLOG(ERROR) << "No frame for given id found";
    return;
  }

  scoped_refptr<blink::DOMWrapperWorld> world =
      frame->GetScriptController().CreateNewInspectorIsolatedWorld(
          String::FromUTF8(world_name.value_or("").data()));
  if (!world) {
    //DLOG(ERROR) << "Could not create isolated world";
    return;
  }

  if (grant_universal_access) {
    scoped_refptr<blink::SecurityOrigin> security_origin =
        frame->GetSecurityContext()->GetSecurityOrigin()->IsolatedCopy();
    security_origin->GrantUniversalAccess();
    blink::DOMWrapperWorld::SetIsolatedWorldSecurityOrigin(world->GetWorldId(),
                                                    security_origin);
  }

  blink::LocalWindowProxy* isolated_world_window_proxy =
      frame->GetScriptController().WindowProxy(*world);
  v8::HandleScope handle_scope(blink::V8PerIsolateData::MainThreadIsolate());
  int32_t execution_context_id = v8_inspector::V8ContextInfo::executionContextId(
      isolated_world_window_proxy->ContextIfInitialized());
  std::move(callback).Run(execution_context_id);
}

void PageDispatcher::BringToFront() {
  //DLOG(INFO) << "PageDispatcher::BringToFront: Not implemented";
}

void PageDispatcher::SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) {
  //DLOG(INFO) << "PageDispatcher::SetDownloadBehavior: Not implemented";
}

void PageDispatcher::Close() {
  //DLOG(INFO) << "PageDispatcher::Close: experimental, see if it works";
  dispatcher_->Close();
}

blink::LocalFrame* PageDispatcher::GetMainFrame() {
  return page_instance_->inspected_frames()->Root();
}

void PageDispatcher::SetBypassCSP(bool enabled) {
  blink::LocalFrame* frame = GetMainFrame();
  frame->GetSettings()->SetBypassCSP(enabled);
  page_instance_->set_bypass_csp_enabled(enabled);
}

void PageDispatcher::DispatchFrameAttached(blink::LocalFrame* frame, blink::LocalFrame* parent_frame) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  String parent_frame_id = blink::IdentifiersFactory::FrameId(parent_frame);
  GetClient()->OnFrameAttached(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()),
                               std::string(parent_frame_id.Utf8().data(), parent_frame_id.Utf8().length()));
}

void PageDispatcher::DispatchDomContentEventFired(blink::LocalFrame* frame) {
  int64_t timestamp = base::saturated_cast<int64_t>(WTF::CurrentTimeTicksInSeconds());
  if (frame == GetMainFrame()) {
    GetClient()->OnDomContentEventFired(timestamp);
  }
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  DispatchLifecycleEvent(frame, loader, "DOMContentLoaded", timestamp);
}

void PageDispatcher::DispatchFrameClearedScheduledNavigation(blink::LocalFrame* frame) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnFrameClearedScheduledNavigation(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()));
}

void PageDispatcher::DispatchFrameDetached(blink::LocalFrame* frame) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnFrameDetached(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()));
}

void PageDispatcher::DispatchFrameNavigated(blink::LocalFrame* frame) {
  GetClient()->OnFrameNavigated(BuildObjectForFrame(frame));
}

void PageDispatcher::DispatchFrameResized() {
  GetClient()->OnFrameResized();
}

void PageDispatcher::DispatchFrameScheduledNavigation(blink::LocalFrame* frame, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnFrameScheduledNavigation(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()),
    delay, reason, url);
}

void PageDispatcher::DispatchFrameStartedLoading(blink::LocalFrame* frame) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnFrameStartedLoading(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()));
}

void PageDispatcher::DispatchFrameStoppedLoading(blink::LocalFrame* frame) {
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnFrameStoppedLoading(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()));
}

void PageDispatcher::DispatchInterstitialHidden() {
  GetClient()->OnInterstitialHidden();
}

void PageDispatcher::DispatchInterstitialShown() {
  GetClient()->OnInterstitialShown();
}

void PageDispatcher::DispatchJavascriptDialogClosed(bool result, const std::string& user_input) {
  GetClient()->OnJavascriptDialogClosed(result, user_input);
}

void PageDispatcher::DispatchJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) {
  GetClient()->OnJavascriptDialogOpening(url, message, type, has_browser_handler, default_prompt);
}

void PageDispatcher::DispatchLoadEventFired(blink::LocalFrame* frame) {
  int64_t timestamp = base::saturated_cast<int64_t>(WTF::CurrentTimeTicksInSeconds());
  if (frame == GetMainFrame()) {
    GetClient()->OnLoadEventFired(timestamp);
  }
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  DispatchLifecycleEvent(frame, loader, "load", timestamp);
}

void PageDispatcher::DispatchNavigatedWithinDocument(blink::LocalFrame* frame, const std::string& url) {
  blink::Document* document = frame->GetDocument();
  if (document) {
    String frame_id = blink::IdentifiersFactory::FrameId(frame);
    GetClient()->OnNavigatedWithinDocument(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()), url);
  }
}

void PageDispatcher::DispatchScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  GetClient()->OnScreencastFrame(base64_data, std::move(metadata), session_id);
}

void PageDispatcher::DispatchScreencastVisibilityChanged(bool visible) {
  GetClient()->OnScreencastVisibilityChanged(visible);
}

void PageDispatcher::DispatchWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  GetClient()->OnWindowOpen(url, window_name, window_features, user_gesture);
}

void PageDispatcher::DispatchLifecycleEvent(
  blink::LocalFrame* frame,
  blink::DocumentLoader* loader,
  const char* name,
  double timestamp) {
  if (!loader)
    return;

  String frame_id = blink::IdentifiersFactory::FrameId(frame);  
  String loader_id =  blink::IdentifiersFactory::LoaderId(loader);
  int32_t loader_id_num = loader_id.ToInt();
  GetClient()->OnLifecycleEvent(std::string(frame_id.Utf8().data(), frame_id.Utf8().length()),
                                loader_id_num, 
                                name,
                                timestamp);
}

void PageDispatcher::SearchContentAfterResourcesContentLoaded(
    const std::string& frame_id,
    const std::string& url,
    const std::string& query,
    bool case_sensitive,
    bool is_regex,
    SearchInResourceCallback callback) {
  blink::LocalFrame* frame =
      blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  if (!frame) {
    //DLOG(ERROR) << "No frame for given id found";
    return;
  }
  String content;
  bool base64_encoded;
  if (!PageDispatcher::CachedResourceContent(
          CachedResource(frame, url, page_instance_->inspector_resource_content_loader()),
          &content, &base64_encoded)) {
    //DLOG(ERROR) << "No resource with given URL found";
    return;
  }

  v8_inspector::StringView contents_view = ToV8InspectorStringView(content);
  v8_inspector::StringView query_view = ToV8InspectorStringView(String::FromUTF8(query.data()));

  auto matches = PageDispatcher::SearchInTextByLines(
      v8_inspector::String16(contents_view.characters16(), contents_view.length()), v8_inspector::String16(query_view.characters16(), query_view.length()),
      case_sensitive, is_regex);
  std::move(callback).Run(std::move(matches));
}

automation::FramePtr PageDispatcher::BuildObjectForFrame(blink::LocalFrame* frame) {
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  blink::KURL url = loader->GetRequest().Url();
  automation::FramePtr frame_object = automation::Frame::New();
  String frame_id = blink::IdentifiersFactory::FrameId(frame);
  String loader_id = blink::IdentifiersFactory::LoaderId(loader);
  frame_object->id = std::string(frame_id.Utf8().data(), frame_id.length());
  frame_object->loader_id = std::string(loader_id.Utf8().data(), loader_id.length());
  frame_object->mime_type = std::string(frame->Loader().GetDocumentLoader()->MimeType().Utf8().data());
  frame_object->security_origin = std::string(blink::SecurityOrigin::Create(url)->ToRawString().Utf8().data());
  blink::Frame* parent_frame = frame->Tree().Parent();
  if (parent_frame) {
    String parent_id = blink::IdentifiersFactory::FrameId(parent_frame);
    frame_object->parent_id = std::string(parent_id.Utf8().data(), parent_id.length());
    AtomicString name = frame->Tree().GetName();
    if (name.IsEmpty() && frame->DeprecatedLocalOwner()) {
      name = frame->DeprecatedLocalOwner()->getAttribute(blink::HTMLNames::idAttr);
    }
    frame_object->name = std::string(name.Utf8().data(), name.length());
  }
  if (loader && !loader->UnreachableURL().IsEmpty()) {
    frame_object->unreachable_url = std::string(loader->UnreachableURL().GetString().Utf8().data());
  }
  return frame_object;
}

automation::FrameTreePtr PageDispatcher::BuildObjectForFrameTree(blink::LocalFrame* frame) {
  automation::FrameTreePtr handle = automation::FrameTree::New();
  handle->frame = BuildObjectForFrame(frame);
  std::vector<automation::FrameTreePtr> children_array;
  for (blink::Frame* child = frame->Tree().FirstChild(); child; child = child->Tree().NextSibling()) {
    if (!child->IsLocalFrame()) {
      continue;
    }
    children_array.push_back(BuildObjectForFrameTree(ToLocalFrame(child)));
  }
  handle->child_frames = std::move(children_array);
  //DLOG(INFO) << "PageDispatcher::BuildObjectForFrameTree: frame_id = '" << handle->frame->id << "'";
  return handle;
}

automation::FrameResourceTreePtr PageDispatcher::BuildObjectForResourceTree(blink::LocalFrame* frame) {
  automation::FrameResourceTreePtr result = automation::FrameResourceTree::New();
  automation::FramePtr frame_object = BuildObjectForFrame(frame);
  std::vector<automation::FrameResourcePtr> subresources;
  blink::HeapVector<blink::Member<blink::Resource>> all_resources = CachedResourcesForFrame(frame, true);
  for (blink::Resource* cached_resource : all_resources) {
    automation::FrameResourcePtr resource_object = automation::FrameResource::New();
    resource_object->url = std::string(cached_resource->Url().GetString().Utf8().data());//std::string(UrlWithoutFragment(cached_resource->Url()).GetString().Utf8().data());
    resource_object->type = PageDispatcher::ToAutomationResourceType(PageDispatcher::ToResourceType(cached_resource->GetType()));
    resource_object->mime_type = std::string(cached_resource->GetResponse().MimeType().Utf8().data());
    resource_object->content_size = cached_resource->GetResponse().DecodedBodyLength();
    double last_modified = cached_resource->GetResponse().LastModified();
    if (!std::isnan(last_modified))
      resource_object->last_modified = last_modified;
    if (cached_resource->WasCanceled())
      resource_object->canceled = true;
    else if (cached_resource->GetStatus() == blink::ResourceStatus::kLoadError)
      resource_object->failed = true;
    subresources.push_back(std::move(resource_object));
  }
  
  blink::HeapVector<blink::Member<blink::Document>> all_imports = blink::InspectorPageAgent::ImportsForFrame(frame);
  for (blink::Document* import : all_imports) {
    automation::FrameResourcePtr resource_object = automation::FrameResource::New();
    resource_object->url = std::string(import->Url().GetString().Utf8().data());//std::string(UrlWithoutFragment(import->Url()).GetString().Utf8().data());
    resource_object->type = PageDispatcher::ToAutomationResourceType(PageDispatcher::kDocumentResource);
    resource_object->mime_type = std::string(import->SuggestedMIMEType().Utf8().data());
    subresources.push_back(std::move(resource_object));
  }

  result->frame = std::move(frame_object);
  result->resources = std::move(subresources);
  
  std::vector<automation::FrameResourceTreePtr> children_array;
  for (blink::Frame* child = frame->Tree().FirstChild(); child; child = child->Tree().NextSibling()) {
    if (!child->IsLocalFrame()) {
      continue;
    }
    children_array.push_back(BuildObjectForResourceTree(ToLocalFrame(child)));
  }
  result->child_frames = std::move(children_array);
  return result;
}

// instrumentation

// FIXME: here goes the callbacks that need to be called by someone else like LocalFrames
//        every time those events happens
//        Right now theres no one calling those 
void PageDispatcher::DidClearDocumentOfWindowObject(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::DidClearDocumentOfWindowObject (application)";
  if (page_instance_->script_count() > 0) {
    for (size_t i = 0; i < page_instance_->script_count(); ++i) {
      const auto& script = page_instance_->script_at(i);
      frame->GetScriptController().ExecuteScriptInMainWorld(String::FromUTF8(script.data()));
    }
  }
  if (!script_to_evaluate_on_load_once_.empty()) {
    frame->GetScriptController().ExecuteScriptInMainWorld(String::FromUTF8(script_to_evaluate_on_load_once_.data()));
    script_to_evaluate_on_load_once_ = std::string();    
  }
}

void PageDispatcher::WillCommitLoad(blink::LocalFrame* frame, blink::DocumentLoader* loader) {
  //DLOG(INFO) << "PageDispatcher::WillCommitLoad (application)";
  if (loader->GetFrame() == GetMainFrame()) {
    FinishReload();
    script_to_evaluate_on_load_once_ = pending_script_to_evaluate_on_load_once_;
    pending_script_to_evaluate_on_load_once_ = std::string();
  }
  GetClient()->OnFrameNavigated(BuildObjectForFrame(frame));
}

void PageDispatcher::DidNavigateWithinDocument(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::DidNavigateWithinDocument (application)";
  blink::Document* document = frame->GetDocument();
  if (document) {
    GetClient()->OnNavigatedWithinDocument(
      std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()), 
      std::string(document->Url().GetString().Utf8().data()));
  }
}

void PageDispatcher::DomContentLoadedEventFired(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::DomContentLoadedEventFired (application)";
  double timestamp = base::TimeTicks::Now().since_origin().InSecondsF();
  if (frame == page_instance_->inspected_frames()->Root())
    GetClient()->OnDomContentEventFired(timestamp);
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  DispatchLifecycleEvent(frame, loader, "DOMContentLoaded", timestamp);
}

void PageDispatcher::LoadEventFired(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::LoadEventFired (application)";
  double timestamp = base::TimeTicks::Now().since_origin().InSecondsF();
  if (frame == page_instance_->inspected_frames()->Root())
    GetClient()->OnLoadEventFired(timestamp);
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  DispatchLifecycleEvent(frame, loader, "load", timestamp);
}

void PageDispatcher::FrameAttachedToParent(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::FrameAttachedToParent (application)";
  blink::Frame* parent_frame = frame->Tree().Parent();
  // std::unique_ptr<SourceLocation> location =
  //     SourceLocation::CaptureWithFullStackTrace();
  GetClient()->OnFrameAttached(
      std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()),
      std::string(blink::IdentifiersFactory::FrameId(parent_frame).Utf8().data()));//location ? location->BuildInspectorObject() : nullptr);
  // Some network events referencing this frame will be reported from the
  // browser, so make sure to deliver FrameAttached without buffering,
  // so it gets to the front-end first.
  //GetClient()->Flush();
}

void PageDispatcher::FrameDetachedFromParent(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::FrameDetachedFromParent (application)";
  GetClient()->OnFrameDetached(std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()));
}

void PageDispatcher::FrameStartedLoading(blink::LocalFrame* frame, blink::FrameLoadType type) {
  //DLOG(INFO) << "PageDispatcher::FrameStartedLoading (application)";
  GetClient()->OnFrameStartedLoading(std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()));
  //GetClient()->Flush();
}

void PageDispatcher::FrameStoppedLoading(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::FrameStoppedLoading (application)";
  GetClient()->OnFrameStoppedLoading(std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()));
  //GetClient()->Flush();
}

void PageDispatcher::FrameScheduledNavigation(blink::LocalFrame* frame, blink::ScheduledNavigation* navigation) {
  //DLOG(INFO) << "PageDispatcher::FrameScheduledNavigation (application)";
  GetClient()->OnFrameScheduledNavigation(
      std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()),
      navigation->Delay(),
      ScheduledNavigationReasonToProtocol(navigation->GetReason()),
      std::string(navigation->Url().GetString().Utf8().data()));
}

void PageDispatcher::FrameClearedScheduledNavigation(blink::LocalFrame* frame) {
  //DLOG(INFO) << "PageDispatcher::FrameClearedScheduledNavigation (application)";
  GetClient()->OnFrameClearedScheduledNavigation(
    std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()));
  //GetClient()->Flush();
}

void PageDispatcher::WillRunJavaScriptDialog() {
  //DLOG(INFO) << "PageDispatcher::WillRunJavaScriptDialog (application)"; 
  //GetClient()->Flush();
}

void PageDispatcher::DidRunJavaScriptDialog() {
  //DLOG(INFO) << "PageDispatcher::DidRunJavaScriptDialog (application)";
  //GetClient()->Flush();
}

void PageDispatcher::PaintTiming(blink::Document* document, const char* name, double timestamp) {
  //DLOG(INFO) << "PageDispatcher::PaintTiming (application): '" << name << "'";
  blink::LocalFrame* frame = document->GetFrame();
  blink::DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  DispatchLifecycleEvent(frame, loader, name, timestamp);
}

void PageDispatcher::Will(const blink::probe::UpdateLayout&) {
  //DLOG(INFO) << "PageDispatcher::Will(UpdateLayout) (application)";
}

void PageDispatcher::Did(const blink::probe::UpdateLayout&) {
  //DLOG(INFO) << "PageDispatcher::Did(UpdateLayout) (application)";
  PageLayoutInvalidated(false);
}

void PageDispatcher::Will(const blink::probe::RecalculateStyle&) {
  //DLOG(INFO) << "PageDispatcher::Will(RecalculateStyle) (application)";
}

void PageDispatcher::Did(const blink::probe::RecalculateStyle&) {
  //DLOG(INFO) << "PageDispatcher::Did(RecalculateStyle) (application)";
  PageLayoutInvalidated(false);
}

void PageDispatcher::WindowOpen(blink::Document* document,
                                const String& url,
                                const AtomicString& window_name,
                                const blink::WebWindowFeatures& window_features,
                                bool user_gesture) {
  //DLOG(INFO) << "PageDispatcher::WindowOpen (application): '" << std::string(url.Utf8().data(), url.Utf8().length()) << "'";
  GetClient()->OnWindowOpen(std::string(url.Utf8().data(), url.Utf8().length()), 
                            std::string(window_name.Utf8().data(), window_name.length()),
                            GetEnabledWindowFeatures(window_features),
                            user_gesture);
  //GetClient()->Flush();
}

void PageDispatcher::DidResizeMainFrame() {
  //DLOG(INFO) << "PageDispatcher::DidResizeMainFrame (application)";
  if (!page_instance_->inspected_frames()->Root()->IsMainFrame()) {
    return;
  }
#if !defined(OS_ANDROID)
  PageLayoutInvalidated(true);
#endif
  GetClient()->OnFrameResized();
}

void PageDispatcher::DidChangeViewport() {
  //DLOG(INFO) << "PageDispatcher::DidChangeViewport (application)";
  PageLayoutInvalidated(false);
}

void PageDispatcher::PageLayoutInvalidated(bool resized) {
  //DLOG(INFO) << "PageDispatcher::PageLayoutInvalidated (application)";
  if (enabled_) {
    GetClient()->OnPageLayoutInvalidated(resized);
  }
}

void PageDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  page_agent_impl_ = new InspectorPageAgentImpl(this);
  page_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  Enable();
}

}
