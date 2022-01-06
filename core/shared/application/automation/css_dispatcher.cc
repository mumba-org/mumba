// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/css_dispatcher.h"

#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/automation/automation_context.h"
#include "core/shared/application/automation/dom_service.h"
#include "core/shared/application/application_window_dispatcher.h"

#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/css/css_color_value.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_rule_usage_tracker.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/css_property_names.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/line/inline_text_box.h"
#include "third_party/blink/renderer/core/layout/ng/inline/ng_physical_text_fragment.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/ng/ng_paint_fragment.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_custom_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/caching_word_shaper.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/wtf/text/cstring.h"
#include "third_party/blink/renderer/platform/wtf/text/string_concatenate.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "ipc/ipc_sync_channel.h"


namespace application {

namespace {

String DocumentURLString(blink::Document* document) {
  if (!document || document->Url().IsNull())
    return "";
  return document->Url().GetString();
}

inline bool MatchesPseudoElement(const blink::CSSSelector* selector,
                                        blink::PseudoId element_pseudo_id) {
  // According to http://www.w3.org/TR/css3-selectors/#pseudo-elements, "Only
  // one pseudo-element may appear per selector."
  // As such, check the last selector in the tag history.
  for (; !selector->IsLastInTagHistory(); ++selector) {
  }
  blink::PseudoId selector_pseudo_id =
      blink::CSSSelector::GetPseudoId(selector->GetPseudoType());

  // FIXME: This only covers the case of matching pseudo-element selectors
  // against PseudoElements.  We should come up with a solution for matching
  // pseudo-element selectors against ordinary Elements, too.
  return selector_pseudo_id == element_pseudo_id;
}

template <class CSSRuleCollection>
blink::CSSKeyframesRule* FindKeyframesRule(CSSRuleCollection* css_rules,
                                           blink::StyleRuleKeyframes* keyframes_rule) {
  blink::CSSKeyframesRule* result = nullptr;
  for (unsigned j = 0; css_rules && j < css_rules->length() && !result; ++j) {
    blink::CSSRule* css_rule = css_rules->item(j);
    if (css_rule->type() == blink::CSSRule::kKeyframesRule) {
      blink::CSSKeyframesRule* css_style_rule = blink::ToCSSKeyframesRule(css_rule);
      if (css_style_rule->Keyframes() == keyframes_rule)
        result = css_style_rule;
    } else if (css_rule->type() == blink::CSSRule::kImportRule) {
      blink::CSSImportRule* css_import_rule = blink::ToCSSImportRule(css_rule);
      result = FindKeyframesRule(css_import_rule->styleSheet(), keyframes_rule);
    } else {
      result = FindKeyframesRule(css_rule->cssRules(), keyframes_rule);
    }
  }
  return result;
}

String CreateShorthandValue(blink::Document* document,
                            const String& shorthand,
                            const String& old_text,
                            const String& longhand,
                            const String& new_value) {
  blink::StyleSheetContents* style_sheet_contents = blink::StyleSheetContents::Create(
      StrictCSSParserContext(document->GetSecureContextMode()));
  String text = " div { " + shorthand + ": " + old_text + "; }";
  blink::CSSParser::ParseSheet(blink::CSSParserContext::Create(*document),
                               style_sheet_contents, text);

  blink::CSSStyleSheet* style_sheet = blink::CSSStyleSheet::Create(style_sheet_contents);
  blink::CSSStyleRule* rule = ToCSSStyleRule(style_sheet->item(0));
  blink::CSSStyleDeclaration* style = rule->style();
  blink::DummyExceptionStateForTesting exception_state;
  style->setProperty(document, longhand, new_value,
                     style->getPropertyPriority(longhand), exception_state);
  return style->getPropertyValue(shorthand);
}

blink::HeapVector<blink::Member<blink::CSSStyleRule>> FilterDuplicateRules(blink::CSSRuleList* rule_list) {
  blink::HeapVector<blink::Member<blink::CSSStyleRule>> uniq_rules;
  blink::HeapHashSet<blink::Member<blink::CSSRule>> uniq_rules_set;
  for (unsigned i = rule_list ? rule_list->length() : 0; i > 0; --i) {
    blink::CSSRule* rule = rule_list->item(i - 1);
    if (!rule || rule->type() != blink::CSSRule::kStyleRule ||
        uniq_rules_set.Contains(rule))
      continue;
    uniq_rules_set.insert(rule);
    uniq_rules.push_back(ToCSSStyleRule(rule));
  }
  uniq_rules.Reverse();
  return uniq_rules;
}

void CollectPlatformFontsFromRunFontDataList(
    const Vector<blink::ShapeResult::RunFontData>& run_font_data_list,
    HashCountedSet<std::pair<int, String>>* font_stats) {
  for (const auto& run_font_data : run_font_data_list) {
    const auto* simple_font_data = run_font_data.font_data_;
    String family_name = simple_font_data->PlatformData().FontFamilyName();
    if (family_name.IsNull())
      family_name = "";
    font_stats->insert(
        std::make_pair(simple_font_data->IsCustomFont() ? 1 : 0, family_name),
        run_font_data.glyph_count_);
  }
}

bool JsonRangeToSourceRange(
  InspectorStyleSheetBase* inspector_style_sheet,
  automation::SourceRange* range,
  blink::SourceRange* source_range) {

  if (range->start_line < 0) {
    //DLOG(ERROR) << "range.startLine must be a non-negative integer";
    return false;
  }

  if (range->start_column < 0) {
    //DLOG(ERROR) << "range.startColumn must be a non-negative integer";
    return false;
  }

  if (range->end_line < 0) {
    //DLOG(ERROR) << "range.endLine must be a non-negative integer";
    return false;
  }

  if (range->end_column < 0) {
    //DLOG(ERROR) << "range.endColumn must be a non-negative integer";
    return false;
  }

  unsigned start_offset = 0;
  unsigned end_offset = 0;
  bool success =
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->start_line, range->start_column, &start_offset) &&
      inspector_style_sheet->LineNumberAndColumnToOffset(
          range->end_line, range->end_column, &end_offset);
  if (!success) {
    //DLOG(ERROR) << "Specified range is out of bounds";
    return false;
  }

  if (start_offset > end_offset) {
    //DLOG(ERROR) << "Range start must not succeed its end";
    return false;
  }
  source_range->start = start_offset;
  source_range->end = end_offset;
  return true;
}

enum ForcePseudoClassFlags {
  kPseudoNone = 0,
  kPseudoHover = 1 << 0,
  kPseudoFocus = 1 << 1,
  kPseudoActive = 1 << 2,
  kPseudoVisited = 1 << 3,
  kPseudoFocusWithin = 1 << 4,
  kPseudoFocusVisible = 1 << 5
};

unsigned ComputePseudoClassMask(const std::vector<std::string>& pseudo_class_array) {
  DEFINE_STATIC_LOCAL(String, active, ("active"));
  DEFINE_STATIC_LOCAL(String, hover, ("hover"));
  DEFINE_STATIC_LOCAL(String, focus, ("focus"));
  DEFINE_STATIC_LOCAL(String, focusVisible, ("focus-visible"));
  DEFINE_STATIC_LOCAL(String, focusWithin, ("focus-within"));
  DEFINE_STATIC_LOCAL(String, visited, ("visited"));
  if (!pseudo_class_array.size())
    return kPseudoNone;

  unsigned result = kPseudoNone;
  for (size_t i = 0; i < pseudo_class_array.size(); ++i) {
    String pseudo_class = String::FromUTF8(pseudo_class_array[i].data());
    if (pseudo_class == active)
      result |= kPseudoActive;
    else if (pseudo_class == hover)
      result |= kPseudoHover;
    else if (pseudo_class == focus)
      result |= kPseudoFocus;
    else if (pseudo_class == focusVisible)
      result |= kPseudoFocusVisible;
    else if (pseudo_class == focusWithin)
      result |= kPseudoFocusWithin;
    else if (pseudo_class == visited)
      result |= kPseudoVisited;
  }

  return result;
}

// Get the elements which overlap the given rectangle.
blink::HeapVector<blink::Member<blink::Element>> ElementsFromRect(blink::LayoutRect rect,
                                                           blink::Document& document) {
  blink::HitTestRequest request(blink::HitTestRequest::kReadOnly | 
                                blink::HitTestRequest::kActive |
                                blink::HitTestRequest::kListBased |
                                blink::HitTestRequest::kPenetratingList |
                                blink::HitTestRequest::kIgnoreClipping);

  blink::LayoutPoint center = rect.Center();
  blink::LayoutUnit horizontal_padding = rect.Width() / 2;
  blink::LayoutUnit vertical_padding = rect.Height() / 2;
  blink::LayoutRectOutsets padding(vertical_padding, horizontal_padding,
                            vertical_padding, horizontal_padding);
  blink::HitTestResult result(request, center, padding);
  document.GetFrame()->ContentLayoutObject()->HitTest(result);
  blink::HeapVector<blink::Member<blink::Element>> elements;
  blink::Node* previous_node = nullptr;
  for (const auto& hit_test_result_node : result.ListBasedTestResult()) {
    blink::Node* node = hit_test_result_node.Get();
    if (!node || node->IsDocumentNode())
      continue;
    if (node->IsPseudoElement() || node->IsTextNode())
      node = node->ParentOrShadowHostNode();
    if (!node || node == previous_node || !node->IsElementNode())
      continue;
    elements.push_back(ToElement(node));
    previous_node = node;
  }
  return elements;
}

// Blends the colors from the given gradient with the existing colors.
void BlendWithColorsFromGradient(blink::cssvalue::CSSGradientValue* gradient,
                                 Vector<blink::Color>& colors,
                                 bool& found_non_transparent_color,
                                 bool& found_opaque_color,
                                 const blink::LayoutObject& layout_object) {
  const blink::Document& document = layout_object.GetDocument();
  const blink::ComputedStyle& style = layout_object.StyleRef();

  Vector<blink::Color> stop_colors = gradient->GetStopColors(document, style);
  if (colors.IsEmpty()) {
    colors.AppendRange(stop_colors.begin(), stop_colors.end());
  } else {
    if (colors.size() > 1) {
      // Gradient on gradient is too complicated, bail out.
      colors.clear();
      return;
    }

    blink::Color existing_color = colors.front();
    colors.clear();
    for (auto stop_color : stop_colors) {
      found_non_transparent_color =
          found_non_transparent_color || (stop_color.Alpha() != 0);
      colors.push_back(existing_color.Blend(stop_color));
    }
  }
  found_opaque_color =
      found_opaque_color || gradient->KnownToBeOpaque(document, style);
}

// Gets the colors from an image style, if one exists and it is a gradient.
void AddColorsFromImageStyle(const blink::ComputedStyle& style,
                             Vector<blink::Color>& colors,
                             bool& found_opaque_color,
                             bool& found_non_transparent_color,
                             const blink::LayoutObject& layout_object) {
  const blink::FillLayer& background_layers = style.BackgroundLayers();
  if (!background_layers.HasImage())
    return;

  blink::StyleImage* style_image = background_layers.GetImage();
  // hasImage() does not always indicate that this is non-null
  if (!style_image)
    return;

  if (!style_image->IsGeneratedImage()) {
    // Make no assertions about the colors in non-generated images
    colors.clear();
    found_opaque_color = false;
    return;
  }

  blink::StyleGeneratedImage* gen_image = ToStyleGeneratedImage(style_image);
  blink::CSSValue* image_css = gen_image->CssValue();
  if (image_css->IsGradientValue()) {
    blink::cssvalue::CSSGradientValue* gradient =
        blink::cssvalue::ToCSSGradientValue(image_css);
    BlendWithColorsFromGradient(gradient, colors, found_non_transparent_color,
                                found_opaque_color, layout_object);
  }
  return;
}

// Get the background colors behind the given rect in the given document, by
// walking up all the elements returned by a hit test (but not going beyond
// |topElement|) covering the area of the rect, and blending their background
// colors.
bool GetColorsFromRect(blink::LayoutRect rect,
                       blink::Document& document,
                       blink::Element* top_element,
                       Vector<blink::Color>& colors) {
  blink::HeapVector<blink::Member<blink::Element>> elements_under_rect = ElementsFromRect(rect, document);

  bool found_opaque_color = false;
  bool found_top_element = false;

  for (auto e = elements_under_rect.rbegin();
       !found_top_element && e != elements_under_rect.rend(); ++e) {
    const blink::Element* element = *e;
    if (element == top_element)
      found_top_element = true;

    const blink::LayoutObject* layout_object = element->GetLayoutObject();
    if (!layout_object)
      continue;

    if (blink::IsHTMLCanvasElement(element) || blink::IsHTMLEmbedElement(element) ||
        blink::IsHTMLImageElement(element) || blink::IsHTMLObjectElement(element) ||
        blink::IsHTMLPictureElement(element) || element->IsSVGElement() ||
        blink::IsHTMLVideoElement(element)) {
      colors.clear();
      found_opaque_color = false;
      continue;
    }

    const blink::ComputedStyle* style = layout_object->Style();
    if (!style)
      continue;

    blink::Color background_color =
        style->VisitedDependentColor(blink::GetCSSPropertyBackgroundColor());
    bool found_non_transparent_color = false;
    if (background_color.Alpha() != 0) {
      found_non_transparent_color = true;
      if (colors.IsEmpty()) {
        if (!background_color.HasAlpha())
          found_opaque_color = true;
        colors.push_back(background_color);
      } else {
        if (!background_color.HasAlpha()) {
          colors.clear();
          colors.push_back(background_color);
          found_opaque_color = true;
        } else {
          for (size_t i = 0; i < colors.size(); i++)
            colors[i] = colors[i].Blend(background_color);
          found_opaque_color =
              found_opaque_color || background_color.HasAlpha();
        }
      }
    }

    AddColorsFromImageStyle(*style, colors, found_opaque_color,
                            found_non_transparent_color, *layout_object);

    bool contains = found_top_element || element->BoundingBox().Contains(rect);
    if (!contains && found_non_transparent_color) {
      // Only return colors if some opaque element covers up this one.
      colors.clear();
      found_opaque_color = false;
    }
  }
  return found_opaque_color;
}

}

class InspectorCSSAgentImpl : public blink::InspectorCSSAgent {
public: 
  InspectorCSSAgentImpl(CSSDispatcher* dispatcher, AutomationContext* context): 
    InspectorCSSAgent(
      context->dom_dispatcher()->dom_agent(), // InspectorDOMAgent
      dispatcher->page_instance_->inspected_frames(),
      nullptr,
      dispatcher->page_instance_->inspector_resource_content_loader(), // InspectorResourceContentLoader*,
      dispatcher->page_instance_->inspector_resource_container()),// InspectorResourceContainer*),
    dispatcher_(dispatcher) {}
  
  void ForcePseudoState(blink::Element* element, blink::CSSSelector::PseudoType pseudo_type, bool* result) override {
    dispatcher_->ForcePseudoState(element, pseudo_type, result);
  }
  
  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame) override {
    dispatcher_->DidCommitLoadForLocalFrame(frame);
  }
  
  void MediaQueryResultChanged() override {
    dispatcher_->MediaQueryResultChanged();
  }
  
  void ActiveStyleSheetsUpdated(blink::Document* document) override {
    dispatcher_->ActiveStyleSheetsUpdated(document);
  }
  
  void DocumentDetached(blink::Document* document) override {
    dispatcher_->DocumentDetached(document);
  }
  
  void FontsUpdated(const blink::FontFace* font_face,
                    const String& src,
                    const blink::FontCustomPlatformData* font_custom) override {
    dispatcher_->FontsUpdated(font_face, src, font_custom);
  }
  
  void SetCoverageEnabled(bool enabled) override {
    dispatcher_->SetCoverageEnabled(enabled);
  }

  void WillChangeStyleElement(blink::Element* element) override {
    dispatcher_->WillChangeStyleElement(element);
  }

private:
  CSSDispatcher* dispatcher_;
};

// static
void CSSDispatcher::CollectAllDocumentStyleSheets(
  blink::Document* document,
  blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& result) {
  for (const auto& style :
       document->GetStyleEngine().ActiveStyleSheetsForInspector())
    CSSDispatcher::CollectStyleSheets(style.first, result);
}

// static
void CSSDispatcher::CollectStyleSheets(
  blink::CSSStyleSheet* style_sheet,
  blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& result) {
  result.push_back(style_sheet);
  for (unsigned i = 0, size = style_sheet->length(); i < size; ++i) {
    blink::CSSRule* rule = style_sheet->item(i);
    if (rule->type() == blink::CSSRule::kImportRule) {
      blink::CSSStyleSheet* imported_style_sheet = ToCSSImportRule(rule)->styleSheet();
      if (imported_style_sheet)
        CSSDispatcher::CollectStyleSheets(imported_style_sheet, result);
    }
  }
}

CSSDispatcher* CSSDispatcher::Create(automation::CSSRequest request, AutomationContext* context, PageInstance* page_instance) {
  return new CSSDispatcher(std::move(request), context, page_instance);
}

CSSDispatcher::CSSDispatcher(
  automation::CSSRequest request,
  AutomationContext* context, 
  PageInstance* page_instance): 
  context_(context),
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false),
  rule_recording_enabled_(false) {
  
}

CSSDispatcher::CSSDispatcher(
  AutomationContext* context, 
  PageInstance* page_instance): 
  context_(context),
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false),
  rule_recording_enabled_(false) {
  
}

CSSDispatcher::~CSSDispatcher() {

}

void CSSDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&css_client_ptr_);
}

void CSSDispatcher::Bind(automation::CSSAssociatedRequest request) {
  //DLOG(INFO) << "CSSDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

automation::CSSClient* CSSDispatcher::GetClient() const {
  return css_client_ptr_.get();
}

blink::InspectorCSSAgent* CSSDispatcher::css_agent() const {
  return css_agent_impl_.Get();
}

void CSSDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void CSSDispatcher::Disable() {
  page_instance_->probe_sink()->removeInspectorCSSAgent(css_agent_impl_.Get());
  enabled_ = false;
}

void CSSDispatcher::Enable() {
  //DLOG(INFO) << "CSSDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  if (!dom_dispatcher_->enabled()) {
    //DLOG(ERROR) << "DOM agent needs to be enabled first.";
    return;
  }
  resource_content_loader_->EnsureResourcesContentLoaded(
    page_instance_->inspector_resource_content_loader_id(),
      WTF::Bind(&CSSDispatcher::ResourceContentLoaded, WTF::Unretained(this)));
}

void CSSDispatcher::ResourceContentLoaded() {
  WasEnabled();
}

void CSSDispatcher::WasEnabled() {
  page_instance_->probe_sink()->addInspectorCSSAgent(css_agent_impl_.Get());
  dom_dispatcher_->SetDOMListener(this);
  blink::HeapVector<blink::Member<blink::Document>> documents = dom_dispatcher_->Documents();
  for (blink::Document* document : documents)
    UpdateActiveStyleSheets(document);
  enabled_ = true;
}

void CSSDispatcher::FlushPendingProtocolNotifications() {
  if (!invalidated_documents_.size())
    return;
  blink::HeapHashSet<blink::Member<blink::Document>> invalidated_documents;
  invalidated_documents_.swap(invalidated_documents);
  for (blink::Document* document : invalidated_documents)
    UpdateActiveStyleSheets(document);
}

void CSSDispatcher::Reset() {
  id_to_inspector_style_sheet_.clear();
  id_to_inspector_style_sheet_for_inline_style_.clear();
  css_style_sheet_to_inspector_style_sheet_.clear();
  document_to_css_style_sheets_.clear();
  invalidated_documents_.clear();
  node_to_inspector_style_sheet_.clear();
}

void CSSDispatcher::AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, AddRuleCallback callback) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  bool ok = AssertInspectorStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!ok) {
    std::move(callback).Run(nullptr);  
    return;
  }
  blink::SourceRange rule_location;
  bool conversion = JsonRangeToSourceRange(inspector_style_sheet, location.get(), &rule_location);
  if (!conversion) {
    std::move(callback).Run(nullptr);
    return;
  }
  
  blink::DummyExceptionStateForTesting exception_state;
  blink::SourceRange added_range;
  blink::CSSStyleRule* rule = inspector_style_sheet->AddRule(
    String::FromUTF8(rule_text.data()), rule_location, &added_range, exception_state);
  if (!exception_state.HadException()) {
    std::move(callback).Run(nullptr);
    return;
  }
  std::move(callback).Run(BuildObjectForRule(rule));
}

void CSSDispatcher::CollectClassNames(const std::string& style_sheet_id, CollectClassNamesCallback callback) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  bool ok = AssertInspectorStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!ok) {
    std::move(callback).Run(std::vector<std::string>());  
    return;
  }
  std::move(callback).Run(inspector_style_sheet->CollectClassNames());
}

void CSSDispatcher::CreateStyleSheet(const std::string& frame_id, CreateStyleSheetCallback callback) {
  blink::LocalFrame* frame = 
    blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  
  if (!frame) {
    //DLOG(ERROR) << "Frame not found";
    std::move(callback).Run(std::string());
    return;
  }

  blink::Document* document = frame->GetDocument();
  if (!document) {
    //DLOG(ERROR) << "Frame does not have a document";
    std::move(callback).Run(std::string());
    return;
  }

  InspectorStyleSheet* inspector_style_sheet = ViaInspectorStyleSheet(document);
  if (!inspector_style_sheet) {
    //DLOG(ERROR) << "No target stylesheet found";
    std::move(callback).Run(std::string());
    return;
  }

  UpdateActiveStyleSheets(document);

  std::move(callback).Run(std::string(inspector_style_sheet->Id().Utf8().data(), inspector_style_sheet->Id().length()));
}

void CSSDispatcher::ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) {
  
  if (!enabled_)
    return;

  blink::Element* element = nullptr;
  bool exists = dom_dispatcher_->AssertElement(node_id, element);
  if (!exists) {
    return;
  }

  unsigned forced_pseudo_state = ComputePseudoClassMask(forced_pseudo_classes);
  NodeIdToForcedPseudoState::iterator it =
      node_id_to_forced_pseudo_state_.find(node_id);
  unsigned current_forced_pseudo_state =
      it == node_id_to_forced_pseudo_state_.end() ? 0 : it->value;
  bool need_style_recalc = forced_pseudo_state != current_forced_pseudo_state;
  if (!need_style_recalc) {
    return;
  }

  if (forced_pseudo_state)
    node_id_to_forced_pseudo_state_.Set(node_id, forced_pseudo_state);
  else
    node_id_to_forced_pseudo_state_.erase(node_id);

  element->ownerDocument()->SetNeedsStyleRecalc(
      blink::kSubtreeStyleChange,
      blink::StyleChangeReasonForTracing::Create("Inspector"));
}

void CSSDispatcher::GetBackgroundColors(int32_t node_id, GetBackgroundColorsCallback callback) {
  std::vector<std::string> background_colors;
  std::string computed_font_size;
  std::string computed_font_weight;
  std::string computed_body_font_size;

  blink::Element* element = nullptr;
  bool element_ok = dom_dispatcher_->AssertElement(node_id, element);
  if (!element_ok) {
    //DLOG(ERROR) << "No element with id " << node_id;
    std::move(callback).Run(std::vector<std::string>(), nullptr, nullptr, nullptr);
    return;
  }

  blink::LayoutRect content_bounds;
  blink::LayoutObject* element_layout = element->GetLayoutObject();
  if (!element_layout) {
    //DLOG(ERROR) << "No layout object for element " << node_id;
    std::move(callback).Run(std::vector<std::string>(), nullptr, nullptr, nullptr);
    return;
  }

  for (const blink::Node* child = element->firstChild(); child; child = child->nextSibling()) {
    if (!child->IsTextNode())
      continue;
    content_bounds.Unite(blink::LayoutRect(child->BoundingBox()));
  }
  if (content_bounds.Size().IsEmpty() && element_layout->IsBox()) {
    // Return content box instead - may have indirect text children.
    blink::LayoutBox* layout_box = ToLayoutBox(element_layout);
    content_bounds = layout_box->ContentBoxRect();
    content_bounds = blink::LayoutRect(
        element_layout->LocalToAbsoluteQuad(blink::FloatRect(content_bounds))
            .BoundingBox());
  }

  if (content_bounds.Size().IsEmpty()) {
    std::move(callback).Run(std::vector<std::string>(), nullptr, nullptr, nullptr);
    return;
  }

  Vector<blink::Color> colors;
  blink::LocalFrameView* view = element->GetDocument().View();
  if (!view) {
    //DLOG(ERROR) << "No view.";
    std::move(callback).Run(std::vector<std::string>(), nullptr, nullptr, nullptr);
    return;
  }
  blink::Document& document = element->GetDocument();
  bool is_main_frame = document.IsInMainFrame();
  bool found_opaque_color = false;
  if (is_main_frame) {
    // Start with the "default" page color (typically white).
    blink::Color base_background_color = view->BaseBackgroundColor();
    colors.push_back(view->BaseBackgroundColor());
    found_opaque_color = !base_background_color.HasAlpha();
  }

  found_opaque_color = GetColorsFromRect(content_bounds, element->GetDocument(),
                                         element, colors);

  if (!found_opaque_color && !is_main_frame) {
    for (blink::HTMLFrameOwnerElement* owner_element = document.LocalOwner();
         !found_opaque_color && owner_element;
         owner_element = owner_element->GetDocument().LocalOwner()) {
      found_opaque_color = GetColorsFromRect(
          content_bounds, owner_element->GetDocument(), nullptr, colors);
    }
  }

  for (auto color : colors) {
    background_colors.push_back(std::string(color.SerializedAsCSSComponentValue().Utf8().data(), color.SerializedAsCSSComponentValue().length()));
  }

  blink::CSSComputedStyleDeclaration* computed_style_info =
      blink::CSSComputedStyleDeclaration::Create(element, true);
  const blink::CSSValue* font_size =
      computed_style_info->GetPropertyCSSValue(blink::GetCSSPropertyFontSize());
  String font_size_str = font_size->CssText();
  computed_font_size = std::string(font_size_str.Utf8().data(), font_size_str.length());
  const blink::CSSValue* font_weight =
      computed_style_info->GetPropertyCSSValue(blink::GetCSSPropertyFontWeight());
  String font_weight_str = font_weight->CssText();
  computed_font_weight = std::string(font_weight_str.Utf8().data(), font_weight_str.length());

  blink::HTMLElement* body = element->GetDocument().body();
  blink::CSSComputedStyleDeclaration* computed_style_body =
      blink::CSSComputedStyleDeclaration::Create(body, true);
  const blink::CSSValue* body_font_size =
      computed_style_body->GetPropertyCSSValue(blink::GetCSSPropertyFontSize());
  if (body_font_size) {
    String body_font_size_str = body_font_size->CssText();
    computed_body_font_size = std::string(body_font_size_str.Utf8().data(), body_font_size_str.length());
  } else {
    // This is an extremely rare and pathological case -
    // just return the baseline default to avoid a crash.
    // crbug.com/738777
    unsigned default_font_size_keyword = blink::FontSizeFunctions::InitialKeywordSize();
    float default_font_size_pixels = blink::FontSizeFunctions::FontSizeForKeyword(
        &document, default_font_size_keyword, false);
    
    String body_font_size_str = blink::CSSPrimitiveValue::Create(default_font_size_pixels,
                                blink::CSSPrimitiveValue::UnitType::kPixels)->CssText();
    computed_body_font_size = std::string(body_font_size_str.Utf8().data(), body_font_size_str.length());
  }
  std::move(callback).Run(
    std::move(background_colors), 
    std::move(computed_font_size), 
    std::move(computed_font_weight), 
    std::move(computed_body_font_size));
}

void CSSDispatcher::GetComputedStyleForNode(int32_t node_id, GetComputedStyleForNodeCallback callback) {
  if (!enabled_) {
    std::move(callback).Run(std::vector<automation::CSSComputedStylePropertyPtr>());
    return;
  }
  blink::Node* node = nullptr;
  bool have_node = dom_dispatcher_->AssertNode(node_id, node);
  if (!have_node) {
    std::move(callback).Run(std::vector<automation::CSSComputedStylePropertyPtr>());
    return;
  }

  blink::CSSComputedStyleDeclaration* computed_style_info =
      blink::CSSComputedStyleDeclaration::Create(node, true);
  std::vector<automation::CSSComputedStylePropertyPtr> style;
  for (int id = blink::firstCSSProperty; id <= blink::lastCSSProperty; ++id) {
    blink::CSSPropertyID property_id = static_cast<blink::CSSPropertyID>(id);
    const blink::CSSProperty& property_class =
        blink::CSSProperty::Get(resolveCSSPropertyID(property_id));
    if (!property_class.IsEnabled() || property_class.IsShorthand() ||
        !property_class.IsProperty())
      continue;

    automation::CSSComputedStylePropertyPtr property = automation::CSSComputedStyleProperty::New();  
    String computed_style_str = computed_style_info->GetPropertyValue(property_id);
    property->name = std::string(property_class.GetPropertyNameString().Utf8().data(), property_class.GetPropertyNameString().Utf8().length());
    property->value = std::string(computed_style_str.Utf8().data(), computed_style_str.Utf8().length());
    style.push_back(std::move(property));
  }

  std::unique_ptr<HashMap<AtomicString, scoped_refptr<blink::CSSVariableData>>>
      variables = computed_style_info->GetVariables();

  if (variables && !variables->IsEmpty()) {
    for (const auto& it : *variables) {
      if (!it.value)
        continue;
      
      String value_str = it.value->TokenRange().Serialize();
      automation::CSSComputedStylePropertyPtr property = automation::CSSComputedStyleProperty::New();
      property->name = std::string(it.key.Utf8().data(), it.key.Utf8().length());
      property->value = std::string(value_str.Utf8().data(), value_str.Utf8().length());
      style.push_back(std::move(property));
    }
  }
  std::move(callback).Run(std::move(style));
}

void CSSDispatcher::GetInlineStylesForNode(int32_t node_id, GetInlineStylesForNodeCallback callback) {
  if (!enabled_) {
    std::move(callback).Run(nullptr,
                            nullptr);
    return;
  }
  blink::Element* element = nullptr;
  bool element_exists = dom_dispatcher_->AssertElement(node_id, element);
  if (!element_exists) {
    //DLOG(ERROR) << "Element " << node_id << " does not exist";
    std::move(callback).Run(nullptr,
                            nullptr);
    return;
  }

  InspectorStyleSheetForInlineStyle* style_sheet =
      AsInspectorStyleSheet(element);
  if (!style_sheet) {
    //DLOG(ERROR) << "Element " << node_id << " is not a style sheet";
    std::move(callback).Run(nullptr,
                            nullptr);
    return;
  }

  std::move(callback).Run(style_sheet->BuildObjectForStyle(element->style()),
                          BuildObjectForAttributesStyle(element));
}

void CSSDispatcher::GetMatchedStylesForNode(int32_t node_id, GetMatchedStylesForNodeCallback callback) {
  automation::CSSStylePtr inline_style;
  automation::CSSStylePtr attributes_style;
  std::vector<automation::RuleMatchPtr> matched_css_rules;
  std::vector<automation::PseudoElementMatchesPtr> pseudo_id_matches;
  std::vector<automation::InheritedStyleEntryPtr> inherited_entries;
  std::vector<automation::CSSKeyframesRulePtr> css_keyframes_rules;

  if (!enabled_) {
    //DLOG(ERROR) << "CSS dispatcher is not enabled";
    std::move(callback).Run(
      nullptr,
      nullptr,
      base::Optional<std::vector<automation::RuleMatchPtr>>(),
      base::Optional<std::vector<automation::PseudoElementMatchesPtr>>(),
      base::Optional<std::vector<automation::InheritedStyleEntryPtr>>(),
      base::Optional<std::vector<automation::CSSKeyframesRulePtr>>());
    return;
  }

  blink::Element* element = nullptr;
  bool element_ok = dom_dispatcher_->AssertElement(node_id, element);
  if (!element_ok) {
    //DLOG(ERROR) << "CSS dispatcher: node with id " << node_id << " not found";
    std::move(callback).Run(
      nullptr,
      nullptr,
      base::Optional<std::vector<automation::RuleMatchPtr>>(),
      base::Optional<std::vector<automation::PseudoElementMatchesPtr>>(),
      base::Optional<std::vector<automation::InheritedStyleEntryPtr>>(),
      base::Optional<std::vector<automation::CSSKeyframesRulePtr>>());
    return;
  }

  blink::Element* original_element = element;
  blink::PseudoId element_pseudo_id = element->GetPseudoId();
  if (element_pseudo_id) {
    element = element->ParentOrShadowHostElement();
    if (!element) {
      //DLOG(ERROR) << "Pseudo element has no parent";
      std::move(callback).Run(
        nullptr,
        nullptr,
        base::Optional<std::vector<automation::RuleMatchPtr>>(),
        base::Optional<std::vector<automation::PseudoElementMatchesPtr>>(),
        base::Optional<std::vector<automation::InheritedStyleEntryPtr>>(),
        base::Optional<std::vector<automation::CSSKeyframesRulePtr>>());
      return;
    }
  }

  blink::Document* owner_document = element->ownerDocument();
  // A non-active document has no styles.
  if (!owner_document->IsActive()) {
    //DLOG(ERROR) << "Document is not active";
    std::move(callback).Run(
      nullptr,
      nullptr,
      base::Optional<std::vector<automation::RuleMatchPtr>>(),
      base::Optional<std::vector<automation::PseudoElementMatchesPtr>>(),
      base::Optional<std::vector<automation::InheritedStyleEntryPtr>>(),
      base::Optional<std::vector<automation::CSSKeyframesRulePtr>>());
    return;
  }

  // FIXME: It's really gross for the inspector to reach in and access
  // StyleResolver directly here. We need to provide the Inspector better APIs
  // to get this information without grabbing at internal style classes!

  // Matched rules.
  blink::StyleResolver& style_resolver = owner_document->EnsureStyleResolver();

  element->UpdateDistributionForUnknownReasons();
  blink::CSSRuleList* matched_rules = style_resolver.PseudoCSSRulesForElement(
      element, element_pseudo_id, blink::StyleResolver::kAllCSSRules);
  matched_css_rules = BuildArrayForMatchedRuleList(
      matched_rules, original_element, blink::kPseudoIdNone);

  // Pseudo elements.
  if (element_pseudo_id) {
    std::move(callback).Run(
      nullptr,
      nullptr,
      std::move(matched_css_rules), 
      base::Optional<std::vector<automation::PseudoElementMatchesPtr>>(),
      base::Optional<std::vector<automation::InheritedStyleEntryPtr>>(),
      base::Optional<std::vector<automation::CSSKeyframesRulePtr>>());
    return; //Response::OK();
  }

  InspectorStyleSheetForInlineStyle* inline_style_sheet =
      AsInspectorStyleSheet(element);
  if (inline_style_sheet) {
    inline_style = inline_style_sheet->BuildObjectForStyle(element->style());
    attributes_style = BuildObjectForAttributesStyle(element);
  }

  for (blink::PseudoId pseudo_id = blink::kFirstPublicPseudoId;
       pseudo_id < blink::kAfterLastInternalPseudoId;
       pseudo_id = static_cast<blink::PseudoId>(pseudo_id + 1)) {
    blink::CSSRuleList* matched_rules = style_resolver.PseudoCSSRulesForElement(
        element, pseudo_id, blink::StyleResolver::kAllCSSRules);
    automation::PseudoType pseudo_type;
    if (matched_rules && matched_rules->length() &&
        dom_dispatcher_->GetPseudoElementType(pseudo_id, &pseudo_type)) {
      automation::PseudoElementMatchesPtr pseudo_element = automation::PseudoElementMatches::New();
      pseudo_element->pseudo_type = pseudo_type;
      pseudo_element->matches = BuildArrayForMatchedRuleList(matched_rules, element, pseudo_id);
      pseudo_id_matches.push_back(std::move(pseudo_element));
    }
  }

  // Inherited styles.
  blink::Element* parent_element = element->ParentOrShadowHostElement();
  while (parent_element) {
    blink::StyleResolver& parent_style_resolver =
        parent_element->ownerDocument()->EnsureStyleResolver();
    blink::CSSRuleList* parent_matched_rules =
        parent_style_resolver.CssRulesForElement(parent_element,
                                                 blink::StyleResolver::kAllCSSRules);
    automation::InheritedStyleEntryPtr entry = automation::InheritedStyleEntry::New();
    entry->matched_css_rules = 
      BuildArrayForMatchedRuleList(parent_matched_rules, parent_element, blink::kPseudoIdNone);
    if (parent_element->style() && parent_element->style()->length()) {
      InspectorStyleSheetForInlineStyle* style_sheet =
          AsInspectorStyleSheet(parent_element);
      if (style_sheet)
        entry->inline_style = 
            style_sheet->BuildObjectForStyle(style_sheet->InlineStyle());
    }

    inherited_entries.push_back(std::move(entry));
    parent_element = parent_element->ParentOrShadowHostElement();
  }

  css_keyframes_rules = AnimationsForNode(element);
  // OK
  std::move(callback).Run(
    std::move(inline_style), 
    std::move(attributes_style), 
    std::move(matched_css_rules),
    std::move(pseudo_id_matches), 
    std::move(inherited_entries), 
    std::move(css_keyframes_rules));
}

void CSSDispatcher::GetMediaQueries(GetMediaQueriesCallback callback) {
  std::vector<automation::CSSMediaPtr> medias;
  for (auto& style : id_to_inspector_style_sheet_) {
    InspectorStyleSheet* style_sheet = style.value;
    CollectMediaQueriesFromStyleSheet(style_sheet->PageStyleSheet(),
                                      &medias);
    const blink::CSSRuleVector& flat_rules = style_sheet->FlatRules();
    for (unsigned i = 0; i < flat_rules.size(); ++i) {
      blink::CSSRule* rule = flat_rules.at(i).Get();
      if (rule->type() == blink::CSSRule::kMediaRule ||
          rule->type() == blink::CSSRule::kImportRule)
        CollectMediaQueriesFromRule(rule, &medias);
    }
  }
  std::move(callback).Run(std::move(medias));
}

void CSSDispatcher::GetPlatformFontsForNode(int32_t node_id, GetPlatformFontsForNodeCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "CSS dispatcher is not enabled";
    std::move(callback).Run(std::vector<automation::PlatformFontUsagePtr>());
    return;
  }
  std::vector<automation::PlatformFontUsagePtr> result;
  blink::Node* node = nullptr;
  if (!dom_dispatcher_->AssertNode(node_id, node)) {
    //DLOG(ERROR) << "CSS dispatcher: node with id " << node_id << " not found";
    std::move(callback).Run(std::vector<automation::PlatformFontUsagePtr>());
    return;
  }

  HashCountedSet<std::pair<int, String>> font_stats;
  blink::LayoutObject* root = node->GetLayoutObject();
  if (root) {
    CollectPlatformFontsForLayoutObject(root, &font_stats);
    // Iterate upto two layers deep.
    for (blink::LayoutObject* child = root->SlowFirstChild(); child;
         child = child->NextSibling()) {
      CollectPlatformFontsForLayoutObject(child, &font_stats);
      for (blink::LayoutObject* child2 = child->SlowFirstChild(); child2;
           child2 = child2->NextSibling())
        CollectPlatformFontsForLayoutObject(child2, &font_stats);
    }
  }
  std::vector<automation::PlatformFontUsagePtr> platform_fonts;
  for (auto& font : font_stats) {
    std::pair<int, String>& font_description = font.key;
    bool is_custom_font = font_description.first == 1;
    String font_name = font_description.second;
    automation::PlatformFontUsagePtr font_usage = automation::PlatformFontUsage::New();
    font_usage->family_name = std::string(font_name.Utf8().data(), font_name.Utf8().length());
    font_usage->is_custom_font = is_custom_font;
    font_usage->glyph_count = font.value;
                      
    platform_fonts.push_back(std::move(font_usage));
  }
  std::move(callback).Run(std::move(platform_fonts));
}

void CSSDispatcher::GetStyleSheetText(const std::string& style_sheet_id, GetStyleSheetTextCallback callback) {
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  String result;
  bool ok = AssertStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!ok) {
    std::move(callback).Run(std::string());
    return;
  }
  inspector_style_sheet->GetText(&result);
  std::move(callback).Run(std::string(result.Utf8().data(), result.Utf8().length()));
}

blink::CSSStyleDeclaration* CSSDispatcher::FindEffectiveDeclaration(
  const blink::CSSProperty& property_class,
  const blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>>& styles) {
  if (!styles.size())
    return nullptr;

  String longhand = property_class.GetPropertyNameString();
  blink::CSSStyleDeclaration* found_style = nullptr;

  for (unsigned i = 0; i < styles.size(); ++i) {
    blink::CSSStyleDeclaration* style = styles.at(i).Get();
    if (style->getPropertyValue(longhand).IsEmpty())
      continue;
    if (style->getPropertyPriority(longhand) == "important")
      return style;
    if (!found_style)
      found_style = style;
  }

  return found_style ? found_style : styles.at(0).Get();
}

void CSSDispatcher::SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) {
  blink::Element* element = nullptr;
  String property_name_str = String::FromUTF8(property_name.data());
  String value_str = String::FromUTF8(value.data());
  bool element_exists = dom_dispatcher_->AssertElement(node_id, element);
  if (!element_exists) {
    //DLOG(ERROR) << "Element with id " << node_id << " does not exists";
    return;
  }
  if (element->GetPseudoId()) {
    //DLOG(ERROR) << "Elements is pseudo";
    return;
  }

  blink::CSSPropertyID property = blink::cssPropertyID(property_name_str);
  if (!property) {
    //DLOG(ERROR) << "Invalid property name";
    return;
  }

  blink::Document* owner_document = element->ownerDocument();
  if (!owner_document->IsActive()) {
    //DLOG(ERROR) << "Can't edit a node from a non-active document";
    return;
  }

  blink::CSSPropertyID property_id = blink::cssPropertyID(property_name_str);
  const blink::CSSProperty& property_class = blink::CSSProperty::Get(property_id);
  blink::CSSStyleDeclaration* style = FindEffectiveDeclaration(property_class, MatchingStyles(element));
  if (!style) {
    //DLOG(ERROR) << "Can't find a style to edit";
    return;
  }

  bool force_important = false;
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  blink::CSSRuleSourceData* source_data;
  // An absence of the parent rule means that given style is an inline style.
  if (style->parentRule()) {
    InspectorStyleSheet* style_sheet =
        BindStyleSheet(style->ParentStyleSheet());
    inspector_style_sheet = style_sheet;
    source_data = style_sheet->SourceDataForRule(style->parentRule());
  } else {
    InspectorStyleSheetForInlineStyle* inline_style_sheet =
        AsInspectorStyleSheet(element);
    inspector_style_sheet = inline_style_sheet;
    source_data = inline_style_sheet->RuleSourceData();
  }

  if (!source_data) {
    //DLOG(ERROR) << "Can't find a source to edit";
    return;
  }

  Vector<blink::StylePropertyShorthand, 4> shorthands;
  blink::getMatchingShorthandsForLonghand(property_id, &shorthands);

  String shorthand =
      shorthands.size() > 0
          ? blink::CSSProperty::Get(shorthands[0].id()).GetPropertyNameString()
          : String();
  String longhand = property_class.GetPropertyNameString();

  int found_index = -1;
  Vector<blink::CSSPropertySourceData>& properties = source_data->property_data;
  for (unsigned i = 0; i < properties.size(); ++i) {
    blink::CSSPropertySourceData property = properties[properties.size() - i - 1];
    String name = property.name;
    if (property.disabled)
      continue;

    if (name != shorthand && name != longhand)
      continue;

    if (property.important || found_index == -1)
      found_index = properties.size() - i - 1;

    if (property.important)
      break;
  }

  blink::SourceRange body_range = source_data->rule_body_range;
  String style_sheet_text;
  inspector_style_sheet->GetText(&style_sheet_text);
  String style_text =
      style_sheet_text.Substring(body_range.start, body_range.length());
  blink::SourceRange change_range;
  if (found_index == -1) {
    String new_property_text = "\n" + longhand + ": " + value_str +
                               (force_important ? " !important" : "") + ";";
    if (!style_text.IsEmpty() && !style_text.StripWhiteSpace().EndsWith(';'))
      new_property_text = ";" + new_property_text;
    style_text.append(new_property_text);
    change_range.start = body_range.end;
    change_range.end = body_range.end + new_property_text.length();
  } else {
    blink::CSSPropertySourceData declaration = properties[found_index];
    String new_value_text;
    if (declaration.name == shorthand)
      new_value_text = CreateShorthandValue(element->ownerDocument(), shorthand,
                                            declaration.value, longhand, value_str);
    else
      new_value_text = value_str;

    String new_property_text =
        declaration.name + ": " + new_value_text +
        (declaration.important || force_important ? " !important" : "") + ";";
    style_text.replace(declaration.range.start - body_range.start,
                       declaration.range.length(), new_property_text);
    change_range.start = declaration.range.start;
    change_range.end = change_range.start + new_property_text.length();
  }
  blink::CSSStyleDeclaration* result_style;
  SetStyleText(inspector_style_sheet, body_range, style_text, result_style);
}

void CSSDispatcher::SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, SetKeyframeKeyCallback callback) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  bool found = AssertInspectorStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!found) {
    std::move(callback).Run(nullptr);
    return;
  }
  blink::SourceRange key_range;
  bool conversion = JsonRangeToSourceRange(inspector_style_sheet, range.get(), &key_range);
  if (!conversion) {
    std::move(callback).Run(nullptr);
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  blink::CSSRule* css_rule = inspector_style_sheet->SetKeyframeKey(key_range, String::FromUTF8(key_text.data()), nullptr, nullptr, exception_state);  
  if (css_rule) {
    blink::CSSKeyframeRule* rule = ToCSSKeyframeRule(css_rule);
    InspectorStyleSheet* inspector_style_sheet = BindStyleSheet(rule->parentStyleSheet());
    if (!inspector_style_sheet) {
      //DLOG(ERROR) << "Failed to get inspector style sheet for rule.";
      std::move(callback).Run(nullptr);
      return;
    }

    blink::CSSRuleSourceData* source_data = inspector_style_sheet->SourceDataForRule(rule);
    automation::CSSValuePtr result = automation::CSSValue::New();
    result->text = std::string(rule->keyText().Utf8().data(), rule->keyText().length());
    result->range = inspector_style_sheet->BuildSourceRangeObject(source_data->rule_header_range);
    std::move(callback).Run(std::move(result));
    return;      
  }
  std::move(callback).Run(nullptr);
}

void CSSDispatcher::SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, SetMediaTextCallback callback) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  bool found = AssertInspectorStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!found) {
    std::move(callback).Run(nullptr);
    return;
  }
  blink::SourceRange text_range;
  bool conversion = JsonRangeToSourceRange(inspector_style_sheet, range.get(), &text_range);
  if (!conversion) {
    std::move(callback).Run(nullptr);
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  blink::CSSRule* css_rule = inspector_style_sheet->SetMediaRuleText(
    text_range, 
    String::FromUTF8(text.data()), 
    nullptr, 
    nullptr, 
    exception_state);
  if (css_rule) {
    blink::CSSMediaRule* rule = CSSDispatcher::AsCSSMediaRule(css_rule);
    String source_url = rule->parentStyleSheet()->Contents()->BaseURL();
    if (source_url.IsEmpty()) {
      source_url = DocumentURLString(rule->parentStyleSheet()->OwnerDocument());
    }
    std::move(callback).Run(
      BuildMediaObject(rule->media(), kMediaListSourceMediaRule,
                       source_url, rule->parentStyleSheet()));
    return;
  }
  std::move(callback).Run(nullptr);
}

void CSSDispatcher::SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, SetRuleSelectorCallback callback) {
  InspectorStyleSheet* inspector_style_sheet = nullptr;
  bool found = AssertInspectorStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!found) {
    std::move(callback).Run(nullptr);
    return;
  }
  blink::SourceRange selector_range;
  bool converted = JsonRangeToSourceRange(inspector_style_sheet, range.get(), &selector_range);
  if (!converted) {
    std::move(callback).Run(nullptr);
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  blink::CSSRule* css_rule = inspector_style_sheet->SetRuleSelector(selector_range, String::FromUTF8(selector.data()), nullptr, nullptr, exception_state);
  if (css_rule) {
    blink::CSSStyleRule* css_style_rule = CSSDispatcher::AsCSSStyleRule(css_rule);
    InspectorStyleSheet* inspector_style_sheet = InspectorStyleSheetForRule(css_style_rule);
    if (!inspector_style_sheet) {
      //DLOG(ERROR) << "Failed to get inspector style sheet for rule.";
      std::move(callback).Run(nullptr);
      return ;
    }
    std::move(callback).Run(inspector_style_sheet->BuildObjectForSelectorList(css_style_rule));
    return;
  }
  std::move(callback).Run(nullptr);
}

void CSSDispatcher::SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, SetStyleSheetTextCallback callback) {
  InspectorStyleSheetBase* inspector_style_sheet = nullptr;
  bool ok = AssertStyleSheetForId(String::FromUTF8(style_sheet_id.data()), inspector_style_sheet);
  if (!ok) {
    std::move(callback).Run(std::string());
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  inspector_style_sheet->SetText(String::FromUTF8(text.data()), exception_state);
  if (!inspector_style_sheet->SourceMapURL().IsEmpty()) {
    String source_map_url = inspector_style_sheet->SourceMapURL();
    std::move(callback).Run(std::string(source_map_url.Utf8().data(), source_map_url.length()));
    return;
  }
  std::move(callback).Run(std::string());
}

void CSSDispatcher::SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, SetStyleTextsCallback callback) {
  std::vector<automation::CSSStylePtr> serialized_styles;

  if (edits.size() == 0) {
    std::move(callback).Run(std::vector<automation::CSSStylePtr>());
  }

  for (size_t i = 0; i < edits.size(); ++i) {
    const automation::StyleDeclarationEditPtr& edit = edits[i];
    InspectorStyleSheetBase* inspector_style_sheet = nullptr;
    bool found = AssertStyleSheetForId(String::FromUTF8(edit->style_sheet_id.data()), inspector_style_sheet);
    if (!found) {
      //DLOG(ERROR) << "StyleSheet not found for edit " << i + 1 << " of " << edits.size();
      std::move(callback).Run(std::vector<automation::CSSStylePtr>());
      return;
    }

    blink::SourceRange range;
    bool converted = JsonRangeToSourceRange(inspector_style_sheet, edit->range.get(), &range);
    if (!converted) {
      std::move(callback).Run(std::vector<automation::CSSStylePtr>());
      return;
    }

    blink::DummyExceptionStateForTesting exception_state;
    if (inspector_style_sheet->IsInlineStyle()) {
      InspectorStyleSheetForInlineStyle* inline_style_sheet = static_cast<InspectorStyleSheetForInlineStyle*>(inspector_style_sheet);
      inline_style_sheet->SetText(String::FromUTF8(edit->text.data()), exception_state);
      automation::CSSStylePtr style = inline_style_sheet->BuildObjectForStyle(inline_style_sheet->InlineStyle());
      serialized_styles.push_back(std::move(style));
    } else {
      automation::CSSStylePtr style;
      InspectorStyleSheet* style_sheet = static_cast<InspectorStyleSheet*>(inspector_style_sheet);
      blink::CSSRule* css_rule = style_sheet->SetStyleText(
        range, String::FromUTF8(edit->text.data()), nullptr, nullptr, exception_state);
      if (css_rule->type() == blink::CSSRule::kStyleRule) {
        style = style_sheet->BuildObjectForStyle(ToCSSStyleRule(css_rule)->style());
      } else if (css_rule->type() == blink::CSSRule::kKeyframeRule) {
        style = style_sheet->BuildObjectForStyle(ToCSSKeyframeRule(css_rule)->style());
      }      
      serialized_styles.push_back(std::move(style));
    }
  }
  std::move(callback).Run(std::move(serialized_styles));
}

bool CSSDispatcher::SetStyleText(
    InspectorStyleSheetBase* inspector_style_sheet,
    const blink::SourceRange& range,
    const String& text,
    blink::CSSStyleDeclaration*& result) {
  blink::DummyExceptionStateForTesting exception_state;
  if (inspector_style_sheet->IsInlineStyle()) {
    InspectorStyleSheetForInlineStyle* inline_style_sheet =
        static_cast<InspectorStyleSheetForInlineStyle*>(inspector_style_sheet);
    return inline_style_sheet->SetText(text, exception_state);
  } else {
    InspectorStyleSheet* style_sheet = static_cast<InspectorStyleSheet*>(inspector_style_sheet);
      blink::CSSRule* css_rule = style_sheet->SetStyleText(
        range, text, nullptr, nullptr, exception_state);
    if (css_rule) {
      if (css_rule->type() == blink::CSSRule::kStyleRule) {
        result = ToCSSStyleRule(css_rule)->style();
        return true;
      }
      if (css_rule->type() == blink::CSSRule::kKeyframeRule) {
        result = ToCSSKeyframeRule(css_rule)->style();
        return true;
      }
    }
  }
  return false;
}

void CSSDispatcher::StartRuleUsageTracking() {
  rule_recording_enabled_ = true;
  SetCoverageEnabled(true);

  for (blink::Document* document : dom_dispatcher_->Documents()) {
    document->SetNeedsStyleRecalc(
        blink::kSubtreeStyleChange,
        blink::StyleChangeReasonForTracing::Create("Inspector"));
    document->UpdateStyleAndLayoutTree();
  }
}

void CSSDispatcher::StopRuleUsageTracking(StopRuleUsageTrackingCallback callback) {
  std::vector<automation::CSSRuleUsagePtr> result = TakeCoverageDeltaInternal();  
  SetCoverageEnabled(false);
  std::move(callback).Run(std::move(result));
}

void CSSDispatcher::TakeCoverageDelta(TakeCoverageDeltaCallback callback) {
  std::vector<automation::CSSRuleUsagePtr> result = TakeCoverageDeltaInternal();  
  std::move(callback).Run(std::move(result));
}

std::vector<automation::CSSRuleUsagePtr> CSSDispatcher::TakeCoverageDeltaInternal() {
  std::vector<automation::CSSRuleUsagePtr> result;
  if (!tracker_) {
    //DLOG(ERROR) << "CSS rule usage tracking is not enabled";
    return result;
  }

  blink::StyleRuleUsageTracker::RuleListByStyleSheet coverage_delta = tracker_->TakeDelta();

  for (const auto& entry : coverage_delta) {
    const blink::CSSStyleSheet* css_style_sheet = entry.key.Get();
    InspectorStyleSheet* style_sheet =
        css_style_sheet_to_inspector_style_sheet_.at(
            const_cast<blink::CSSStyleSheet*>(css_style_sheet));
    if (!style_sheet)
      continue;

    blink::HeapHashMap<blink::Member<const blink::StyleRule>, blink::Member<blink::CSSStyleRule>> rule_to_css_rule;
    const blink::CSSRuleVector& css_rules = style_sheet->FlatRules();
    for (auto css_rule : css_rules) {
      if (css_rule->type() != blink::CSSRule::kStyleRule)
        continue;
      blink::CSSStyleRule* css_style_rule = AsCSSStyleRule(css_rule);
      rule_to_css_rule.Set(css_style_rule->GetStyleRule(), css_style_rule);
    }
    for (auto used_rule : entry.value) {
      blink::CSSStyleRule* css_style_rule = rule_to_css_rule.at(used_rule);
      if (automation::CSSRuleUsagePtr rule_usage_object = style_sheet->BuildObjectForRuleUsage(css_style_rule, true)) {
        result.push_back(std::move(rule_usage_object));
      }
    }
  }
  return result;
}

void CSSDispatcher::UpdateActiveStyleSheets(blink::Document* document) {
  blink::HeapVector<blink::Member<blink::CSSStyleSheet>> new_sheets_vector;
  CSSDispatcher::CollectAllDocumentStyleSheets(document, new_sheets_vector);
  SetActiveStyleSheets(document, new_sheets_vector);
}

void CSSDispatcher::SetActiveStyleSheets(
  blink::Document* document,
  const blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& all_sheets_vector) {
  blink::HeapHashSet<blink::Member<blink::CSSStyleSheet>>* document_css_style_sheets =
      document_to_css_style_sheets_.at(document);
  if (!document_css_style_sheets) {
    document_css_style_sheets = new blink::HeapHashSet<blink::Member<blink::CSSStyleSheet>>();
    document_to_css_style_sheets_.Set(document, document_css_style_sheets);
  }

  blink::HeapHashSet<blink::Member<blink::CSSStyleSheet>> removed_sheets(*document_css_style_sheets);
  blink::HeapVector<blink::Member<blink::CSSStyleSheet>> added_sheets;
  for (blink::CSSStyleSheet* css_style_sheet : all_sheets_vector) {
    if (removed_sheets.Contains(css_style_sheet)) {
      removed_sheets.erase(css_style_sheet);
    } else {
      added_sheets.push_back(css_style_sheet);
    }
  }

  for (blink::CSSStyleSheet* css_style_sheet : removed_sheets) {
    InspectorStyleSheet* inspector_style_sheet =
        css_style_sheet_to_inspector_style_sheet_.at(css_style_sheet);
    DCHECK(inspector_style_sheet);

    document_css_style_sheets->erase(css_style_sheet);
    if (id_to_inspector_style_sheet_.Contains(inspector_style_sheet->Id())) {
      String id = UnbindStyleSheet(inspector_style_sheet);
      if (GetClient())
        GetClient()->OnStyleSheetRemoved(std::string(id.Utf8().data()));
    }
  }

  for (blink::CSSStyleSheet* css_style_sheet : added_sheets) {
    InspectorStyleSheet* new_style_sheet = BindStyleSheet(css_style_sheet);
    document_css_style_sheets->insert(css_style_sheet);
    if (GetClient()) {
      GetClient()->OnStyleSheetAdded(new_style_sheet->BuildObjectForStyleSheetInfo());
    }
  }

  if (document_css_style_sheets->IsEmpty())
    document_to_css_style_sheets_.erase(document);
}


void CSSDispatcher::ForcePseudoState(blink::Element* element, blink::CSSSelector::PseudoType pseudo_type, bool* result) {
  if (node_id_to_forced_pseudo_state_.IsEmpty())
    return;

  int node_id = dom_dispatcher_->BoundNodeId(element);
  if (!node_id)
    return;

  NodeIdToForcedPseudoState::iterator it =
      node_id_to_forced_pseudo_state_.find(node_id);
  if (it == node_id_to_forced_pseudo_state_.end())
    return;

  bool force = false;
  unsigned forced_pseudo_state = it->value;
  switch (pseudo_type) {
    case blink::CSSSelector::kPseudoActive:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoActive;
      break;
    case blink::CSSSelector::kPseudoFocus:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoFocus;
      break;
    case blink::CSSSelector::kPseudoFocusWithin:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoFocusWithin;
      break;
    case blink::CSSSelector::kPseudoFocusVisible:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoFocusVisible;
      break;
    case blink::CSSSelector::kPseudoHover:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoHover;
      break;
    case blink::CSSSelector::kPseudoVisited:
      force = forced_pseudo_state & blink::CSSSelector::kPseudoVisited;
      break;
    default:
      break;
  }
  if (force)
    *result = true;
}

void CSSDispatcher::DidCommitLoadForLocalFrame(blink::LocalFrame* frame) {
  if (frame == page_instance_->inspected_frames()->Root())
    Reset();
}

void CSSDispatcher::MediaQueryResultChanged() {
  FlushPendingProtocolNotifications();
  GetClient()->OnMediaQueryResultChanged();
}

void CSSDispatcher::ActiveStyleSheetsUpdated(blink::Document* document) {
  invalidated_documents_.insert(document);
}

void CSSDispatcher::DocumentDetached(blink::Document* document) {
  invalidated_documents_.erase(document);
  SetActiveStyleSheets(document, blink::HeapVector<blink::Member<blink::CSSStyleSheet>>());
}

void CSSDispatcher::FontsUpdated(const blink::FontFace* font,
                                 const String& src,
                                 const blink::FontCustomPlatformData* font_custom) {
  FlushPendingProtocolNotifications();

  if (!(font && src && font_custom)) {
    GetClient()->OnFontsUpdated(nullptr);
    return;
  }

  // blink::FontFace returns sane property defaults per the web fonts spec,
  // so we don't perform null checks here.
  automation::FontFacePtr font_face = automation::FontFace::New();
  font_face->font_family = std::string(font->family().Utf8().data(), font->family().length());
  font_face->font_style = std::string(font->style().Utf8().data(), font->style().length());
  font_face->font_variant = std::string(font->variant().Utf8().data(), font->variant().length());
  font_face->font_weight = std::string(font->weight().Utf8().data(), font->weight().length());
  font_face->font_stretch = std::string(font->stretch().Utf8().data(), font->stretch().length());;
  font_face->unicode_range = std::string(font->unicodeRange().Utf8().data(), font->unicodeRange().length());
  font_face->src = std::string(src.Utf8().data(), src.length());
  font_face->platform_font_family = std::string(String::FromUTF8(font_custom->FamilyNameForInspector().c_str()).Utf8().data());
  GetClient()->OnFontsUpdated(std::move(font_face));
}

void CSSDispatcher::SetCoverageEnabled(bool enabled) {
  if (enabled == !!tracker_)
    return;
    
  tracker_ = enabled ? new blink::StyleRuleUsageTracker() : nullptr;

  for (blink::Document* document : dom_dispatcher_->Documents())
    document->GetStyleEngine().SetRuleUsageTracker(tracker_);
}

void CSSDispatcher::WillChangeStyleElement(blink::Element* element) {
  resource_container_->EraseStyleElementContent(blink::DOMNodeIds::IdForNode(element));
}

InspectorStyleSheet* CSSDispatcher::BindStyleSheet(blink::CSSStyleSheet* style_sheet) {
  InspectorStyleSheet* inspector_style_sheet =
      css_style_sheet_to_inspector_style_sheet_.at(style_sheet);
  if (!inspector_style_sheet) {
    blink::Document* document = style_sheet->OwnerDocument();
    inspector_style_sheet = InspectorStyleSheet::Create(
        network_dispatcher_, style_sheet, DetectOrigin(style_sheet, document),
        DocumentURLString(document), this,
        resource_container_);
    id_to_inspector_style_sheet_.Set(inspector_style_sheet->Id(),
                                     inspector_style_sheet);
    css_style_sheet_to_inspector_style_sheet_.Set(style_sheet,
                                                  inspector_style_sheet);
  }
  return inspector_style_sheet;
}

String CSSDispatcher::StyleSheetId(blink::CSSStyleSheet* style_sheet) {
  return BindStyleSheet(style_sheet)->Id();
}

String CSSDispatcher::UnbindStyleSheet(InspectorStyleSheet* inspector_style_sheet) {
  String id = inspector_style_sheet->Id();
  id_to_inspector_style_sheet_.erase(id);
  if (inspector_style_sheet->PageStyleSheet())
    css_style_sheet_to_inspector_style_sheet_.erase(
        inspector_style_sheet->PageStyleSheet());
  return id;
}

automation::StyleSheetOrigin CSSDispatcher::DetectOrigin(
  blink::CSSStyleSheet* page_style_sheet,
  blink::Document* owner_document) {
  DCHECK(page_style_sheet);

  if (!page_style_sheet->ownerNode() && page_style_sheet->href().IsEmpty())
    return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_USER_AGENT;

  if (page_style_sheet->ownerNode() &&
      page_style_sheet->ownerNode()->IsDocumentNode()) {
    if (page_style_sheet ==
        owner_document->GetStyleEngine().InspectorStyleSheet())
      return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INSPECTOR;
    return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INJECTED;
  }
  return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR;
}

// static
blink::CSSStyleRule* CSSDispatcher::AsCSSStyleRule(blink::CSSRule* rule) {
  if (!rule || rule->type() != blink::CSSRule::kStyleRule)
    return nullptr;
  return ToCSSStyleRule(rule);
}

// static 
blink::CSSMediaRule* CSSDispatcher::AsCSSMediaRule(blink::CSSRule* rule) {
  if (!rule || rule->type() != blink::CSSRule::kMediaRule)
    return nullptr;
  return ToCSSMediaRule(rule);
}

void CSSDispatcher::StyleSheetChanged(InspectorStyleSheetBase* style_sheet) {
  FlushPendingProtocolNotifications();
  GetClient()->OnStyleSheetChanged(std::string(style_sheet->Id().Utf8().data(), style_sheet->Id().length()));
}

void CSSDispatcher::CollectMediaQueriesFromStyleSheet(
  blink::CSSStyleSheet* style_sheet,
  std::vector<automation::CSSMediaPtr>* media_array) {
  
  blink::MediaList* media_list = style_sheet->media();
  String source_url;
  if (media_list && media_list->length()) {
    blink::Document* doc = style_sheet->OwnerDocument();
    if (doc)
      source_url = doc->Url();
    else if (!style_sheet->Contents()->BaseURL().IsEmpty())
      source_url = style_sheet->Contents()->BaseURL();
    else
      source_url = "";
    media_array->push_back(BuildMediaObject(
                            media_list,
                            style_sheet->ownerNode()
                              ? kMediaListSourceLinkedSheet
                              : kMediaListSourceInlineSheet,
                            source_url, style_sheet));
  }
}

void CSSDispatcher::CollectMediaQueriesFromRule(
  blink::CSSRule* rule,
  std::vector<automation::CSSMediaPtr>* media_array) {
  
  blink::MediaList* media_list;
  String source_url;
  blink::CSSStyleSheet* parent_style_sheet = nullptr;
  bool is_media_rule = true;
  if (rule->type() == blink::CSSRule::kMediaRule) {
    blink::CSSMediaRule* media_rule = blink::ToCSSMediaRule(rule);
    media_list = media_rule->media();
    parent_style_sheet = media_rule->parentStyleSheet();
  } else if (rule->type() == blink::CSSRule::kImportRule) {
    blink::CSSImportRule* import_rule = blink::ToCSSImportRule(rule);
    media_list = import_rule->media();
    parent_style_sheet = import_rule->parentStyleSheet();
    is_media_rule = false;
  } else {
    media_list = nullptr;
  }

  if (parent_style_sheet) {
    source_url = parent_style_sheet->Contents()->BaseURL();
    if (source_url.IsEmpty())
      source_url = DocumentURLString(
          parent_style_sheet->OwnerDocument());
  } else {
    source_url = "";
  }

  if (media_list && media_list->length())
    media_array->push_back(BuildMediaObject(
        media_list,
        is_media_rule ? kMediaListSourceMediaRule : kMediaListSourceImportRule,
        source_url, parent_style_sheet));
}


automation::CSSMediaPtr CSSDispatcher::BuildMediaObject(
  const blink::MediaList* media,
  MediaListSource media_list_source,
  const String& source_url,
  blink::CSSStyleSheet* parent_style_sheet) {
  // Make certain compilers happy by initializing |source| up-front.
  automation::CSSMediaSource source = automation::CSSMediaSource::kCSS_MEDIA_SOURCE_INLINE_SHEET;
  switch (media_list_source) {
    case kMediaListSourceMediaRule:
      source = automation::CSSMediaSource::kCSS_MEDIA_SOURCE_MEDIA_RULE;
      break;
    case kMediaListSourceImportRule:
      source = automation::CSSMediaSource::kCSS_MEDIA_SOURCE_IMPORT_RULE;
      break;
    case kMediaListSourceLinkedSheet:
      source = automation::CSSMediaSource::kCSS_MEDIA_SOURCE_LINKED_SHEET;
      break;
    case kMediaListSourceInlineSheet:
      source = automation::CSSMediaSource::kCSS_MEDIA_SOURCE_INLINE_SHEET;
      break;
  }

  const blink::MediaQuerySet* queries = media->Queries();
  const Vector<std::unique_ptr<blink::MediaQuery>>& query_vector =
      queries->QueryVector();
  blink::LocalFrame* frame = nullptr;
  if (parent_style_sheet) {
    if (blink::Document* document = parent_style_sheet->OwnerDocument())
      frame = document->GetFrame();
  }
  blink::MediaQueryEvaluator* media_evaluator = new blink::MediaQueryEvaluator(frame);

  InspectorStyleSheet* inspector_style_sheet =
      parent_style_sheet
          ? css_style_sheet_to_inspector_style_sheet_.at(parent_style_sheet)
          : nullptr;
  std::vector<automation::CSSMediaQueryPtr> media_list_array;
  blink::MediaValues* media_values = blink::MediaValues::CreateDynamicIfFrameExists(frame);
  bool has_media_query_items = false;
  for (size_t i = 0; i < query_vector.size(); ++i) {
    blink::MediaQuery& query = *query_vector.at(i);
    const blink::ExpressionHeapVector& expressions = query.Expressions();
    std::vector<automation::CSSMediaQueryExpressionPtr> expression_array;
    bool has_expression_items = false;
    for (size_t j = 0; j < expressions.size(); ++j) {
      const blink::MediaQueryExp& media_query_exp = expressions.at(j);
      blink::MediaQueryExpValue exp_value = media_query_exp.ExpValue();
      if (!exp_value.is_value)
        continue;
      const char* value_name = blink::CSSPrimitiveValue::UnitTypeToString(exp_value.unit);
      automation::CSSMediaQueryExpressionPtr media_query_expression = automation::CSSMediaQueryExpression::New();
      media_query_expression->value = exp_value.value;
      media_query_expression->unit = std::string(value_name);
      media_query_expression->feature = std::string(media_query_exp.MediaFeature().Utf8().data(), media_query_exp.MediaFeature().Utf8().length());
                  
      if (inspector_style_sheet && media->ParentRule())
        media_query_expression->value_range = 
            inspector_style_sheet->MediaQueryExpValueSourceRange(
                media->ParentRule(), i, j);

      int computed_length;
      if (media_values->ComputeLength(exp_value.value, exp_value.unit,
                                      computed_length))
        media_query_expression->computed_length = computed_length;

      expression_array.push_back(std::move(media_query_expression));
      has_expression_items = true;
    }
    if (!has_expression_items)
      continue;
    automation::CSSMediaQueryPtr media_query = automation::CSSMediaQuery::New();
    media_query->active = media_evaluator->Eval(query, nullptr);
    media_query->expressions = std::move(expression_array);
    media_list_array.push_back(std::move(media_query));
    has_media_query_items = true;
  }

  automation::CSSMediaPtr media_object = automation::CSSMedia::New();
  media_object->text = std::string(media->mediaText().Utf8().data(), media->mediaText().Utf8().length());
  media_object->source = source;
  
  if (has_media_query_items)
    media_object->media_list = std::move(media_list_array);

  if (inspector_style_sheet && media_list_source != kMediaListSourceLinkedSheet)
    media_object->style_sheet_id = std::string(inspector_style_sheet->Id().Utf8().data(), inspector_style_sheet->Id().Utf8().length());

  if (!source_url.IsEmpty()) {
    media_object->source_url = std::string(source_url.Utf8().data(), source_url.Utf8().length());

    blink::CSSRule* parent_rule = media->ParentRule();
    if (!parent_rule)
      return media_object;
    InspectorStyleSheet* inspector_style_sheet =
        BindStyleSheet(parent_rule->parentStyleSheet());
    media_object->range = inspector_style_sheet->RuleHeaderSourceRange(parent_rule);
  }
  return media_object;
}

std::vector<automation::RuleMatchPtr> CSSDispatcher::BuildArrayForMatchedRuleList(
  blink::CSSRuleList* rule_list,
  blink::Element* element,
  blink::PseudoId matches_for_pseudo_id) {

  std::vector<automation::RuleMatchPtr> result;
  if (!rule_list)
    return result;

  blink::HeapVector<blink::Member<blink::CSSStyleRule>> uniq_rules = FilterDuplicateRules(rule_list);
  for (unsigned i = 0; i < uniq_rules.size(); ++i) {
    blink::CSSStyleRule* rule = uniq_rules.at(i).Get();
    automation::CSSRulePtr rule_object = BuildObjectForRule(rule);
    if (!rule_object)
      continue;
    std::vector<int> matching_selectors;
    const blink::CSSSelectorList& selector_list = rule->GetStyleRule()->SelectorList();
    long index = 0;
    blink::PseudoId element_pseudo_id =
        matches_for_pseudo_id ? matches_for_pseudo_id : element->GetPseudoId();
    for (const blink::CSSSelector* selector = selector_list.First(); 
         selector;
         selector = blink::CSSSelectorList::Next(*selector)) {
      const blink::CSSSelector* first_tag_history_selector = selector;
      bool matched = false;
      if (element_pseudo_id)
        matched = MatchesPseudoElement(selector, element_pseudo_id);  // Modifies |selector|.
      else
        matched = element->matches(
            AtomicString(first_tag_history_selector->SelectorText()),
            blink::DummyExceptionStateForTesting().ReturnThis());
      if (matched)
        matching_selectors.push_back(index);
      ++index;
    }
    automation::RuleMatchPtr match = automation::RuleMatch::New();
    match->rule = std::move(rule_object);
    match->matching_selectors = std::move(matching_selectors);
                        
    result.push_back(std::move(match));
  }

  return result;
}

std::vector<automation::CSSKeyframesRulePtr> CSSDispatcher::AnimationsForNode(blink::Element* element) {
  std::vector<automation::CSSKeyframesRulePtr> css_keyframes_rules;
  blink::Document* owner_document = element->ownerDocument();

  blink::StyleResolver& style_resolver = owner_document->EnsureStyleResolver();
  scoped_refptr<blink::ComputedStyle> style = style_resolver.StyleForElement(element);
  if (!style)
    return css_keyframes_rules;
  const blink::CSSAnimationData* animation_data = style->Animations();
  for (size_t i = 0; animation_data && i < animation_data->NameList().size();
       ++i) {
    AtomicString animation_name(animation_data->NameList()[i]);
    if (animation_name == blink::CSSAnimationData::InitialName())
      continue;
    blink::StyleRuleKeyframes* keyframes_rule =
        style_resolver.FindKeyframesRule(element, animation_name);
    if (!keyframes_rule)
      continue;

    // Find CSSOM wrapper.
    blink::CSSKeyframesRule* css_keyframes_rule = nullptr;
    for (blink::CSSStyleSheet* style_sheet :
         *document_to_css_style_sheets_.at(owner_document)) {
      css_keyframes_rule = FindKeyframesRule(style_sheet, keyframes_rule);
      if (css_keyframes_rule)
        break;
    }
    if (!css_keyframes_rule)
      continue;

    std::vector<automation::CSSKeyframeRulePtr> keyframes;
    for (unsigned j = 0; j < css_keyframes_rule->length(); ++j) {
      InspectorStyleSheet* inspector_style_sheet =
          BindStyleSheet(css_keyframes_rule->parentStyleSheet());
      keyframes.push_back(inspector_style_sheet->BuildObjectForKeyframeRule(
          css_keyframes_rule->Item(j)));
    }

    InspectorStyleSheet* inspector_style_sheet =
        BindStyleSheet(css_keyframes_rule->parentStyleSheet());
    blink::CSSRuleSourceData* source_data =
        inspector_style_sheet->SourceDataForRule(css_keyframes_rule);
    automation::CSSValuePtr name = automation::CSSValue::New();
    name->text = std::string(css_keyframes_rule->name().Utf8().data(), css_keyframes_rule->name().Utf8().length());
    
    if (source_data)
      name->range = inspector_style_sheet->BuildSourceRangeObject(source_data->rule_header_range);
    
    automation::CSSKeyframesRulePtr rule = automation::CSSKeyframesRule::New();
    rule->animation_name = std::move(name);
    rule->keyframes = std::move(keyframes); 
    css_keyframes_rules.push_back(std::move(rule));
  }
  return css_keyframes_rules;
}

automation::CSSStylePtr CSSDispatcher::BuildObjectForAttributesStyle(blink::Element* element) {
  if (!element->IsStyledElement())
    return nullptr;

  // FIXME: Ugliness below.
  blink::CSSPropertyValueSet* attribute_style =
      const_cast<blink::CSSPropertyValueSet*>(element->PresentationAttributeStyle());
  if (!attribute_style)
    return nullptr;

  blink::MutableCSSPropertyValueSet* mutable_attribute_style =
      ToMutableCSSPropertyValueSet(attribute_style);

  InspectorStyle* inspector_style = InspectorStyle::Create(
      mutable_attribute_style->EnsureCSSStyleDeclaration(), nullptr, nullptr);
  return inspector_style->BuildObjectForStyle();
}

std::vector<automation::CSSMediaPtr> CSSDispatcher::BuildMediaListChain(blink::CSSRule* rule) {
  if (!rule)
    return std::vector<automation::CSSMediaPtr>();
  
  std::vector<automation::CSSMediaPtr> media_array;
  blink::CSSRule* parent_rule = rule;
  while (parent_rule) {
    CollectMediaQueriesFromRule(parent_rule, &media_array);
    if (parent_rule->parentRule()) {
      parent_rule = parent_rule->parentRule();
    } else {
      blink::CSSStyleSheet* style_sheet = parent_rule->parentStyleSheet();
      while (style_sheet) {
        CollectMediaQueriesFromStyleSheet(style_sheet, &media_array);
        parent_rule = style_sheet->ownerRule();
        if (parent_rule)
          break;
        style_sheet = style_sheet->parentStyleSheet();
      }
    }
  }
  return media_array;
}

automation::CSSRulePtr CSSDispatcher::BuildObjectForRule(blink::CSSStyleRule* rule) {
  InspectorStyleSheet* inspector_style_sheet = InspectorStyleSheetForRule(rule);
  if (!inspector_style_sheet)
    return nullptr;

  automation::CSSRulePtr result = inspector_style_sheet->BuildObjectForRuleWithoutMedia(rule);
  result->media = BuildMediaListChain(rule);
  return result;
}

InspectorStyleSheetForInlineStyle* CSSDispatcher::AsInspectorStyleSheet(
  blink::Element* element) {
  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(element);
  if (it != node_to_inspector_style_sheet_.end())
    return it->value.Get();

  blink::CSSStyleDeclaration* style = element->style();
  if (!style)
    return nullptr;

  InspectorStyleSheetForInlineStyle* inspector_style_sheet =
      InspectorStyleSheetForInlineStyle::Create(element, this);
  id_to_inspector_style_sheet_for_inline_style_.Set(inspector_style_sheet->Id(),
                                                    inspector_style_sheet);
  node_to_inspector_style_sheet_.Set(element, inspector_style_sheet);
  return inspector_style_sheet;
}

InspectorStyleSheet* CSSDispatcher::InspectorStyleSheetForRule(blink::CSSStyleRule* rule) {
  if (!rule)
    return nullptr;

  // CSSRules returned by StyleResolver::pseudoCSSRulesForElement lack parent
  // pointers if they are coming from user agent stylesheets. To work around
  // this issue, we use CSSOM wrapper created by inspector.
  if (!rule->parentStyleSheet()) {
    if (!inspector_user_agent_style_sheet_)
      inspector_user_agent_style_sheet_ = blink::CSSStyleSheet::Create(
          blink::CSSDefaultStyleSheets::Instance().DefaultStyleSheet());
    rule->SetParentStyleSheet(inspector_user_agent_style_sheet_.Get());
  }
  return BindStyleSheet(rule->parentStyleSheet());
}

void CSSDispatcher::CollectPlatformFontsForLayoutObject(
  blink::LayoutObject* layout_object,
  HashCountedSet<std::pair<int, String>>* font_stats) {
  if (!layout_object->IsText())
    return;

  blink::FontCachePurgePreventer preventer;
  blink::LayoutText* layout_text = ToLayoutText(layout_object);

 // if (RuntimeEnabledFeatures::LayoutNGEnabled()) {
    auto fragments = blink::NGPaintFragment::InlineFragmentsFor(layout_object);
    if (fragments.IsInLayoutNGInlineFormattingContext()) {
      for (const blink::NGPaintFragment* fragment : fragments) {
        DCHECK(fragment->PhysicalFragment().IsText());
        const blink::NGPhysicalTextFragment& text_fragment =
            ToNGPhysicalTextFragment(fragment->PhysicalFragment());
        const blink::ShapeResult* shape_result = text_fragment.TextShapeResult();
        if (!shape_result)
          continue;
        Vector<blink::ShapeResult::RunFontData> run_font_data_list;
        shape_result->GetRunFontData(&run_font_data_list);
        CollectPlatformFontsFromRunFontDataList(run_font_data_list, font_stats);
      }
      return;
    }
    // If !IsInLayoutNGInlineFormattingContext, the LayoutText is in legacy
    // inline formatting context. Fallback to InlineTextBox code below.
  //}

  for (blink::InlineTextBox* box : layout_text->TextBoxes()) {
    const blink::ComputedStyle& style = layout_text->StyleRef(box->IsFirstLineStyle());
    const blink::Font& font = style.GetFont();
    blink::TextRun run = box->ConstructTextRunForInspector(style);
    blink::CachingWordShaper shaper(font);
    CollectPlatformFontsFromRunFontDataList(shaper.GetRunFontData(run),
                                            font_stats);
  }
}

InspectorStyleSheet* CSSDispatcher::ViaInspectorStyleSheet(blink::Document* document) {
  if (!document)
    return nullptr;

  if (!document->IsHTMLDocument() && !document->IsSVGDocument()) {
    return nullptr;
  }

  blink::CSSStyleSheet& inspector_sheet =
      document->GetStyleEngine().EnsureInspectorStyleSheet();

  FlushPendingProtocolNotifications();

  return css_style_sheet_to_inspector_style_sheet_.at(&inspector_sheet);
}

bool CSSDispatcher::AssertInspectorStyleSheetForId(const String& style_sheet_id, InspectorStyleSheet*& result) {
  if (enabled_) {
    return false;
  }
  IdToInspectorStyleSheet::iterator it =
      id_to_inspector_style_sheet_.find(style_sheet_id);
  if (it == id_to_inspector_style_sheet_.end())
    return false;
  result = it->value.Get();
  return true;
}

bool CSSDispatcher::AssertStyleSheetForId(
  const String& style_sheet_id,
  InspectorStyleSheetBase*& result) {
  InspectorStyleSheet* style_sheet = nullptr;
  bool ok = AssertInspectorStyleSheetForId(style_sheet_id, style_sheet);
  if (ok) {
    result = style_sheet;
    return true;
  }
  IdToInspectorStyleSheetForInlineStyle::iterator it =
      id_to_inspector_style_sheet_for_inline_style_.find(style_sheet_id);
  if (it == id_to_inspector_style_sheet_for_inline_style_.end()) {
    return false;
  }
  result = it->value.Get();
  return true;
}

blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>> CSSDispatcher::MatchingStyles(blink::Element* element) {
  blink::PseudoId pseudo_id = element->GetPseudoId();
  if (pseudo_id)
    element = element->parentElement();
  blink::StyleResolver& style_resolver =
      element->ownerDocument()->EnsureStyleResolver();
  element->UpdateDistributionForUnknownReasons();

  blink::HeapVector<blink::Member<blink::CSSStyleRule>> rules =
      FilterDuplicateRules(style_resolver.PseudoCSSRulesForElement(
          element, pseudo_id, blink::StyleResolver::kAllCSSRules));
  blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>> styles;
  if (!pseudo_id && element->style())
    styles.push_back(element->style());
  for (unsigned i = rules.size(); i > 0; --i) {
    blink::CSSStyleSheet* parent_style_sheet = rules.at(i - 1)->parentStyleSheet();
    if (!parent_style_sheet || !parent_style_sheet->ownerNode())
      continue;  // User agent.
    styles.push_back(rules.at(i - 1)->style());
  }
  return styles;
}

void CSSDispatcher::DidAddDocument(blink::Document* document) {
  if (!tracker_)
    return;

  document->GetStyleEngine().SetRuleUsageTracker(tracker_);
  document->SetNeedsStyleRecalc(
      blink::kSubtreeStyleChange,
      blink::StyleChangeReasonForTracing::Create("Inspector"));
}

void CSSDispatcher::DidRemoveDocument(blink::Document* document) {

}

void CSSDispatcher::DidRemoveDOMNode(blink::Node* node) {
  if (!node)
    return;

  int node_id = dom_dispatcher_->BoundNodeId(node);
  if (node_id)
    node_id_to_forced_pseudo_state_.erase(node_id);

  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(node);
  if (it == node_to_inspector_style_sheet_.end())
    return;

  id_to_inspector_style_sheet_for_inline_style_.erase(it->value->Id());
  node_to_inspector_style_sheet_.erase(node);
}

void CSSDispatcher::DidModifyDOMAttr(blink::Element* element) {
  if (!element)
    return;

  NodeToInspectorStyleSheet::iterator it =
      node_to_inspector_style_sheet_.find(element);
  if (it == node_to_inspector_style_sheet_.end())
    return;

  it->value->DidModifyElementAttribute();
}

void CSSDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  resource_container_ = page_instance_->inspector_resource_container();
  resource_content_loader_ = page_instance_->inspector_resource_content_loader();
  css_agent_impl_ = new InspectorCSSAgentImpl(this, context_);
  css_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
}

}