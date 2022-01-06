// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_CSS_DISPATCHER_H_
#define MUMBA_APPLICATION_CSS_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "core/shared/application/automation/dom_dispatcher.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "core/shared/application/automation/inspector_style_sheet.h"

namespace blink {
class LocalFrame;
class Document;
class DocumentLoader;
class Node;
class Element;
class FontFace;
class FontCustomPlatformData;
class CSSStyleSheet;
class CSSRule;
class CSSStyleRule;
class CSSRuleList;
class CSSMediaRule;
class StyleRuleUsageTracker;
class InspectorResourceContainer;
class InspectorResourceContentLoader;
class InspectorCSSAgent;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class InspectorCSSAgentImpl;
class PageInstance;
class DOMDispatcher;
class NetworkDispatcher;
class AutomationContext;
class ApplicationWindowDispatcher;
class InspectorStyleSheet;
class InspectorStyleSheetForInlineStyle;

class CSSDispatcher : public automation::CSS,
                      public InspectorStyleSheetBase::Listener,
                      public DOMDispatcher::DOMListener {
public:
  enum MediaListSource {
    kMediaListSourceLinkedSheet,
    kMediaListSourceInlineSheet,
    kMediaListSourceMediaRule,
    kMediaListSourceImportRule
  };

  class InlineStyleOverrideScope {
    STACK_ALLOCATED();

   public:
    InlineStyleOverrideScope(blink::SecurityContext* context)
        : content_security_policy_(context->GetContentSecurityPolicy()) {
      content_security_policy_->SetOverrideAllowInlineStyle(true);
    }

    ~InlineStyleOverrideScope() {
      content_security_policy_->SetOverrideAllowInlineStyle(false);
    }

   private:
    blink::Member<blink::ContentSecurityPolicy> content_security_policy_;
  };

  typedef blink::HeapHashMap<String, blink::Member<InspectorStyleSheet>>
      IdToInspectorStyleSheet;
  typedef blink::HeapHashMap<String, blink::Member<InspectorStyleSheetForInlineStyle>>
      IdToInspectorStyleSheetForInlineStyle;
  typedef blink::HeapHashMap<blink::Member<blink::Node>, blink::Member<InspectorStyleSheetForInlineStyle>>
      NodeToInspectorStyleSheet;  // bogus "stylesheets" with elements' inline
                                  // styles
  typedef HashMap<int, unsigned> NodeIdToForcedPseudoState;

  static blink::CSSStyleRule* AsCSSStyleRule(blink::CSSRule* rule);
  static blink::CSSMediaRule* AsCSSMediaRule(blink::CSSRule* rule);
  static CSSDispatcher* Create(automation::CSSRequest request, AutomationContext* context, PageInstance* page_instance);

  CSSDispatcher(automation::CSSRequest request, AutomationContext* context, PageInstance* page_instance);
  CSSDispatcher(AutomationContext* context, PageInstance* page_instance);
  ~CSSDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::CSSAssociatedRequest request);

  blink::InspectorCSSAgent* css_agent() const;

  void Register(int32_t application_id) override;
  void AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, AddRuleCallback callback) override;
  void CollectClassNames(const std::string& style_sheet_id, CollectClassNamesCallback callback) override;
  void CreateStyleSheet(const std::string& frame_id, CreateStyleSheetCallback callback) override;
  void Disable() override;
  void Enable() override;
  void ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) override;
  void GetBackgroundColors(int32_t node_id, GetBackgroundColorsCallback callback) override;
  void GetComputedStyleForNode(int32_t node_id, GetComputedStyleForNodeCallback callback) override;
  void GetInlineStylesForNode(int32_t node_id, GetInlineStylesForNodeCallback callback) override;
  void GetMatchedStylesForNode(int32_t node_id, GetMatchedStylesForNodeCallback callback) override;
  void GetMediaQueries(GetMediaQueriesCallback callback) override;
  void GetPlatformFontsForNode(int32_t node_id, GetPlatformFontsForNodeCallback callback) override;
  void GetStyleSheetText(const std::string& style_sheet_id, GetStyleSheetTextCallback callback) override;
  void SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) override;
  void SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, SetKeyframeKeyCallback callback) override;
  void SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, SetMediaTextCallback callback) override;
  void SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, SetRuleSelectorCallback callback) override;
  void SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, SetStyleSheetTextCallback callback) override;
  void SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, SetStyleTextsCallback callback) override;
  void StartRuleUsageTracking() override;
  void StopRuleUsageTracking(StopRuleUsageTrackingCallback callback) override;
  void TakeCoverageDelta(TakeCoverageDeltaCallback callback) override;

  automation::CSSClient* GetClient() const;

  String StyleSheetId(blink::CSSStyleSheet*);

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorCSSAgentImpl;

  static void CollectAllDocumentStyleSheets(
    blink::Document* document,
    blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& result);

  static void CollectStyleSheets(
    blink::CSSStyleSheet* style_sheet,
    blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& result);

  void ForcePseudoState(blink::Element* element, blink::CSSSelector::PseudoType, bool* result);
  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame);
  void MediaQueryResultChanged();
  void ActiveStyleSheetsUpdated(blink::Document* document);
  void DocumentDetached(blink::Document* document);
  void FontsUpdated(const blink::FontFace* font_face,
                    const String& src,
                    const blink::FontCustomPlatformData* font_custom);
  void SetCoverageEnabled(bool enabled);
  void WillChangeStyleElement(blink::Element* element);
  void SetActiveStyleSheets(blink::Document* document, const blink::HeapVector<blink::Member<blink::CSSStyleSheet>>& all_sheets_vector);
  void UpdateActiveStyleSheets(blink::Document* document);

  void FlushPendingProtocolNotifications();
  void Reset();

  // InspectorStyleSheetBase::Listener
  void StyleSheetChanged(InspectorStyleSheetBase*) override;

  InspectorStyleSheet* BindStyleSheet(blink::CSSStyleSheet*);
  String UnbindStyleSheet(InspectorStyleSheet*);
  automation::StyleSheetOrigin DetectOrigin(blink::CSSStyleSheet* page_style_sheet, blink::Document* owner_document);

  void CollectMediaQueriesFromStyleSheet(blink::CSSStyleSheet* style_sheet,
                                         std::vector<automation::CSSMediaPtr>* media_array);

  void CollectMediaQueriesFromRule(blink::CSSRule* rule, std::vector<automation::CSSMediaPtr>* media_array);

  automation::CSSMediaPtr BuildMediaObject(
    const blink::MediaList* media,
    MediaListSource media_list_source,
    const String& source_url,
    blink::CSSStyleSheet* parent_style_sheet);

  std::vector<automation::CSSMediaPtr> BuildMediaListChain(blink::CSSRule* rule);

  void ResourceContentLoaded();
  void WasEnabled();

  std::vector<automation::RuleMatchPtr> BuildArrayForMatchedRuleList(
    blink::CSSRuleList* rule_list,
    blink::Element* element,
    blink::PseudoId matches_for_pseudo_id);
  
  automation::CSSStylePtr BuildObjectForAttributesStyle(blink::Element* element);
  std::vector<automation::CSSKeyframesRulePtr> AnimationsForNode(blink::Element* element);
  automation::CSSRulePtr BuildObjectForRule(blink::CSSStyleRule* rule);
  InspectorStyleSheetForInlineStyle* AsInspectorStyleSheet(blink::Element* element);
  InspectorStyleSheet* InspectorStyleSheetForRule(blink::CSSStyleRule* rule);
  void CollectPlatformFontsForLayoutObject(
    blink::LayoutObject* layout_object,
    HashCountedSet<std::pair<int, String>>* font_stats);
  InspectorStyleSheet* ViaInspectorStyleSheet(blink::Document* document);
  bool AssertInspectorStyleSheetForId(const String& style_sheet_id, InspectorStyleSheet*& result);
  bool AssertStyleSheetForId(const String& style_sheet_id, InspectorStyleSheetBase*& result);
  bool SetStyleText(
    InspectorStyleSheetBase* inspector_style_sheet,
    const blink::SourceRange& range,
    const String& text,
    blink::CSSStyleDeclaration*& result);
  std::vector<automation::CSSRuleUsagePtr> TakeCoverageDeltaInternal();
  blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>> MatchingStyles(blink::Element* element);
  blink::CSSStyleDeclaration* FindEffectiveDeclaration(
    const blink::CSSProperty& property_class,
    const blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>>& styles);

  void DidAddDocument(blink::Document*) override;
  void DidRemoveDocument(blink::Document*) override;
  void DidRemoveDOMNode(blink::Node*) override;
  void DidModifyDOMAttr(blink::Element*) override;

  AutomationContext* context_;
  PageInstance* page_instance_;
  DOMDispatcher* dom_dispatcher_;
  NetworkDispatcher* network_dispatcher_;
  int32_t application_id_;
  
  mojo::AssociatedBinding<automation::CSS> binding_;
  automation::CSSClientAssociatedPtr css_client_ptr_;
  blink::Persistent<InspectorCSSAgentImpl> css_agent_impl_;

  blink::Member<blink::InspectorResourceContentLoader> resource_content_loader_;
  blink::Member<blink::InspectorResourceContainer> resource_container_;

  IdToInspectorStyleSheet id_to_inspector_style_sheet_;
  IdToInspectorStyleSheetForInlineStyle
      id_to_inspector_style_sheet_for_inline_style_;
  blink::HeapHashSet<blink::Member<blink::Document>> invalidated_documents_;

  NodeToInspectorStyleSheet node_to_inspector_style_sheet_;
  NodeIdToForcedPseudoState node_id_to_forced_pseudo_state_;

  typedef blink::HeapHashMap<blink::Member<blink::Document>,
                      blink::Member<blink::HeapHashSet<blink::Member<blink::CSSStyleSheet>>>>
      DocumentStyleSheets;
  DocumentStyleSheets document_to_css_style_sheets_;

  blink::Member<blink::StyleRuleUsageTracker> tracker_;

  blink::Member<blink::CSSStyleSheet> inspector_user_agent_style_sheet_;
  blink::HeapHashMap<blink::Member<blink::CSSStyleSheet>, blink::Member<InspectorStyleSheet>> css_style_sheet_to_inspector_style_sheet_;
  
  bool enabled_;
  bool rule_recording_enabled_;
  
  DISALLOW_COPY_AND_ASSIGN(CSSDispatcher); 
};

}

#endif