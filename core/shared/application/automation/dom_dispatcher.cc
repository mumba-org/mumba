// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/dom_dispatcher.h"

#include "core/shared/application/automation/inspector_highlight.h"

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
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/imports/html_import_child.h"
#include "third_party/blink/renderer/core/html/imports/html_import_loader.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/network/http_header_map.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/network/web_socket_handshake_request.h"
#include "third_party/blink/renderer/platform/network/web_socket_handshake_response.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_page_agent.h"
#include "third_party/blink/renderer/core/inspector/dom_editor.h"
#include "third_party/blink/renderer/core/inspector/dom_patch_support.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/inspector/resolve_node.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/line/inline_text_box.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/xml/document_xpath_evaluator.h"
#include "third_party/blink/renderer/core/xml/xpath_result.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/wtf/text/cstring.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/core/fetch/response.h"
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
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader_client.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/core/inspector/network_resources_data.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/shadow_root_v0.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/v0_insertion_point.h"
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

#include "v8/include/v8.h"

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

const size_t kMaxTextSize = 10000;
const UChar kEllipsisUChar[] = {0x2026, 0};  

String DocumentURLString(blink::Document* document) {
  if (!document || document->Url().IsNull())
    return "";
  return document->Url().GetString();
}

String DocumentBaseURLString(blink::Document* document) {
  return document->BaseURL().GetString();
}

// static
automation::ShadowRootType GetShadowRootType(blink::ShadowRoot* shadow_root) {
  switch (shadow_root->GetType()) {
    case blink::ShadowRootType::kUserAgent:
      return automation::ShadowRootType::kSHADOW_ROOT_TYPE_USER_AGENT;
    case blink::ShadowRootType::V0:
    case blink::ShadowRootType::kOpen:
      return automation::ShadowRootType::kSHADOW_ROOT_TYPE_OPEN;
    case blink::ShadowRootType::kClosed:
      return automation::ShadowRootType::kSHADOW_ROOT_TYPE_CLOSED;
  }
  NOTREACHED();
  return automation::ShadowRootType::kSHADOW_ROOT_TYPE_USER_AGENT;
}

blink::Node* NextNodeWithShadowDOMInMind(const blink::Node& current,
                                         const blink::Node* stay_within,
                                         bool include_user_agent_shadow_dom) {
  // At first traverse the subtree.

  if (blink::ShadowRoot* shadow_root = current.GetShadowRoot()) {
    if (!shadow_root->IsUserAgent() || include_user_agent_shadow_dom)
      return shadow_root;
  }
  if (current.hasChildren())
    return current.firstChild();

  // Then traverse siblings of the node itself and its ancestors.
  const blink::Node* node = &current;
  do {
    if (node == stay_within)
      return nullptr;
    if (node->IsShadowRoot()) {
      const blink::ShadowRoot* shadow_root = ToShadowRoot(node);
      blink::Element& host = shadow_root->host();
      if (host.HasChildren())
        return host.firstChild();
    }
    if (node->nextSibling())
      return node->nextSibling();
    node =
        node->IsShadowRoot() ? &ToShadowRoot(node)->host() : node->parentNode();
  } while (node);

  return nullptr;
}


blink::ShadowRoot* ShadowRootForNode(blink::Node* node, const String& type) {
  if (!node->IsElementNode())
    return nullptr;
  if (type == "a")
    return ToElement(node)->AuthorShadowRoot();
  if (type == "u")
    return ToElement(node)->UserAgentShadowRoot();
  return nullptr;
}

}

class InspectorDOMAgentImpl : public blink::InspectorDOMAgent {
public:
  InspectorDOMAgentImpl(DOMDispatcher* dispatcher): 
    blink::InspectorDOMAgent(v8::Isolate::GetCurrent(),
                             dispatcher->page_instance_->inspected_frames(),
                             nullptr),
    dispatcher_(dispatcher) {
    
  }
  
  void DomContentLoadedEventFired(blink::LocalFrame* frame) override {
    dispatcher_->DomContentLoadedEventFired(frame);
  }

  void DidCommitLoad(blink::LocalFrame* frame, blink::DocumentLoader* loader) override {
    dispatcher_->DidCommitLoad(frame, loader);
  }

  void DidInsertDOMNode(blink::Node* node) override {
    dispatcher_->DidInsertDOMNode(node);
  }

  void WillRemoveDOMNode(blink::Node* node) override {
    dispatcher_->WillRemoveDOMNode(node);
  }

  void WillModifyDOMAttr(blink::Element* element,
                         const AtomicString& old_value,
                         const AtomicString& new_value) override {
    dispatcher_->WillModifyDOMAttr(element, old_value, new_value);
  }

  void DidModifyDOMAttr(blink::Element* element,
                        const blink::QualifiedName& name,
                        const AtomicString& value) override {
    dispatcher_->DidModifyDOMAttr(element, name, value);
  }

  void DidRemoveDOMAttr(blink::Element* element, const blink::QualifiedName& name) override {
    dispatcher_->DidRemoveDOMAttr(element, name);
  }

  void StyleAttributeInvalidated(const blink::HeapVector<blink::Member<blink::Element>>& elements) override {
    dispatcher_->StyleAttributeInvalidated(elements);
  }

  void CharacterDataModified(blink::CharacterData* data) override {
    dispatcher_->CharacterDataModified(data);
  }

  void DidInvalidateStyleAttr(blink::Node* node) override {
    dispatcher_->DidInvalidateStyleAttr(node);
  }

  void DidPushShadowRoot(blink::Element* host, blink::ShadowRoot* root) override {
    dispatcher_->DidPushShadowRoot(host, root);
  }

  void WillPopShadowRoot(blink::Element* host, blink::ShadowRoot* root) override {
    dispatcher_->WillPopShadowRoot(host, root);
  }

  void DidPerformElementShadowDistribution(blink::Element* element) override {
    dispatcher_->DidPerformElementShadowDistribution(element);
  }

  void DidPerformSlotDistribution(blink::HTMLSlotElement* element) override {
    dispatcher_->DidPerformSlotDistribution(element);
  }

  void FrameDocumentUpdated(blink::LocalFrame* frame) override {
    dispatcher_->FrameDocumentUpdated(frame);
  }

  void FrameOwnerContentUpdated(blink::LocalFrame* frame, blink::HTMLFrameOwnerElement* element) override {
    dispatcher_->FrameOwnerContentUpdated(frame, element);
  }

  void PseudoElementCreated(blink::PseudoElement* element) override {
    dispatcher_->PseudoElementCreated(element);
  }

  void PseudoElementDestroyed(blink::PseudoElement* element) override {
    dispatcher_->PseudoElementDestroyed(element);
  }

private:
  
  DOMDispatcher* dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(InspectorDOMAgentImpl);
};

class InspectorRevalidateDOMTask final
    : public blink::GarbageCollectedFinalized<InspectorRevalidateDOMTask> {
 public:
  explicit InspectorRevalidateDOMTask(DOMDispatcher*);
  void ScheduleStyleAttrRevalidationFor(blink::Element*);
  void Reset() { timer_.Stop(); }
  void OnTimer(blink::TimerBase*);
  void Trace(blink::Visitor*);

 private:
  DOMDispatcher* dom_agent_;
  blink::TaskRunnerTimer<InspectorRevalidateDOMTask> timer_;
  blink::HeapHashSet<blink::Member<blink::Element>> style_attr_invalidated_elements_;
};

InspectorRevalidateDOMTask::InspectorRevalidateDOMTask(
    DOMDispatcher* dom_agent)
    : dom_agent_(dom_agent),
      timer_(
          dom_agent->GetDocument()->GetTaskRunner(blink::TaskType::kDOMManipulation),
          this,
          &InspectorRevalidateDOMTask::OnTimer) {}

void InspectorRevalidateDOMTask::ScheduleStyleAttrRevalidationFor(
  blink::Element* element) {
  style_attr_invalidated_elements_.insert(element);
  if (!timer_.IsActive())
    timer_.StartOneShot(TimeDelta(), FROM_HERE);
}

void InspectorRevalidateDOMTask::OnTimer(blink::TimerBase*) {
  // The timer is stopped on m_domAgent destruction, so this method will never
  // be called after m_domAgent has been destroyed.
  blink::HeapVector<blink::Member<blink::Element>> elements;
  for (auto& attribute : style_attr_invalidated_elements_)
    elements.push_back(attribute.Get());
  dom_agent_->StyleAttributeInvalidated(elements);
  style_attr_invalidated_elements_.clear();
}

void InspectorRevalidateDOMTask::Trace(blink::Visitor* visitor) {
  //visitor->Trace(dom_agent_);
  visitor->Trace(style_attr_invalidated_elements_);
}

// static 
DOMDispatcher* DOMDispatcher::Create(automation::DOMRequest request, PageInstance* page_instance) {
  return new DOMDispatcher(std::move(request), page_instance);
}

DOMDispatcher::DOMDispatcher(
  automation::DOMRequest request, 
  PageInstance* page_instance): 
    page_instance_(page_instance),
    application_id_(-1),
    binding_(this),
    dom_listener_(nullptr),
    document_node_to_id_map_(new NodeToIdMap()),
    last_node_id_(1),
    enabled_(false),
    suppress_attribute_modified_event_(false)  {
  
}

DOMDispatcher::DOMDispatcher(
  PageInstance* page_instance): 
    page_instance_(page_instance),
    application_id_(-1),
    binding_(this),
    dom_listener_(nullptr),
    document_node_to_id_map_(new NodeToIdMap()),
    last_node_id_(1),
    enabled_(false),
    suppress_attribute_modified_event_(false)  {
  
}

DOMDispatcher::~DOMDispatcher() {

}

blink::InspectorDOMAgent* DOMDispatcher::dom_agent() const {
  return dom_agent_impl_.Get();
}

void DOMDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&dom_client_ptr_);
}

void DOMDispatcher::BindMojo(automation::DOMAssociatedRequest request) {
  //DLOG(INFO) << "DOMDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

blink::Document* DOMDispatcher::GetDocument() const { 
  return document_.Get(); 
}

// static
blink::ShadowRoot* DOMDispatcher::UserAgentShadowRoot(blink::Node* node) {
  if (!node || !node->IsInShadowTree())
    return nullptr;

  blink::Node* candidate = node;
  while (candidate && !candidate->IsShadowRoot())
    candidate = candidate->ParentOrShadowHostNode();
  DCHECK(candidate);
  blink::ShadowRoot* shadow_root = ToShadowRoot(candidate);

  return shadow_root->IsUserAgent() ? shadow_root : nullptr;
}

// static
blink::Color DOMDispatcher::ParseColor(automation::RGBA* rgba) {
  if (!rgba)
    return blink::Color::kTransparent;

  int r = rgba->r;
  int g = rgba->g;
  int b = rgba->b;
  if (rgba->a == -1)
    return blink::Color(r, g, b);

  double a = rgba->a;
  // Clamp alpha to the [0..1] range.
  if (a < 0)
    a = 0;
  else if (a > 1)
    a = 1;

  return blink::Color(r, g, b, static_cast<int>(a * 255));
}

blink::Node* DOMDispatcher::NodeForId(int id) {
  if (!id)
    return nullptr;

  blink::HeapHashMap<int, blink::Member<blink::Node>>::iterator it = id_to_node_.find(id);
  if (it != id_to_node_.end())
    return it->value;
  return nullptr;
}

void DOMDispatcher::Disable() {
  enabled_ = false;
  page_instance_->probe_sink()->removeInspectorDOMAgent(dom_agent_impl_.Get());
}

void DOMDispatcher::Enable() {
  //DLOG(INFO) << "DOMDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  InnerEnable();
}

void DOMDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void DOMDispatcher::InnerEnable() {
  enabled_ = true;
}

void DOMDispatcher::DiscardSearchResults(const std::string& search_id) {
  search_results_.erase(String::FromUTF8(search_id.data()));
}

void DOMDispatcher::CollectClassNamesFromSubtree(int32_t node_id, CollectClassNamesFromSubtreeCallback callback) {
  HashSet<String> unique_names;
  std::vector<std::string> class_names;
  blink::Node* parent_node = NodeForId(node_id);
  if (!parent_node ||
      (!parent_node->IsElementNode() && !parent_node->IsDocumentNode() &&
       !parent_node->IsDocumentFragment())) {
    //DLOG(ERROR) << "No suitable node with given id found";
    std::move(callback).Run(std::vector<std::string>());
    return;
  }

  for (blink::Node* node = parent_node; node;
       node = blink::FlatTreeTraversal::Next(*node, parent_node)) {
    if (node->IsElementNode()) {
      const blink::Element& element = ToElement(*node);
      if (!element.HasClass())
        continue;
      const blink::SpaceSplitString& class_name_list = element.ClassNames();
      for (unsigned i = 0; i < class_name_list.size(); ++i)
        unique_names.insert(class_name_list[i]);
    }
  }
  for (const String& class_name : unique_names) {
    class_names.push_back(std::string(class_name.Utf8().data(), class_name.length()));
  }
  std::move(callback).Run(std::move(class_names));
}

void DOMDispatcher::CopyTo(int32_t node_id, int32_t target_element_id, int32_t anchor_node_id, CopyToCallback callback) {
  blink::Node* node = nullptr;
  bool editable = AssertEditableNode(node_id, node);
  if (!editable) {
    std::move(callback).Run(-1);
    return;
  }

  blink::Element* target_element = nullptr;
  bool editable_element = AssertEditableElement(target_element_id, target_element);
  if (!editable_element) {
    std::move(callback).Run(-1);
    return;
  }

  blink::Node* anchor_node = nullptr;
  if (anchor_node_id != 0) {
    bool editable_element = AssertEditableChildNode(target_element,
                                                    anchor_node_id, anchor_node);
    if (!editable_element) {
      std::move(callback).Run(-1);
      return;
    }
  }

  // The clone is deep by default.
  blink::Node* cloned_node = node->cloneNode(true);
  if (!cloned_node) {
    //DLOG(INFO) << "Failed to clone node";
    std::move(callback).Run(-1);
    return;
  }
  blink::protocol::Response response =
      dom_editor_->InsertBefore(target_element, cloned_node, anchor_node);
  if (!response.isSuccess()) {
    return;
  }

  int new_node_id = PushNodePathToFrontend(cloned_node);
  std::move(callback).Run(new_node_id);
}

void DOMDispatcher::DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, DescribeNodeCallback callback) {
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, backend_node_id, object_id, node);
  if (!have_node) {
    std::move(callback).Run(nullptr);
    return;
  }
  if (!node) {
    //DLOG(ERROR) << "Node not found";
    std::move(callback).Run(nullptr);
    return;
  }
  automation::DOMNodePtr result = 
    BuildObjectForNode(node, depth, pierce, nullptr, nullptr);
  std::move(callback).Run(std::move(result)); 
}

void DOMDispatcher::Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, backend_node_id, object_id, node);
  if (!have_node) {
    return;
  }
  if (!node->IsElementNode()) {
    //DLOG(ERROR) << "Node is not an Element";
    return;
  }
  blink::Element* element = ToElement(node);
  element->GetDocument().UpdateStyleAndLayoutIgnorePendingStylesheets();
  if (!element->IsFocusable()) {
    //DLOG(ERROR) << "Element is not focusable";
    return;
  }
  element->focus();
}

void DOMDispatcher::GetAttributes(int32_t node_id, GetAttributesCallback callback) {
  blink::Element* element = nullptr;
  bool have_element = AssertElement(node_id, element);
  if (!have_element) {
    std::move(callback).Run(std::vector<std::string>());
    return;
  }

  std::move(callback).Run(BuildArrayForElementAttributes(element));
}

void DOMDispatcher::GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetBoxModelCallback callback) {
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, backend_node_id, object_id, node);
  if (!have_node) {
    std::move(callback).Run(nullptr);
    return;
  }

  automation::BoxModelPtr model = InspectorHighlight::GetBoxModel(node);
  if (!model) {
    //DLOG(ERROR) << "Could not compute box model.";
    return;
  }
  std::move(callback).Run(std::move(model));
}

void DOMDispatcher::GetDocument(int32_t depth, bool pierce, GetDocumentCallback callback) {
  automation::DOMNodePtr root = GetDocumentInternal(depth, pierce);
  std::move(callback).Run(std::move(root));
}

automation::DOMNodePtr DOMDispatcher::GetDocumentInternal(int32_t depth, bool pierce) {
  if (!enabled_)
    InnerEnable();

  if (!document_) {
    //DLOG(ERROR) << "Document is not available";
    return nullptr;
  }

  DiscardFrontendBindings();

  int sanitized_depth = depth;
  if (sanitized_depth == -1)
    sanitized_depth = INT_MAX;

  automation::DOMNodePtr root = BuildObjectForNode(document_.Get(), 
                                sanitized_depth,
                                pierce,
                                document_node_to_id_map_.Get());
  return root;
}

void DOMDispatcher::GetFlattenedDocument(int32_t depth, bool pierce, GetFlattenedDocumentCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "DOM agent hasn't been enabled";
    std::move(callback).Run(std::vector<automation::DOMNodePtr>());
    return;
  }

  if (!document_) {
    //DLOG(ERROR) << "Document is not available";
    std::move(callback).Run(std::vector<automation::DOMNodePtr>());
  }

  DiscardFrontendBindings();

  int sanitized_depth = depth;
  if (sanitized_depth == -1)
    sanitized_depth = INT_MAX;

  std::vector<automation::DOMNodePtr> nodes;
  nodes.push_back(
    BuildObjectForNode(
      document_.Get(), 
      sanitized_depth, 
      pierce,
      document_node_to_id_map_.Get(), 
      &nodes));
  std::move(callback).Run(std::move(nodes));
}

void DOMDispatcher::GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, GetNodeForLocationCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "DOM agent hasn't been enabled";
    std::move(callback).Run(-1);
  }
  bool ok = PushDocumentUponHandlelessOperation();
  if (!ok) {
    std::move(callback).Run(-1);
  }
  blink::LayoutPoint document_point(x, y);
  blink::HitTestRequest request(blink::HitTestRequest::kMove | 
                                blink::HitTestRequest::kReadOnly |
                                blink::HitTestRequest::kAllowChildFrameContent);
  blink::HitTestResult result(request,
                       document_->View()->DocumentToAbsolute(document_point));
  document_->GetFrame()->ContentLayoutObject()->HitTest(result);
  if (!include_user_agent_shadow_dom)
    result.SetToShadowHostIfInRestrictedShadowRoot();
  blink::Node* node = result.InnerPossiblyPseudoNode();
  while (node && node->getNodeType() == blink::Node::kTextNode) {
    node = node->parentNode();
  }
  if (!node) {
    //DLOG(ERROR) << "No node found at given location";
    std::move(callback).Run(-1);
  }
  int node_id = PushNodePathToFrontend(node);
  std::move(callback).Run(node_id);
}

void DOMDispatcher::GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetOuterHTMLCallback callback) {
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, backend_node_id, object_id, node);
  if (!have_node) {
    //DLOG(ERROR) << "No node found for id " << node_id;
    std::move(callback).Run(std::string());
    return;
  }
  String outer_html = blink::CreateMarkup(node);
  std::move(callback).Run(std::string(outer_html.Utf8().data(), outer_html.length()));
}

void DOMDispatcher::GetRelayoutBoundary(int32_t node_id, GetRelayoutBoundaryCallback callback) {
  blink::Node* node = nullptr;
  bool node_exists = AssertNode(node_id, node);
  if (!node_exists) {
    //DLOG(ERROR) << "No node found for id " << node_id;
    std::move(callback).Run(-1);
    return;
  }
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object) {
    //DLOG(ERROR) << "No layout object for node, perhaps orphan or hidden node";
    std::move(callback).Run(-1);
    return;
  }
  while (layout_object && !layout_object->IsDocumentElement() &&
         !layout_object->IsRelayoutBoundaryForInspector())
    layout_object = layout_object->Container();
  blink::Node* result_node =
      layout_object ? layout_object->GeneratingNode() : node->ownerDocument();
  int relayout_boundary_node_id = PushNodePathToFrontend(result_node);
  std::move(callback).Run(relayout_boundary_node_id);
}

void DOMDispatcher::HideHighlight() {
  //DLOG(ERROR) << "DOM dispatcher: HideHighlight not implemented";
}

void DOMDispatcher::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) {
  //DLOG(ERROR) << "DOM dispatcher: HighlightNode not implemented";
}

void DOMDispatcher::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  //DLOG(ERROR) << "DOM dispatcher: HighlightRect not implemented";
}

void DOMDispatcher::MarkUndoableState() {
  history_->MarkUndoableState();
}

void DOMDispatcher::MoveTo(int32_t node_id, int32_t target_element_id, int32_t anchor_node_id, MoveToCallback callback) {
  blink::Node* node = nullptr;
  bool node_editable = AssertEditableNode(node_id, node);
  if (!node_editable) {
    //DLOG(ERROR) << "Node with id " << node_id << " not editable";
    std::move(callback).Run(-1);
    return;
  }

  blink::Element* target_element = nullptr;
  bool element_editable = AssertEditableElement(target_element_id, target_element);
  if (!element_editable) {
    //DLOG(ERROR) << "Element with id " << target_element_id << " not editable";
    std::move(callback).Run(-1);
    return;
  }

  blink::Node* current = target_element;
  while (current) {
    if (current == node) {
      //DLOG(ERROR) << "Unable to move node into self or descendant";
      std::move(callback).Run(-1);
      return;
    }
    current = current->parentNode();
  }

  blink::Node* anchor_node = nullptr;
  if (anchor_node_id != -1) {
    bool child_editable = AssertEditableChildNode(target_element,
                                                  anchor_node_id, anchor_node);
    if (!child_editable) {
      //DLOG(ERROR) << "Child node of anchor node with id " << anchor_node_id << " is not editable";
      std::move(callback).Run(-1);
      return;
    }
  }

  blink::protocol::Response response = dom_editor_->InsertBefore(target_element, node, anchor_node);
  if (!response.isSuccess()) {
    //DLOG(ERROR) << "Unable to rearange node";
    std::move(callback).Run(-1);
    return;
  }

  int new_node_id = PushNodePathToFrontend(node);
  std::move(callback).Run(new_node_id);
}

void DOMDispatcher::PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, PerformSearchCallback callback) {
   String search_id;
   int result_count = 0;
   
   if (!enabled_) {
    //DLOG(ERROR) << "DOM agent is not enabled";
    std::move(callback).Run(std::string(), -1);
    return;
   }

  // FIXME: Few things are missing here:
  // 1) Search works with node granularity - number of matches within node is
  //    not calculated.
  // 2) There is no need to push all search results to the front-end at a time,
  //    pushing next / previous result is sufficient.
  String whitespace_trimmed_query = String::FromUTF8(query.data());
  unsigned query_length = whitespace_trimmed_query.length();
  bool start_tag_found = !whitespace_trimmed_query.find('<');
  bool end_tag_found = whitespace_trimmed_query.ReverseFind('>') + 1 == query_length;
  bool start_quote_found = !whitespace_trimmed_query.find('"');
  bool end_quote_found = whitespace_trimmed_query.ReverseFind('"') + 1 == query_length;
  bool exact_attribute_match = start_quote_found && end_quote_found;

  String tag_name_query = whitespace_trimmed_query;
  String attribute_query = whitespace_trimmed_query;
  if (start_tag_found)
    tag_name_query = tag_name_query.Right(tag_name_query.length() - 1);
  if (end_tag_found)
    tag_name_query = tag_name_query.Left(tag_name_query.length() - 1);
  if (start_quote_found)
    attribute_query = attribute_query.Right(attribute_query.length() - 1);
  if (end_quote_found)
    attribute_query = attribute_query.Left(attribute_query.length() - 1);

  blink::HeapVector<blink::Member<blink::Document>> docs = Documents();
  blink::HeapListHashSet<blink::Member<blink::Node>> result_collector;

  for (blink::Document* document : docs) {
    blink::Node* document_element = document->documentElement();
    blink::Node* node = document_element;
    if (!node)
      continue;

    // Manual plain text search.
    for (; node; node = NextNodeWithShadowDOMInMind(*node, document_element, include_user_agent_shadow_dom)) {
      switch (node->getNodeType()) {
        case blink::Node::kTextNode:
        case blink::Node::kCommentNode:
        case blink::Node::kCdataSectionNode: {
          String text = node->nodeValue();
          if (text.FindIgnoringCase(whitespace_trimmed_query) != kNotFound)
            result_collector.insert(node);
          break;
        }
        case blink::Node::kElementNode: {
          if ((!start_tag_found && !end_tag_found &&
               (node->nodeName().FindIgnoringCase(tag_name_query) !=
                kNotFound)) ||
              (start_tag_found && end_tag_found &&
               DeprecatedEqualIgnoringCase(node->nodeName(), tag_name_query)) ||
              (start_tag_found && !end_tag_found &&
               node->nodeName().StartsWithIgnoringCase(tag_name_query)) ||
              (!start_tag_found && end_tag_found &&
               node->nodeName().EndsWithIgnoringCase(tag_name_query))) {
            result_collector.insert(node);
            break;
          }
          // Go through all attributes and serialize them.
          const blink::Element* element = ToElement(node);
          blink::AttributeCollection attributes = element->Attributes();
          for (auto& attribute : attributes) {
            // Add attribute pair
            if (attribute.LocalName().FindIgnoringCase(whitespace_trimmed_query,
                                                       0) != kNotFound) {
              result_collector.insert(node);
              break;
            }
            size_t found_position =
                attribute.Value().FindIgnoringCase(attribute_query, 0);
            if (found_position != kNotFound) {
              if (!exact_attribute_match ||
                  (!found_position &&
                   attribute.Value().length() == attribute_query.length())) {
                result_collector.insert(node);
                break;
              }
            }
          }
          break;
        }
        default:
          break;
      }
    }

    // XPath evaluation
    for (blink::Document* document : docs) {
      DCHECK(document);
      blink::DummyExceptionStateForTesting exception_state;
      blink::XPathResult* result = blink::DocumentXPathEvaluator::evaluate(
          *document, whitespace_trimmed_query, document, nullptr,
          blink::XPathResult::kOrderedNodeSnapshotType, blink::ScriptValue(),
          exception_state);
      if (exception_state.HadException() || !result)
        continue;

      unsigned long size = result->snapshotLength(exception_state);
      for (unsigned long i = 0; !exception_state.HadException() && i < size;
           ++i) {
        blink::Node* node = result->snapshotItem(i, exception_state);
        if (exception_state.HadException())
          break;

        if (node->getNodeType() == blink::Node::kAttributeNode)
          node = ToAttr(node)->ownerElement();
        result_collector.insert(node);
      }
    }

    // Selector evaluation
    for (blink::Document* document : docs) {
      blink::DummyExceptionStateForTesting exception_state;
      blink::StaticElementList* element_list = document->QuerySelectorAll(
          AtomicString(whitespace_trimmed_query), exception_state);
      if (exception_state.HadException() || !element_list)
        continue;

      unsigned size = element_list->length();
      for (unsigned i = 0; i < size; ++i)
        result_collector.insert(element_list->item(i));
    }
  }

  search_id = blink::IdentifiersFactory::CreateIdentifier();
  blink::HeapVector<blink::Member<blink::Node>>* results_it =
      &search_results_.insert(search_id, blink::HeapVector<blink::Member<blink::Node>>())
           .stored_value->value;

  for (auto& result : result_collector)
    results_it->push_back(result);

  result_count = results_it->size();

  std::move(callback).Run(std::string(search_id.Utf8().data(), search_id.length()), result_count);
}

void DOMDispatcher::GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, GetSearchResultsCallback callback) {
  std::vector<int> node_ids;
  SearchResults::iterator it = search_results_.find(String::FromUTF8(search_id.data()));
  if (it == search_results_.end()) {
    //DLOG(ERROR) << "No search session with given id found";
    std::move(callback).Run(std::move(node_ids));
    return;
  }

  int size = it->value.size();
  if (from_index < 0 || to_index > size || from_index >= to_index) {
    //DLOG(ERROR) << "Invalid search result range";
    std::move(callback).Run(std::move(node_ids));
    return;
  }

  for (int i = from_index; i < to_index; ++i) {
    node_ids.push_back(PushNodePathToFrontend((it->value)[i].Get()));
  }
  std::move(callback).Run(std::move(node_ids));
}

void DOMDispatcher::PushNodeByPathToFrontend(const std::string& path, PushNodeByPathToFrontendCallback callback) {
  int node_id = -1;
  if (!enabled_) {
    //DLOG(ERROR) << "DOM agent is not enabled";
    std::move(callback).Run(node_id);
    return;
  }
  if (blink::Node* node = NodeForPath(String::FromUTF8(path.data()))) {
    node_id = PushNodePathToFrontend(node);
  } else {
    //DLOG(ERROR) << "No node with given path found";
    std::move(callback).Run(node_id);
    return;
  }
  std::move(callback).Run(node_id);
}

void DOMDispatcher::PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, PushNodesByBackendIdsToFrontendCallback callback) {
  std::vector<int> result;
  if (!enabled_) {
    //DLOG(ERROR) << "DOM agent is not enabled";
    std::move(callback).Run(std::move(result));
    return;
  }
  for (size_t index = 0; index < backend_node_ids.size(); ++index) {
    blink::Node* node = blink::DOMNodeIds::NodeForId(backend_node_ids[index]);
    if (node && node->GetDocument().GetFrame() &&
        page_instance_->inspected_frames()->Contains(node->GetDocument().GetFrame())) {
      result.push_back(PushNodePathToFrontend(node));
    } else {
      result.push_back(0);
    }
  }
  std::move(callback).Run(std::move(result));
}

void DOMDispatcher::QuerySelector(int32_t node_id, const std::string& selectors, QuerySelectorCallback callback) {
  int element_id = 0;
  blink:: Node* node = nullptr;
  bool have_node = AssertNode(node_id, node);
  if (!have_node) {
    //DLOG(ERROR) << "Node with id " << node_id << " does not exists";
    std::move(callback).Run(-1);
    return;
  }
  
  if (!node || !node->IsContainerNode()) {
    //DLOG(ERROR) << "Not a container node";
    std::move(callback).Run(-1);
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  blink::Element* element = ToContainerNode(node)->QuerySelector(
      AtomicString(selectors.data()), exception_state);
  if (exception_state.HadException()) {
    //DLOG(ERROR) << "DOM Error while querying";
    std::move(callback).Run(-1);
  }

  if (element) {
    element_id = PushNodePathToFrontend(element);
  }
  std::move(callback).Run(element_id);
}

void DOMDispatcher::QuerySelectorAll(int32_t node_id, const std::string& selectors, QuerySelectorAllCallback callback) {
  std::vector<int> result;
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, node);
  if (!have_node) {
    //DLOG(ERROR) << "Node with id " << node_id << " does not exists";
    std::move(callback).Run(std::move(result));
    return;
  }
  if (!node || !node->IsContainerNode()) {
    //DLOG(ERROR) << "Not a container node";
    std::move(callback).Run(std::move(result));
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  blink::StaticElementList* elements = ToContainerNode(node)->QuerySelectorAll(
      AtomicString(selectors.data()), exception_state);
  if (exception_state.HadException()) {
    //DLOG(ERROR) << "DOM Error while querying";
    std::move(callback).Run(std::move(result));
    return;
  }

  for (unsigned i = 0; i < elements->length(); ++i) {
    result.push_back(PushNodePathToFrontend(elements->item(i)));
  }
  std::move(callback).Run(std::move(result));
}

void DOMDispatcher::Redo() {
  if (!enabled_) {
    //DLOG(ERROR) << "DOM dispatcher is not enabled";
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  history_->Redo(exception_state);
}

void DOMDispatcher::RemoveAttribute(int32_t node_id, const std::string& name) {
  blink::Element* element = nullptr;
  bool editable = AssertEditableElement(node_id, element);
  if (!editable) {
    //DLOG(ERROR) << "Node with id " << node_id << " not editable";
    return;
  }
  dom_editor_->RemoveAttribute(element, String::FromUTF8(name.data()));
}

void DOMDispatcher::RemoveNode(int32_t node_id) {
  blink::Node* node = nullptr;
  bool editable = AssertEditableNode(node_id, node);
  if (!editable) {
    //DLOG(ERROR) << "Node with id " << node_id << " not editable";
    return;
  }
  blink::ContainerNode* parent_node = node->parentNode();
  if (!parent_node) {
    //DLOG(ERROR) << "Cannot remove detached node";
    return;
  }
  dom_editor_->RemoveChild(parent_node, node);
}

void DOMDispatcher::RequestChildNodes(int32_t node_id, int32_t depth, bool maybe_taverse_frames) {
  int sanitized_depth = depth;
  
  if (sanitized_depth == 0 || sanitized_depth < -1) {
    //DLOG(ERROR) <<
    //    "Please provide a positive integer as a depth or -1 for entire "
    //    "subtree";
    return;
  }
  
  if (sanitized_depth == -1) {
    sanitized_depth = INT_MAX;
  }

  PushChildNodesToFrontend(node_id, sanitized_depth, maybe_taverse_frames);
}

void DOMDispatcher::RequestNode(const std::string& object_id, RequestNodeCallback callback) {
  blink::Node* node = nullptr;
  bool found = NodeForRemoteObjectId(String::FromUTF8(object_id.data()), node);
  if (!found) {
    std::move(callback).Run(-1);
    return;
  }
  std::move(callback).Run(PushNodePathToFrontend(node));
}

void DOMDispatcher::ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, ResolveNodeCallback callback) {
  //DLOG(ERROR) << "ResolveNode: remote javascript objects are not implemented";
  // String object_group_name = String::FromUTF8(object_group.value_or("").data());
  // blink::Node* node = nullptr;

  // if (node_id.has_value() == backend_node_id.has_value()) {
  //   //DLOG(ERROR) << "Either nodeId or backendNodeId must be specified.";
  //   return;
  // }

  // if (node_id.has_value())
  //   node = NodeForId(node_id.fromJust());
  // else
  //   node = DOMNodeIds::NodeForId(backend_node_id.fromJust());

  // if (!node) {
  //   //DLOG(ERROR) << "No node with given id found";
  //   return;
  // }
  // *result = ResolveNode(v8_session_, node, object_group_name);
  // if (!*result) {
  //   //DLOG(ERROR) << "Node with given id does not belong to the document";
  //   return;
  // }
  std::move(callback).Run(nullptr);
}

void DOMDispatcher::SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) {
  blink::Element* element = nullptr;
  bool editable = AssertEditableElement(node_id, element);
  if (!editable) {
    //DLOG(ERROR) << "Node with id " << node_id << " not found";
    return;
  }
  dom_editor_->SetAttribute(element, String::FromUTF8(name.data()), String::FromUTF8(value.data()));
}

void DOMDispatcher::SetAttributesAsText(int32_t element_id, const std::string& text, const base::Optional<std::string>& name) {
  blink::Element* element = nullptr;
  String name_str = String::FromUTF8(name.value_or("").data());
  bool is_editable = AssertEditableElement(element_id, element);
  if (!is_editable) {
    //DLOG(ERROR) << "Node " << element_id << " is not editable";
    return;
  }

  String markup = "<span " + String::FromUTF8(text.data()) + "></span>";
  blink::DocumentFragment* fragment = element->GetDocument().createDocumentFragment();

  bool should_ignore_case =
      element->GetDocument().IsHTMLDocument() && element->IsHTMLElement();
  // Not all elements can represent the context (i.e. IFRAME), hence using
  // document.body.
  if (should_ignore_case && element->GetDocument().body())
    fragment->ParseHTML(markup, element->GetDocument().body(),
                        blink::kAllowScriptingContent);
  else
    fragment->ParseXML(markup, nullptr, blink::kAllowScriptingContent);

  blink::Element* parsed_element =
      fragment->firstChild() && fragment->firstChild()->IsElementNode()
          ? ToElement(fragment->firstChild())
          : nullptr;
  if (!parsed_element) {
    //DLOG(ERROR) << "Could not parse value as attributes";
    return;
  }

  String case_adjusted_name = should_ignore_case
                                  ? name_str.DeprecatedLower()
                                  : name_str;

  blink::AttributeCollection attributes = parsed_element->Attributes();
  if (attributes.IsEmpty() && name.has_value()) {
    dom_editor_->RemoveAttribute(element, case_adjusted_name);
    return;
  }

  bool found_original_attribute = false;
  for (auto& attribute : attributes) {
    // Add attribute pair
    String attribute_name = attribute.GetName().ToString();
    if (should_ignore_case)
      attribute_name = attribute_name.DeprecatedLower();
    found_original_attribute |=
        name.has_value() && attribute_name == case_adjusted_name;
    blink::protocol::Response response =
        dom_editor_->SetAttribute(element, attribute_name, attribute.Value());
    if (!response.isSuccess()) {
      //DLOG(ERROR) << "Failed setting attribute " << attribute_name;
      return;
    }
  }

  if (!found_original_attribute && name.has_value() &&
      !name_str.StripWhiteSpace().IsEmpty()) {
    dom_editor_->RemoveAttribute(element, case_adjusted_name);
  }
}

void DOMDispatcher::SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  blink::Node* node = nullptr;
  bool have_node = AssertNode(node_id, backend_node_id, object_id, node);
  if (!have_node) {
    //DLOG(ERROR) << "Node with id " << node_id << " does not exists";
    return;
  }
  if (!IsHTMLInputElement(*node) ||
      ToHTMLInputElement(*node).type() != blink::InputTypeNames::file) {
    //DLOG(ERROR) << "Node is not a file input element";
    return;
  }

  Vector<String> paths;
  for (size_t index = 0; index < files.size(); ++index) {
    paths.push_back(String::FromUTF8(files[index].data()));
  }
  ToHTMLInputElement(node)->SetFilesFromPaths(paths);
}

void DOMDispatcher::SetInspectedNode(int32_t node_id) {
  //DLOG(ERROR) << "SetInspectedNode is not implemented/ not of interest";
}

void DOMDispatcher::SetNodeName(int32_t node_id, const std::string& tag_name, SetNodeNameCallback callback) {
  blink::protocol::Response response;
  int new_id = 0;
  blink::Element* old_element = nullptr;
  bool have_element = AssertElement(node_id, old_element);
  if (!have_element) {
    //DLOG(ERROR) << "Node " << node_id << " does not exists";
    std::move(callback).Run(-1);
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  blink::Element* new_elem = old_element->GetDocument().CreateElementForBinding(
      AtomicString(tag_name.data()), exception_state);
  if (exception_state.HadException()) {
    //DLOG(ERROR) << "Error creating tag " << tag_name << " for node " << node_id;
    std::move(callback).Run(-1);
    return;
  }

  // Copy over the original node's attributes.
  new_elem->CloneAttributesFrom(*old_element);

  // Copy over the original node's children.
  for (blink::Node* child = old_element->firstChild(); child;
       child = old_element->firstChild()) {
    response = dom_editor_->InsertBefore(new_elem, child, nullptr);
    if (!response.isSuccess()) {
      //DLOG(ERROR) << "Error while updating children";
      std::move(callback).Run(-1);
      return;
    }
  }

  // Replace the old node with the new node
  blink::ContainerNode* parent = old_element->parentNode();
  response =
      dom_editor_->InsertBefore(parent, new_elem, old_element->nextSibling());
  if (!response.isSuccess()) {
    //DLOG(ERROR) << "Error while updating node";
    std::move(callback).Run(-1);
    return;
  }
  response = dom_editor_->RemoveChild(parent, old_element);
  if (!response.isSuccess()) {
    //DLOG(ERROR) << "Error while updating node";
    std::move(callback).Run(-1);
    return;
  }

  new_id = PushNodePathToFrontend(new_elem);
  if (children_requested_.Contains(node_id))
    PushChildNodesToFrontend(new_id);

  std::move(callback).Run(new_id);
}

void DOMDispatcher::SetNodeValue(int32_t node_id, const std::string& value) {
  blink::Node* node = nullptr;
  bool editable = AssertEditableNode(node_id, node);
  if (!editable) {
    //DLOG(ERROR) << "Node " << node_id << " is not editable or does not exists";
    return;
  }

  if (node->getNodeType() != blink::Node::kTextNode) {
    return; //DLOG(ERROR) << "Can only set value of text nodes";
  }

  dom_editor_->ReplaceWholeText(ToText(node), String::FromUTF8(value.data()));
}

void DOMDispatcher::SetOuterHTML(int32_t node_id, const std::string& outer_html) {
  if (!node_id) {
    DCHECK(document_);
    blink::DOMPatchSupport dom_patch_support(dom_editor_.Get(), *document_.Get());
    dom_patch_support.PatchDocument(String::FromUTF8(outer_html.data()));
    return;
  }

  blink::Node* node = nullptr;
  bool editable = AssertEditableNode(node_id, node);
  if (!editable) {
    //DLOG(ERROR) << "Node " << node_id << " is not editable";
    return;
  }

  blink::Document* document =
      node->IsDocumentNode() ? ToDocument(node) : node->ownerDocument();
  if (!document || (!document->IsHTMLDocument() && !document->IsXMLDocument())) {
    //DLOG(ERROR) << "Not an HTML/XML document";
    return;
  }

  blink::Node* new_node = nullptr;
  blink::protocol::Response response = dom_editor_->SetOuterHTML(node, String::FromUTF8(outer_html.data()), &new_node);
  if (!response.isSuccess())
    return;

  if (!new_node) {
    // The only child node has been deleted.
    return;
  }

  int new_id = PushNodePathToFrontend(new_node);

  bool children_requested = children_requested_.Contains(node_id);
  if (children_requested)
    PushChildNodesToFrontend(new_id);
}

void DOMDispatcher::Undo() {
  if (!enabled_) {
    //DLOG(ERROR) << "DOM dispatcher is not enabled";
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  history_->Undo(exception_state);
}

void DOMDispatcher::GetFrameOwner(const std::string& frame_id, GetFrameOwnerCallback callback) {
  blink::Frame* frame = page_instance_->inspected_frames()->Root();
  String frame_id_str = String::FromUTF8(frame_id.data());
  for (; frame; frame = frame->Tree().TraverseNext(page_instance_->inspected_frames()->Root())) {
    if (blink::IdentifiersFactory::FrameId(frame) == frame_id_str)
      break;
  }
  if (!frame || !frame->Owner()->IsLocal()) {
    //DLOG(ERROR) << "Frame with given id does not belong to target.";
    std::move(callback).Run(-1);
    return;
  }
  blink::HTMLFrameOwnerElement* frame_owner = ToHTMLFrameOwnerElement(frame->Owner());
  if (!frame_owner) {
    //DLOG(ERROR) << "No iframe owner for given node";
    std::move(callback).Run(-1);
    return;
  }
  int node_id = PushNodePathToFrontend(frame_owner, document_node_to_id_map_.Get());
  std::move(callback).Run(node_id);
  return;
}


void DOMDispatcher::SetDOMListener(DOMListener* listener) {
  dom_listener_ = listener;
}

automation::DOMClient* DOMDispatcher::GetClient() const {
  return dom_client_ptr_.get();
}

// events

void DOMDispatcher::DomContentLoadedEventFired(blink::LocalFrame* frame) {
  //DLOG(INFO) << "DOMDispatcher::DomContentLoadedEventFired";
  if (frame != page_instance_->inspected_frames()->Root())
    return;

  // Re-push document once it is loaded.
  DiscardFrontendBindings();
  if (enabled_)
    GetClient()->OnDocumentUpdated();
}

void DOMDispatcher::InvalidateFrameOwnerElement(blink::HTMLFrameOwnerElement* frame_owner) {
  if (!frame_owner)
    return;

  int frame_owner_id = document_node_to_id_map_->at(frame_owner);
  if (!frame_owner_id)
    return;

  // Re-add frame owner element together with its new children.
  int parent_id = document_node_to_id_map_->at(InnerParentNode(frame_owner));
  GetClient()->OnChildNodeRemoved(parent_id, frame_owner_id);
  Unbind(frame_owner, document_node_to_id_map_.Get());

  automation::DOMNodePtr value =
      BuildObjectForNode(frame_owner, 0, false, document_node_to_id_map_.Get(), nullptr);
  blink::Node* previous_sibling = InnerPreviousSibling(frame_owner);
  int prev_id =
      previous_sibling ? document_node_to_id_map_->at(previous_sibling) : 0;
  GetClient()->OnChildNodeInserted(parent_id, prev_id, std::move(value));
}

void DOMDispatcher::DidCommitLoad(blink::LocalFrame* frame, blink::DocumentLoader* loader) {
  blink::Document* document = loader->GetFrame()->GetDocument();
  if (dom_listener_)
    dom_listener_->DidAddDocument(document);

  blink::LocalFrame* inspected_frame = page_instance_->inspected_frames()->Root();
  if (loader->GetFrame() != inspected_frame) {
    InvalidateFrameOwnerElement(
        loader->GetFrame()->GetDocument()->LocalOwner());
    return;
  }

  SetDocument(inspected_frame->GetDocument());
}

void DOMDispatcher::SetDocument(blink::Document* doc) {
  if (doc == document_.Get())
    return;

  DiscardFrontendBindings();
  document_ = doc;

  if (!enabled_)
    return;

  // Immediately communicate 0 document or document that has finished loading.
  if (!doc || !doc->Parsing())
    GetClient()->OnDocumentUpdated();
}

void DOMDispatcher::DidInsertDOMNode(blink::Node* node) {
  if (IsWhitespace(node))
    return;

  // We could be attaching existing subtree. Forget the bindings.
  Unbind(node, document_node_to_id_map_.Get());

  blink::ContainerNode* parent = node->parentNode();
  if (!parent)
    return;
  int parent_id = document_node_to_id_map_->at(parent);
  // Return if parent is not mapped yet.
  if (!parent_id)
    return;

  if (!children_requested_.Contains(parent_id)) {
    // No children are mapped yet -> only notify on changes of child count.
    int count = cached_child_count_.at(parent_id) + 1;
    cached_child_count_.Set(parent_id, count);
    GetClient()->OnChildNodeCountUpdated(parent_id, count);
  } else {
    // Children have been requested -> return value of a new child.
    blink::Node* prev_sibling = InnerPreviousSibling(node);
    int prev_id = prev_sibling ? document_node_to_id_map_->at(prev_sibling) : 0;
    automation::DOMNodePtr value = BuildObjectForNode(node, 0, false, document_node_to_id_map_.Get(), nullptr);
    GetClient()->OnChildNodeInserted(parent_id, prev_id, std::move(value));
  }
}

void DOMDispatcher::WillRemoveDOMNode(blink::Node* node) {
  if (IsWhitespace(node))
    return;

  blink::ContainerNode* parent = node->parentNode();

  // If parent is not mapped yet -> ignore the event.
  if (!document_node_to_id_map_->Contains(parent))
    return;

  int parent_id = document_node_to_id_map_->at(parent);

  if (!children_requested_.Contains(parent_id)) {
    // No children are mapped yet -> only notify on changes of child count.
    int count = cached_child_count_.at(parent_id) - 1;
    cached_child_count_.Set(parent_id, count);
    GetClient()->OnChildNodeCountUpdated(parent_id, count);
  } else {
    GetClient()->OnChildNodeRemoved(parent_id,
                                    document_node_to_id_map_->at(node));
  }
  Unbind(node, document_node_to_id_map_.Get());
}

void DOMDispatcher::WillModifyDOMAttr(blink::Element* element,
                                      const AtomicString& old_value,
                                      const AtomicString& new_value) {
  suppress_attribute_modified_event_ = (old_value == new_value);
}

void DOMDispatcher::DidModifyDOMAttr(blink::Element* element,
                                     const blink::QualifiedName& name,
                                     const AtomicString& value) {
  bool should_suppress_event = suppress_attribute_modified_event_;
  suppress_attribute_modified_event_ = false;
  if (should_suppress_event)
    return;

  int id = BoundNodeId(element);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  if (dom_listener_)
    dom_listener_->DidModifyDOMAttr(element);

  GetClient()->OnAttributeModified(id, std::string(name.ToString().Utf8().data()), std::string(value.Utf8().data(), value.length()));
}

void DOMDispatcher::DidRemoveDOMAttr(blink::Element* element, const blink::QualifiedName& name) {
  int id = BoundNodeId(element);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  if (dom_listener_)
    dom_listener_->DidModifyDOMAttr(element);

  GetClient()->OnAttributeRemoved(id, std::string(name.ToString().Utf8().data()));
}

void DOMDispatcher::StyleAttributeInvalidated(const blink::HeapVector<blink::Member<blink::Element>>& elements) {
  std::vector<int> node_ids;
  for (unsigned i = 0, size = elements.size(); i < size; ++i) {
    blink::Element* element = elements.at(i);
    int id = BoundNodeId(element);
    // If node is not mapped yet -> ignore the event.
    if (!id)
      continue;

    if (dom_listener_)
      dom_listener_->DidModifyDOMAttr(element);
    node_ids.push_back(id);
  }
  GetClient()->OnInlineStyleInvalidated(std::move(node_ids));
}

void DOMDispatcher::CharacterDataModified(blink::CharacterData* character_data) {
  int id = document_node_to_id_map_->at(character_data);
  if (!id) {
    // Push text node if it is being created.
    DidInsertDOMNode(character_data);
    return;
  }
  GetClient()->OnCharacterDataModified(id, std::string(character_data->data().Utf8().data()));
}

InspectorRevalidateDOMTask* DOMDispatcher::RevalidateTask() {
  if (!revalidate_task_)
    revalidate_task_ = new InspectorRevalidateDOMTask(this);
  return revalidate_task_.Get();
}

void DOMDispatcher::DidInvalidateStyleAttr(blink::Node* node) {
  int id = document_node_to_id_map_->at(node);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  RevalidateTask()->ScheduleStyleAttrRevalidationFor(ToElement(node));
}

void DOMDispatcher::DidPushShadowRoot(blink::Element* host, blink::ShadowRoot* root) {
  if (!host->ownerDocument())
    return;

  int host_id = document_node_to_id_map_->at(host);
  if (!host_id)
    return;

  PushChildNodesToFrontend(host_id, 1);
  GetClient()->OnShadowRootPushed(
      host_id,
      BuildObjectForNode(root, 0, false, document_node_to_id_map_.Get()));
}

void DOMDispatcher::WillPopShadowRoot(blink::Element* host, blink::ShadowRoot* root) {
  if (!host->ownerDocument())
    return;

  int host_id = document_node_to_id_map_->at(host);
  int root_id = document_node_to_id_map_->at(root);
  if (host_id && root_id)
    GetClient()->OnShadowRootPopped(host_id, root_id);
}

void DOMDispatcher::DidPerformElementShadowDistribution(blink::Element* shadow_host) {
  int shadow_host_id = document_node_to_id_map_->at(shadow_host);
  if (!shadow_host_id)
    return;

  if (blink::ShadowRoot* root = shadow_host->GetShadowRoot()) {
    const blink::HeapVector<blink::Member<blink::V0InsertionPoint>>& insertion_points =
        root->V0().DescendantInsertionPoints();
    for (const auto& it : insertion_points) {
      blink::V0InsertionPoint* insertion_point = it.Get();
      int insertion_point_id = document_node_to_id_map_->at(insertion_point);
      if (insertion_point_id)
        GetClient()->OnDistributedNodesUpdated(
            insertion_point_id, BuildArrayForDistributedNodes(insertion_point));
    }
  }
}

void DOMDispatcher::DidPerformSlotDistribution(blink::HTMLSlotElement* slot_element) {
  int insertion_point_id = document_node_to_id_map_->at(slot_element);
  if (insertion_point_id)
    GetClient()->OnDistributedNodesUpdated(
        insertion_point_id, BuildDistributedNodesForSlot(slot_element));
}

void DOMDispatcher::FrameDocumentUpdated(blink::LocalFrame* frame) {
  blink::Document* document = frame->GetDocument();
  if (!document)
    return;

  if (frame != page_instance_->inspected_frames()->Root())
    return;

  // Only update the main frame document, nested frame document updates are not
  // required (will be handled by invalidateFrameOwnerElement()).
  SetDocument(document);
}

void DOMDispatcher::FrameOwnerContentUpdated(blink::LocalFrame* frame, blink::HTMLFrameOwnerElement* frame_owner) {
  if (!frame_owner->contentDocument()) {
    // frame_owner does not point to frame at this point, so Unbind it
    // explicitly.
    Unbind(frame->GetDocument(), document_node_to_id_map_.Get());
  }

  // Revalidating owner can serialize empty frame owner - that's what we are
  // looking for when disconnecting.
  InvalidateFrameOwnerElement(frame_owner);
}

void DOMDispatcher::PseudoElementCreated(blink::PseudoElement* pseudo_element) {
  blink::Element* parent = pseudo_element->ParentOrShadowHostElement();
  if (!parent)
    return;
  int parent_id = document_node_to_id_map_->at(parent);
  if (!parent_id)
    return;

  PushChildNodesToFrontend(parent_id, 1);
  GetClient()->OnPseudoElementAdded(
      parent_id, BuildObjectForNode(pseudo_element, 0, false,
                                    document_node_to_id_map_.Get()));
}

void DOMDispatcher::PseudoElementDestroyed(blink::PseudoElement* pseudo_element) {
  int pseudo_element_id = document_node_to_id_map_->at(pseudo_element);
  if (!pseudo_element_id)
    return;

  // If a PseudoElement is bound, its parent element must be bound, too.
  blink::Element* parent = pseudo_element->ParentOrShadowHostElement();
  DCHECK(parent);
  int parent_id = document_node_to_id_map_->at(parent);
  DCHECK(parent_id);

  Unbind(pseudo_element, document_node_to_id_map_.Get());
  GetClient()->OnPseudoElementRemoved(parent_id, pseudo_element_id);
}

bool DOMDispatcher::PushDocumentUponHandlelessOperation() {
  if (!document_node_to_id_map_->Contains(document_)) {
    automation::DOMNodePtr root = GetDocumentInternal(-1, false);
    return !root.is_null();
  }
  return true;
}

void DOMDispatcher::DiscardFrontendBindings() {
  //if (history_)
  //  history_->Reset();
  search_results_.clear();
  document_node_to_id_map_->clear();
  id_to_node_.clear();
  id_to_nodes_map_.clear();
  ReleaseDanglingNodes();
  children_requested_.clear();
  cached_child_count_.clear();
  if (revalidate_task_)
    revalidate_task_->Reset();
}

void DOMDispatcher::ReleaseDanglingNodes() {
  dangling_node_to_id_maps_.clear();
}

automation::DOMNodePtr DOMDispatcher::BuildObjectForNode(
    blink::Node* node,
    int depth,
    bool pierce,
    NodeToIdMap* nodes_map,
    std::vector<automation::DOMNodePtr>* flatten_result) {
  int id = Bind(node, nodes_map);
  String local_name;
  String node_value;

  switch (node->getNodeType()) {
    case blink::Node::kTextNode:
    case blink::Node::kCommentNode:
    case blink::Node::kCdataSectionNode:
      node_value = node->nodeValue();
      if (node_value.length() > kMaxTextSize)
        node_value = node_value.Left(kMaxTextSize) + kEllipsisUChar;
      break;
    case blink::Node::kAttributeNode:
      local_name = ToAttr(node)->localName();
      break;
    case blink::Node::kElementNode:
      local_name = ToElement(node)->localName();
      break;
    default:
      break;
  }

  automation::DOMNodePtr value = automation::DOMNode::New();
  value->node_id = id;
  value->backend_node_id = blink::DOMNodeIds::IdForNode(node);
  value->node_type = static_cast<int>(node->getNodeType());
  value->node_name = std::string(node->nodeName().Utf8().data(), node->nodeName().length());
  value->local_name = std::string(local_name.Utf8().data(), local_name.length());
  value->node_value = std::string(node_value.Utf8().data(), node_value.length());
      
  if (node->IsSVGElement())
    value->is_svg = true;

  bool force_push_children = false;
  if (node->IsElementNode()) {
    blink::Element* element = ToElement(node);
    value->attributes = BuildArrayForElementAttributes(element);

    if (node->IsFrameOwnerElement()) {
      blink::HTMLFrameOwnerElement* frame_owner = ToHTMLFrameOwnerElement(node);
      if (frame_owner->ContentFrame()) {
        String frame_id = blink::IdentifiersFactory::FrameId(frame_owner->ContentFrame());
        value->frame_id = std::string(frame_id.Utf8().data(), frame_id.length());
      }
      if (blink::Document* doc = frame_owner->contentDocument()) {
        value->content_document = BuildObjectForNode(
          doc, pierce ? depth : 0, pierce, nodes_map, flatten_result);
      }
    }

    if (node->parentNode() && node->parentNode()->IsDocumentNode()) {
      blink::LocalFrame* frame = node->GetDocument().GetFrame();
      if (frame) {
        String frame_id = blink::IdentifiersFactory::FrameId(frame);
        value->frame_id = std::string(frame_id.Utf8().data(), frame_id.length());
      }
    }

    if (blink::ShadowRoot* root = element->GetShadowRoot()) {
      std::vector<automation::DOMNodePtr> shadow_roots;
      shadow_roots.push_back(BuildObjectForNode(root, pierce ? depth : 0, pierce,
                                                 nodes_map, flatten_result));
      value->shadow_roots = std::move(shadow_roots);
      force_push_children = true;
    }

    if (auto* link_element = ToHTMLLinkElementOrNull(*element)) {
      if (link_element->IsImport() && link_element->import() &&
          InnerParentNode(link_element->import()) == link_element) {
        value->imported_document = BuildObjectForNode(
            link_element->import(), 0, pierce, nodes_map, flatten_result);
      }
      force_push_children = true;
    }

    if (auto* template_element = ToHTMLTemplateElementOrNull(*element)) {
      value->template_content = BuildObjectForNode(
          template_element->content(), 0, pierce, nodes_map, flatten_result);
      force_push_children = true;
    }

    if (element->GetPseudoId()) {
      automation::PseudoType pseudo_type;
      if (DOMDispatcher::GetPseudoElementType(element->GetPseudoId(),
                                              &pseudo_type))
        value->pseudo_type = pseudo_type;
    } else {
      std::vector<automation::DOMNodePtr> pseudo_elements = BuildArrayForPseudoElements(element, nodes_map);
      if (pseudo_elements.size() > 0) {
        value->pseudo_elements = std::move(pseudo_elements);
        force_push_children = true;
      }
      if (!element->ownerDocument()->xmlVersion().IsEmpty())
        value->xml_version = std::string(element->ownerDocument()->xmlVersion().Utf8().data());
    }

    if (element->IsV0InsertionPoint()) {
      value->distributed_nodes = BuildArrayForDistributedNodes(ToV0InsertionPoint(element));
      force_push_children = true;
    }
    if (auto* slot = ToHTMLSlotElementOrNull(*element)) {
      if (node->IsInShadowTree()) {
        value->distributed_nodes = BuildDistributedNodesForSlot(slot);
        force_push_children = true;
      }
    }
  } else if (node->IsDocumentNode()) {
    blink::Document* document = ToDocument(node);
    value->document_url = std::string(DocumentURLString(document).Utf8().data());
    value->base_url = std::string(DocumentBaseURLString(document).Utf8().data());
    value->xml_version = std::string(document->xmlVersion().Utf8().data());
  } else if (node->IsDocumentTypeNode()) {
    blink::DocumentType* doc_type = ToDocumentType(node);
    value->public_id = std::string(doc_type->publicId().Utf8().data());
    value->system_id = std::string(doc_type->systemId().Utf8().data());
  } else if (node->IsAttributeNode()) {
    blink::Attr* attribute = ToAttr(node);
    value->name = std::string(attribute->name().Utf8().data(), attribute->name().length());
    value->value = std::string(attribute->value().Utf8().data(), attribute->value().length());
  } else if (node->IsShadowRoot()) {
    value->shadow_root_type = GetShadowRootType(ToShadowRoot(node));
  }

  if (node->IsContainerNode()) {
    int node_count = InnerChildNodeCount(node);
    value->child_node_count = node_count;
    if (nodes_map == document_node_to_id_map_)
      cached_child_count_.Set(id, node_count);
    if (nodes_map && force_push_children && !depth)
      depth = 1;
    std::vector<automation::DOMNodePtr> children =
        BuildArrayForContainerChildren(node, depth, pierce, nodes_map,
                                       flatten_result);
    if (children.size() > 0 ||
        depth)  // Push children along with shadow in any case.
      value->children = std::move(children);
  }

  return value;
}

std::vector<std::string> DOMDispatcher::BuildArrayForElementAttributes(blink::Element* element) {
  std::vector<std::string> attributes_value;
  // Go through all attributes and serialize them.
  blink::AttributeCollection attributes = element->Attributes();
  for (auto& attribute : attributes) {
    // Add attribute pair
    attributes_value.push_back(std::string(attribute.GetName().ToString().Utf8().data()));
    attributes_value.push_back(std::string(attribute.Value().Utf8().data()));
  }
  return attributes_value;
}

std::vector<automation::DOMNodePtr> DOMDispatcher::BuildArrayForContainerChildren(
  blink::Node* container,
  int depth,
  bool pierce,
  NodeToIdMap* nodes_map,
  std::vector<automation::DOMNodePtr>* flatten_result) {
  std::vector<automation::DOMNodePtr> children;
  if (depth == 0) {
    if (!nodes_map)
      return children;
    // Special-case the only text child - pretend that container's children have
    // been requested.
    blink::Node* first_child = container->firstChild();
    if (first_child && first_child->getNodeType() == blink::Node::kTextNode &&
        !first_child->nextSibling()) {
      automation::DOMNodePtr child_node = BuildObjectForNode(first_child, 0, pierce, nodes_map, flatten_result);
      child_node->parent_id = Bind(container, nodes_map);
      if (flatten_result) {
        flatten_result->push_back(std::move(child_node));
      } else {
        children.push_back(std::move(child_node));
      }
      children_requested_.insert(Bind(container, nodes_map));
    }
    return children;
  }

  blink::Node* child = InnerFirstChild(container);
  depth--;
  if (nodes_map)
    children_requested_.insert(Bind(container, nodes_map));

  while (child) {
    automation::DOMNodePtr child_node = BuildObjectForNode(child, depth, pierce, nodes_map, flatten_result);
    child_node->parent_id = Bind(container, nodes_map);
    if (flatten_result) {
      flatten_result->push_back(std::move(child_node));
    } else {
      children.push_back(std::move(child_node));
    }
    if (nodes_map)
      children_requested_.insert(Bind(container, nodes_map));
    child = InnerNextSibling(child);
  }
  return children;
}

std::vector<automation::DOMNodePtr> DOMDispatcher::BuildArrayForPseudoElements(
  blink::Element* element,
  NodeToIdMap* nodes_map) {

  if (!element->GetPseudoElement(blink::kPseudoIdBefore) &&
      !element->GetPseudoElement(blink::kPseudoIdAfter))
    return std::vector<automation::DOMNodePtr>();

  std::vector<automation::DOMNodePtr> pseudo_elements;
  if (element->GetPseudoElement(blink::kPseudoIdBefore)) {
    pseudo_elements.push_back(BuildObjectForNode(
        element->GetPseudoElement(blink::kPseudoIdBefore), 0, false, nodes_map));
  }
  if (element->GetPseudoElement(blink::kPseudoIdAfter)) {
    pseudo_elements.push_back(BuildObjectForNode(
        element->GetPseudoElement(blink::kPseudoIdAfter), 0, false, nodes_map));
  }
  return pseudo_elements;
}

std::vector<automation::BackendNodePtr> DOMDispatcher::BuildArrayForDistributedNodes(blink::V0InsertionPoint* insertion_point) {
  std::vector<automation::BackendNodePtr> distributed_nodes;
  for (size_t i = 0; i < insertion_point->DistributedNodesSize(); ++i) {
    blink::Node* distributed_node = insertion_point->DistributedNodeAt(i);
    if (IsWhitespace(distributed_node))
      continue;

    automation::BackendNodePtr backend_node = automation::BackendNode::New();
    backend_node->node_type = distributed_node->getNodeType();
    backend_node->node_name = std::string(distributed_node->nodeName().Utf8().data(), distributed_node->nodeName().length());
    backend_node->backend_node_id = blink::DOMNodeIds::IdForNode(distributed_node);
    distributed_nodes.push_back(std::move(backend_node));
  }
  return distributed_nodes;
}

std::vector<automation::BackendNodePtr> DOMDispatcher::BuildDistributedNodesForSlot(blink::HTMLSlotElement* slot_element) {
  std::vector<automation::BackendNodePtr> distributed_nodes;
  // if (RuntimeEnabledFeatures::IncrementalShadowDOMEnabled()) {
  //   // TODO(hayato): Support distributed_nodes for IncrementalShadowDOM.
  //   // We might use HTMLSlotElement::flat_tree_children here, however, we don't
  //   // want to expose it, as of now.
  //   return distributed_nodes;
  // }
  for (blink::Node* node = slot_element->FirstDistributedNode(); node;
       node = slot_element->DistributedNodeNextTo(*node)) {
    if (IsWhitespace(node))
      continue;

    automation::BackendNodePtr backend_node = automation::BackendNode::New();
    backend_node->node_type = node->getNodeType();
    backend_node->node_name = std::string(node->nodeName().Utf8().data(), node->nodeName().length());
    backend_node->backend_node_id = blink::DOMNodeIds::IdForNode(node);
    distributed_nodes.push_back(std::move(backend_node));
  }
  return distributed_nodes;
}

int DOMDispatcher::Bind(blink::Node* node, NodeToIdMap* nodes_map) {
  if (!nodes_map)
    return 0;
  int id = nodes_map->at(node);
  if (id)
    return id;
  id = last_node_id_++;
  nodes_map->Set(node, id);
  id_to_node_.Set(id, node);
  id_to_nodes_map_.Set(id, nodes_map);
  return id;
}

void DOMDispatcher::Unbind(blink::Node* node, NodeToIdMap* nodes_map) {
  int id = nodes_map->at(node);
  if (!id)
    return;

  id_to_node_.erase(id);
  id_to_nodes_map_.erase(id);

  if (node->IsDocumentNode() && dom_listener_)
    dom_listener_->DidRemoveDocument(ToDocument(node));

  if (node->IsFrameOwnerElement()) {
    blink::Document* content_document = ToHTMLFrameOwnerElement(node)->contentDocument();
    if (content_document)
      Unbind(content_document, nodes_map);
  }

  if (blink::ShadowRoot* root = node->GetShadowRoot())
    Unbind(root, nodes_map);

  if (node->IsElementNode()) {
    blink::Element* element = ToElement(node);
    if (element->GetPseudoElement(blink::kPseudoIdBefore))
      Unbind(element->GetPseudoElement(blink::kPseudoIdBefore), nodes_map);
    if (element->GetPseudoElement(blink::kPseudoIdAfter))
      Unbind(element->GetPseudoElement(blink::kPseudoIdAfter), nodes_map);

    if (auto* link_element = ToHTMLLinkElementOrNull(*element)) {
      if (link_element->IsImport() && link_element->import())
        Unbind(link_element->import(), nodes_map);
    }
  }

  nodes_map->erase(node);
  if (dom_listener_)
    dom_listener_->DidRemoveDOMNode(node);

  bool children_requested = children_requested_.Contains(id);
  if (children_requested) {
    // Unbind subtree known to client recursively.
    children_requested_.erase(id);
    blink::Node* child = InnerFirstChild(node);
    while (child) {
      Unbind(child, nodes_map);
      child = InnerNextSibling(child);
    }
  }
  if (nodes_map == document_node_to_id_map_.Get())
    cached_child_count_.erase(id);
}

bool DOMDispatcher::GetPseudoElementType(blink::PseudoId pseudo_id,
                                         automation::PseudoType* type) {
  switch (pseudo_id) {
    case blink::kPseudoIdFirstLine:
      *type = automation::PseudoType::kPSEUDO_TYPE_FIRST_LINE;
      return true;
    case blink::kPseudoIdFirstLetter:
      *type = automation::PseudoType::kPSEUDO_TYPE_FIRST_LETTER;
      return true;
    case blink::kPseudoIdBefore:
      *type = automation::PseudoType::kPSEUDO_TYPE_BEFORE;
      return true;
    case blink::kPseudoIdAfter:
      *type = automation::PseudoType::kPSEUDO_TYPE_AFTER;
      return true;
    case blink::kPseudoIdBackdrop:
      *type = automation::PseudoType::kPSEUDO_TYPE_BACKDROP;
      return true;
    case blink::kPseudoIdSelection:
      *type = automation::PseudoType::kPSEUDO_TYPE_SELECTION;
      return true;
    case blink::kPseudoIdFirstLineInherited:
      *type = automation::PseudoType::kPSEUDO_TYPE_FIRST_LINE_INHERITED;
      return true;
    case blink::kPseudoIdScrollbar:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR;
      return true;
    case blink::kPseudoIdScrollbarThumb:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR_THUMB;
      return true;
    case blink::kPseudoIdScrollbarButton:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR_BUTTON;
      return true;
    case blink::kPseudoIdScrollbarTrack:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR_TRACK;
      return true;
    case blink::kPseudoIdScrollbarTrackPiece:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR_TRACK_PIECE;
      return true;
    case blink::kPseudoIdScrollbarCorner:
      *type = automation::PseudoType::kPSEUDO_TYPE_SCROLLBAR_CORNER;
      return true;
    case blink::kPseudoIdResizer:
      *type = automation::PseudoType::kPSEUDO_TYPE_RESIZER;
      return true;
    case blink::kPseudoIdInputListButton:
      *type = automation::PseudoType::kPSEUDO_TYPE_INPUT_LIST_BUTTON;
      return true;
    default:
      return false;
  }
}

// static
blink::Node* DOMDispatcher::InnerFirstChild(blink::Node* node) {
  node = node->firstChild();
  while (IsWhitespace(node))
    node = node->nextSibling();
  return node;
}

// static
blink::Node* DOMDispatcher::InnerNextSibling(blink::Node* node) {
  do {
    node = node->nextSibling();
  } while (IsWhitespace(node));
  return node;
}

// static
blink::Node* DOMDispatcher::InnerPreviousSibling(blink::Node* node) {
  do {
    node = node->previousSibling();
  } while (IsWhitespace(node));
  return node;
}

// static
unsigned DOMDispatcher::InnerChildNodeCount(blink::Node* node) {
  unsigned count = 0;
  blink::Node* child = InnerFirstChild(node);
  while (child) {
    count++;
    child = InnerNextSibling(child);
  }
  return count;
}

// static
blink::Node* DOMDispatcher::InnerParentNode(blink::Node* node) {
  if (node->IsDocumentNode()) {
    blink::Document* document = ToDocument(node);
    if (blink::HTMLImportLoader* loader = document->ImportLoader())
      return loader->FirstImport()->Link();
    return document->LocalOwner();
  }
  return node->ParentOrShadowHostNode();
}

// static
bool DOMDispatcher::IsWhitespace(blink::Node* node) {
  // TODO: pull ignoreWhitespace setting from the frontend and use here.
  return node && node->getNodeType() == blink::Node::kTextNode &&
         node->nodeValue().StripWhiteSpace().length() == 0;
}

// static
void DOMDispatcher::CollectNodes(
  blink::Node* node,
  int depth,
  bool pierce,
  base::RepeatingCallback<bool(blink::Node*)> filter,
  blink::HeapVector<blink::Member<blink::Node>>* result) {
  if (filter && filter.Run(node))
    result->push_back(node);
  if (--depth <= 0)
    return;

  if (pierce && node->IsElementNode()) {
    blink::Element* element = blink::ToElement(node);
    if (node->IsFrameOwnerElement()) {
      blink::HTMLFrameOwnerElement* frame_owner = blink::ToHTMLFrameOwnerElement(node);
      if (frame_owner->ContentFrame() &&
          frame_owner->ContentFrame()->IsLocalFrame()) {
        if (blink::Document* doc = frame_owner->contentDocument())
          CollectNodes(doc, depth, pierce, filter, result);
      }
    }

    blink::ShadowRoot* root = element->GetShadowRoot();
    if (pierce && root)
      CollectNodes(root, depth, pierce, filter, result);

    if (auto* link_element = ToHTMLLinkElementOrNull(*element)) {
      if (link_element->IsImport() && link_element->import() &&
          InnerParentNode(link_element->import()) == link_element) {
        CollectNodes(link_element->import(), depth, pierce, filter, result);
      }
    }
  }

  for (blink::Node* child = InnerFirstChild(node); child;
       child = InnerNextSibling(child)) {
    CollectNodes(child, depth, pierce, filter, result);
  }
}

void DOMDispatcher::PushChildNodesToFrontend(int node_id,
                                             int depth,
                                             bool pierce) {
  blink::Node* node = NodeForId(node_id);
  if (!node || (!node->IsElementNode() && !node->IsDocumentNode() &&
                !node->IsDocumentFragment()))
    return;

  NodeToIdMap* node_map = id_to_nodes_map_.at(node_id);

  if (children_requested_.Contains(node_id)) {
    if (depth <= 1)
      return;

    depth--;

    for (node = InnerFirstChild(node); node; node = InnerNextSibling(node)) {
      int child_node_id = node_map->at(node);
      DCHECK(child_node_id);
      PushChildNodesToFrontend(child_node_id, depth, pierce);
    }

    return;
  }

  std::vector<automation::DOMNodePtr> children =
      BuildArrayForContainerChildren(node, depth, pierce, node_map, nullptr);
  GetClient()->SetChildNodes(node_id, std::move(children));
}


int DOMDispatcher::BoundNodeId(blink::Node* node) {
  return document_node_to_id_map_->at(node);
}

blink::HeapVector<blink::Member<blink::Document>> DOMDispatcher::Documents() {
  blink::HeapVector<blink::Member<blink::Document>> result;
  if (document_) {
    for (blink::LocalFrame* frame : *page_instance_->inspected_frames()) {
      if (blink::Document* document = frame->GetDocument())
        result.push_back(document);
    }
  }
  return result;
}

bool DOMDispatcher::AssertNode(int node_id, blink::Node*& node) {
  node = NodeForId(node_id);
  if (!node)
    return false;
  return true;
}

bool DOMDispatcher::AssertNode(int node_id,
                               int backend_node_id,
                               const base::Optional<std::string>& object_id,
                               blink::Node*& node) {
  if (node_id != 0) {
    return AssertNode(node_id, node);
  }

  if (backend_node_id != 0) {
    node = blink::DOMNodeIds::NodeForId(backend_node_id);
    return !node ? false
                 : true;
  }

  if (object_id.has_value()) {
    return NodeForRemoteObjectId(String::FromUTF8((*object_id).data()), node);
  }

  return false;
}

bool DOMDispatcher::AssertElement(int node_id, blink::Element*& element) {
  blink::Node* node = nullptr;
  bool node_ok = AssertNode(node_id, node);
  if (!node_ok)
    return false;

  if (!node->IsElementNode()) {
    //DLOG(ERROR) << "Node is not an Element";
    return false;
  }
  element = ToElement(node);
  return true;
}

blink::Node* DOMDispatcher::NodeForPath(const String& path) {
  // The path is of form "1,HTML,2,BODY,1,DIV" (<index> and <nodeName>
  // interleaved).  <index> may also be "a" (author shadow root) or "u"
  // (user-agent shadow root), in which case <nodeName> MUST be
  // "#document-fragment".
  if (!document_)
    return nullptr;

  blink::Node* node = document_.Get();
  Vector<String> path_tokens;
  path.Split(',', path_tokens);
  if (!path_tokens.size())
    return nullptr;

  for (size_t i = 0; i < path_tokens.size() - 1; i += 2) {
    bool success = true;
    String& index_value = path_tokens[i];
    unsigned child_number = index_value.ToUInt(&success);
    blink::Node* child;
    if (!success) {
      child = ShadowRootForNode(node, index_value);
    } else {
      if (child_number >= InnerChildNodeCount(node))
        return nullptr;

      child = InnerFirstChild(node);
    }
    String child_name = path_tokens[i + 1];
    for (size_t j = 0; child && j < child_number; ++j)
      child = InnerNextSibling(child);

    if (!child || child->nodeName() != child_name)
      return nullptr;
    node = child;
  }
  return node;
}

int DOMDispatcher::PushNodePathToFrontend(blink::Node* node_to_push,
                                          NodeToIdMap* node_map) {
  DCHECK(node_to_push);  // Invalid input
  // InspectorDOMAgent might have been resetted already. See crbug.com/450491
  if (!document_)
    return 0;
  if (!document_node_to_id_map_->Contains(document_))
    return 0;

  // Return id in case the node is known.
  int result = node_map->at(node_to_push);
  if (result)
    return result;

  blink::Node* node = node_to_push;
  blink::HeapVector<blink::Member<blink::Node>> path;

  while (true) {
    blink::Node* parent = InnerParentNode(node);
    if (!parent)
      return 0;
    path.push_back(parent);
    if (node_map->at(parent))
      break;
    node = parent;
  }

  for (int i = path.size() - 1; i >= 0; --i) {
    int node_id = node_map->at(path.at(i).Get());
    DCHECK(node_id);
    PushChildNodesToFrontend(node_id);
  }
  return node_map->at(node_to_push);
}

int DOMDispatcher::PushNodePathToFrontend(blink::Node* node_to_push) {
  if (!document_)
    return 0;

  int node_id = PushNodePathToFrontend(node_to_push, document_node_to_id_map_.Get());
  if (node_id)
    return node_id;

  blink::Node* node = node_to_push;
  while (blink::Node* parent = InnerParentNode(node))
    node = parent;

  // Node being pushed is detached -> push subtree root.
  NodeToIdMap* new_map = new NodeToIdMap;
  NodeToIdMap* dangling_map = new_map;
  dangling_node_to_id_maps_.push_back(new_map);
  std::vector<automation::DOMNodePtr> children;
  children.push_back(BuildObjectForNode(node, 0, false, dangling_map));
  GetClient()->SetChildNodes(0, std::move(children));

  return PushNodePathToFrontend(node_to_push, dangling_map);
}

bool DOMDispatcher::AssertEditableNode(int node_id, blink::Node*& node) {
  bool has_node = AssertNode(node_id, node);
  if (!has_node) {
    //DLOG(INFO) << "Node " << node_id << " is not existant";
    return false;
  }

  if (node->IsInShadowTree()) {
    if (node->IsShadowRoot()) {
      //DLOG(INFO) << "Cannot edit shadow roots";
      return false;
    }
    if (UserAgentShadowRoot(node)) {
      //DLOG(INFO) << "Cannot edit nodes from user-agent shadow trees";
      return false;
    }
  }

  if (node->IsPseudoElement()) {
    //DLOG(INFO) << "Cannot edit pseudo elements";
    return false;
  }
  return true;
}  

bool DOMDispatcher::AssertEditableChildNode(blink::Element* parent_element,
                                            int node_id,
                                            blink::Node*& node) {
  bool editable = AssertEditableNode(node_id, node);
  if (!editable) {
    return false;
  }
  
  if (node->parentNode() != parent_element) {
    //DLOG(ERROR) << "Anchor node must be child of the target element";
    return false;
  }
  return true;
}

bool DOMDispatcher::AssertEditableElement(int node_id, blink::Element*& element) {
  bool have_element = AssertElement(node_id, element);

  if (!have_element) {
    //DLOG(ERROR) << "No element with id " << node_id;
    return false;
  }

  if (element->IsInShadowTree() && UserAgentShadowRoot(element)) {
    //DLOG(ERROR) << "Cannot edit elements from user-agent shadow trees";
    return false;
  }

  if (element->IsPseudoElement()) {
    //DLOG(ERROR) << "Cannot edit pseudo elements";
    return false;
  }

  //DLOG(ERROR) << "Either nodeId, backendNodeId or objectId must be specified";

  return true;
}

bool DOMDispatcher::NodeForRemoteObjectId(const String& object_id,
                                          blink::Node*& node) {
  // v8::HandleScope handles(isolate_);
  // v8::Local<v8::Value> value;
  // v8::Local<v8::Context> context;
  // std::unique_ptr<v8_inspector::StringBuffer> error;
  // if (!v8_session_->unwrapObject(&error, ToV8InspectorStringView(object_id),
  //                                &value, &context, nullptr)) {
  //   //DLOG(ERROR) << ToCoreString(std::move(error));
  //   return false;
  // }
  // if (!V8Node::hasInstance(value, isolate_)) {
  //   //DLOG(ERROR) << "Object id doesn't reference a Node";
  //   return false;
  // }
  // node = V8Node::ToImpl(v8::Local<v8::Object>::Cast(value));
  // if (!node) {
  //   //DLOG(ERROR) << "Couldn't convert object with given objectId to Node";
  //   return false;
  // }
  // return true;
  LOG(ERROR) << "remote objects are not implemented";
  return false;
}

void DOMDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  dom_agent_impl_ = new InspectorDOMAgentImpl(this);
  dom_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  history_ = new blink::InspectorHistory();
  dom_editor_ = new blink::DOMEditor(history_.Get());
  document_ = page_instance_->inspected_frames()->Root()->GetDocument();
  page_instance_->probe_sink()->addInspectorDOMAgent(dom_agent_impl_.Get());
  Enable();
  //DLOG(INFO) << "DOMDispatcher::OnWebFrameCreated: probe_sink = " << page_instance_->probe_sink() << " dom_agent = " << dom_agent_impl_.Get();
}

}
