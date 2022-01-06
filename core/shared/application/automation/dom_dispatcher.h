// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_DOM_DISPATCHER_H_
#define MUMBA_APPLICATION_DOM_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

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

namespace blink {
class LocalFrame;
class Color;
class Document;
class DocumentLoader;
class Node;
class Element;
class ShadowRoot;
class HTMLSlotElement;
class HTMLFrameOwnerElement;
class PseudoElement;
class QualifiedName;
class CharacterData;
class InspectorHistory;
class DOMEditor;
class V0InsertionPoint;
class InspectorDOMAgent;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class InspectorRevalidateDOMTask;
class InspectorDOMAgentImpl;
class PageInstance;
class ApplicationWindowDispatcher;

class DOMDispatcher : public automation::DOM {
public:
  class DOMListener {
  public:
    virtual ~DOMListener() = default;
    virtual void DidAddDocument(blink::Document*) = 0;
    virtual void DidRemoveDocument(blink::Document*) = 0;
    virtual void DidRemoveDOMNode(blink::Node*) = 0;
    virtual void DidModifyDOMAttr(blink::Element*) = 0;
  };

  static bool GetPseudoElementType(blink::PseudoId pseudo_id,
                                   automation::PseudoType* type);

  static blink::Color ParseColor(automation::RGBA*);

  static blink::ShadowRoot* UserAgentShadowRoot(blink::Node* node);
  static blink::Node* InnerFirstChild(blink::Node* node);
  static blink::Node* InnerNextSibling(blink::Node* node);
  static blink::Node* InnerPreviousSibling(blink::Node* node);
  static unsigned InnerChildNodeCount(blink::Node* node);
  static blink::Node* InnerParentNode(blink::Node* node);
  static bool IsWhitespace(blink::Node* node);
  static void CollectNodes(
    blink::Node* node,
    int depth,
    bool pierce,
    base::RepeatingCallback<bool(blink::Node*)> filter,
    blink::HeapVector<blink::Member<blink::Node>>* result);
  static DOMDispatcher* Create(automation::DOMRequest request, PageInstance* page_instance);

  DOMDispatcher(automation::DOMRequest request, PageInstance* page_instance);
  DOMDispatcher(PageInstance* page_instance);
  ~DOMDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void BindMojo(automation::DOMAssociatedRequest request);

  void SetDOMListener(DOMListener*);

  bool enabled() const {
    return enabled_;
  }

  void Register(int32_t application_id) override;
  void CollectClassNamesFromSubtree(int32_t node_id, CollectClassNamesFromSubtreeCallback callback) override;
  void CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, CopyToCallback callback) override;
  void DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, DescribeNodeCallback callback) override;
  void Disable() override;
  void DiscardSearchResults(const std::string& search_id) override;
  void Enable() override;
  void Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void GetAttributes(int32_t node_id, GetAttributesCallback callback) override;
  void GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetBoxModelCallback callback) override;
  void GetDocument(int32_t depth, bool pierce, GetDocumentCallback callback) override;
  void GetFlattenedDocument(int32_t depth, bool pierce, GetFlattenedDocumentCallback callback) override;
  void GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, GetNodeForLocationCallback callback) override;
  void GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetOuterHTMLCallback callback) override;
  void GetRelayoutBoundary(int32_t node_id, GetRelayoutBoundaryCallback callback) override;
  void GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, GetSearchResultsCallback callback) override;
  void HideHighlight() override;
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) override;
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void MarkUndoableState() override;
  void MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, MoveToCallback callback) override;
  void PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, PerformSearchCallback callback) override;
  void PushNodeByPathToFrontend(const std::string& path, PushNodeByPathToFrontendCallback callback) override;
  void PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, PushNodesByBackendIdsToFrontendCallback callback) override;
  void QuerySelector(int32_t node_id, const std::string& selector, QuerySelectorCallback callback) override;
  void QuerySelectorAll(int32_t node_id, const std::string& selector, QuerySelectorAllCallback callback) override;
  void Redo() override;
  void RemoveAttribute(int32_t node_id, const std::string& name) override;
  void RemoveNode(int32_t node_id) override;
  void RequestChildNodes(int32_t node_id, int32_t depth, bool pierce) override;
  void RequestNode(const std::string& object_id, RequestNodeCallback callback) override;
  void ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, ResolveNodeCallback callback) override;
  void SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) override;
  void SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name) override;
  void SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void SetInspectedNode(int32_t node_id) override;
  void SetNodeName(int32_t node_id, const std::string& name, SetNodeNameCallback callback) override;
  void SetNodeValue(int32_t node_id, const std::string& value) override;
  void SetOuterHTML(int32_t node_id, const std::string& outer_html) override;
  void Undo() override;
  void GetFrameOwner(const std::string& frame_id, GetFrameOwnerCallback callback) override;

  blink::Document* GetDocument() const;
  blink::HeapVector<blink::Member<blink::Document>> Documents();
  int BoundNodeId(blink::Node* node);
  PageInstance* page_instance() const {
    return page_instance_;
  }

  bool AssertNode(int node_id, blink::Node*&);
  bool AssertNode(int node_id,
                  int backend_node_id,
                  const base::Optional<std::string>& object_id,
                  blink::Node*&);
  bool AssertElement(int node_id, blink::Element*&);

  blink::InspectorDOMAgent* dom_agent() const;
  
  typedef blink::HeapHashMap<blink::Member<blink::Node>, int> NodeToIdMap;
  int PushNodePathToFrontend(blink::Node* node_to_push);
  int PushNodePathToFrontend(blink::Node*, NodeToIdMap* node_map);

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorDOMAgentImpl;
  friend class InspectorRevalidateDOMTask;

  void InnerEnable();
  
  void SetDocument(blink::Document* document);

  void DomContentLoadedEventFired(blink::LocalFrame*);
  void DidCommitLoad(blink::LocalFrame*, blink::DocumentLoader*);
  void DidInsertDOMNode(blink::Node*);
  void WillRemoveDOMNode(blink::Node*);
  void WillModifyDOMAttr(blink::Element*,
                         const AtomicString& old_value,
                         const AtomicString& new_value);
  void DidModifyDOMAttr(blink::Element*,
                        const blink::QualifiedName&,
                        const AtomicString& value);
  void DidRemoveDOMAttr(blink::Element*, const blink::QualifiedName&);
  void StyleAttributeInvalidated(const blink::HeapVector<blink::Member<blink::Element>>& elements);
  void CharacterDataModified(blink::CharacterData*);
  void DidInvalidateStyleAttr(blink::Node*);
  void DidPushShadowRoot(blink::Element* host, blink::ShadowRoot*);
  void WillPopShadowRoot(blink::Element* host, blink::ShadowRoot*);
  void DidPerformElementShadowDistribution(blink::Element*);
  void DidPerformSlotDistribution(blink::HTMLSlotElement*);
  void FrameDocumentUpdated(blink::LocalFrame*);
  void FrameOwnerContentUpdated(blink::LocalFrame*, blink::HTMLFrameOwnerElement*);
  void PseudoElementCreated(blink::PseudoElement*);
  void PseudoElementDestroyed(blink::PseudoElement*);

  void InvalidateFrameOwnerElement(blink::HTMLFrameOwnerElement* frame_owner);
  InspectorRevalidateDOMTask* RevalidateTask();
  void DiscardFrontendBindings();
  void ReleaseDanglingNodes();
  automation::DOMClient* GetClient() const;
  blink::Node* NodeForId(int id);
  
  int Bind(blink::Node* node, NodeToIdMap* nodes_map);
  void Unbind(blink::Node* node, NodeToIdMap* nodes_map);

  void PushChildNodesToFrontend(int node_id,
                                int depth = 1,
                                bool traverse_frames = false);

  bool NodeForRemoteObjectId(const String& object_id,
                             blink::Node*& node);

  automation::DOMNodePtr BuildObjectForNode(blink::Node* node, 
    int depth, 
    bool pierce, 
    NodeToIdMap* nodes_map, 
    std::vector<automation::DOMNodePtr>* flatten_result = nullptr);

  std::vector<std::string> BuildArrayForElementAttributes(blink::Element* element);
  std::vector<automation::DOMNodePtr> BuildArrayForContainerChildren(
    blink::Node* container,
    int depth,
    bool pierce,
    NodeToIdMap* nodes_map,
    std::vector<automation::DOMNodePtr>* flatten_result);
  std::vector<automation::DOMNodePtr> BuildArrayForPseudoElements(blink::Element* element, NodeToIdMap* nodes_map);
  std::vector<automation::BackendNodePtr> BuildArrayForDistributedNodes(blink::V0InsertionPoint* insertion_point);
  std::vector<automation::BackendNodePtr> BuildDistributedNodesForSlot(blink::HTMLSlotElement* slot_element);

  bool AssertEditableNode(int node_id, blink::Node*& node);
  bool AssertEditableChildNode(blink::Element* parent_element, int node_id, blink::Node*&);
  bool AssertEditableElement(int node_id, blink::Element*&);
  bool PushDocumentUponHandlelessOperation();
  automation::DOMNodePtr GetDocumentInternal(int32_t depth, bool pierce);
  blink::Node* NodeForPath(const String& path);

  PageInstance* page_instance_;
  int32_t application_id_;

  mojo::AssociatedBinding<automation::DOM> binding_;
  
  automation::DOMClientAssociatedPtr dom_client_ptr_;
  blink::Persistent<InspectorDOMAgentImpl> dom_agent_impl_;
  DOMListener* dom_listener_;
  blink::Member<NodeToIdMap> document_node_to_id_map_;
  // Owns node mappings for dangling nodes.
  blink::HeapVector<blink::Member<NodeToIdMap>> dangling_node_to_id_maps_;
  blink::HeapHashMap<int, blink::Member<blink::Node>> id_to_node_;
  blink::HeapHashMap<int, blink::Member<NodeToIdMap>> id_to_nodes_map_;
  HashSet<int> children_requested_;
  HashSet<int> distributed_nodes_requested_;
  HashMap<int, int> cached_child_count_;
  int last_node_id_;
  blink::Member<blink::Document> document_;
  typedef blink::HeapHashMap<String, blink::HeapVector<blink::Member<blink::Node>>> SearchResults;
  SearchResults search_results_;
  blink::Member<InspectorRevalidateDOMTask> revalidate_task_;
  blink::Member<blink::InspectorHistory> history_;
  blink::Member<blink::DOMEditor> dom_editor_;
  bool enabled_;
  bool suppress_attribute_modified_event_;

  DISALLOW_COPY_AND_ASSIGN(DOMDispatcher); 
};

}

#endif
