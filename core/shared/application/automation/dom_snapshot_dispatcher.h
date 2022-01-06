// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_DOM_SNAPSHOT_DISPATCHER_H_
#define MUMBA_APPLICATION_DOM_SNAPSHOT_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/core/css_property_names.h"
#include "third_party/blink/renderer/core/inspector/inspector_base_agent.h"
#include "third_party/blink/renderer/core/inspector/protocol/DOMSnapshot.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_listener_info.h"

namespace blink {
class Document;
class Element;
class Node;
class PaintLayer;
class EventTarget;
class WebLocalFrame;
}

namespace IPC {
class SyncChannel;
}

namespace service_manager {
class InterfaceProvider;
}

namespace application {
class PageInstance;

class DOMSnapshotDispatcher : public automation::DOMSnapshot {
public:
  static void CollectEventListeners(v8::Isolate* isolate,
    blink::EventTarget* target,
    v8::Local<v8::Value> target_wrapper,
    blink::Node* target_node,
    bool report_for_all_contexts,
    blink::V8EventListenerInfoList* event_information);

  static void Create(automation::DOMSnapshotRequest request, PageInstance* page_instance);

  DOMSnapshotDispatcher(automation::DOMSnapshotRequest request, PageInstance* page_instance);
  DOMSnapshotDispatcher(PageInstance* page_instance);
  ~DOMSnapshotDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::DOMSnapshotAssociatedRequest request);

  void Register(int32_t application_id) override;
  void GetSnapshot(const std::vector<std::string>& computed_style_whitelist, bool include_event_listeners, bool include_paint_order, bool include_user_agent_shadow_tree, GetSnapshotCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  // Adds a DOMNode for the given Node to |dom_nodes_| and returns its index.
  int VisitNode(blink::Node*,
                bool include_event_listeners,
                bool include_user_agent_shadow_tree);

  // Helpers for VisitContainerChildren.
  static blink::Node* FirstChild(const blink::Node& node,
                          bool include_user_agent_shadow_tree);
  static bool HasChildren(const blink::Node& node,
                          bool include_user_agent_shadow_tree);
  static blink::Node* NextSibling(const blink::Node& node,
                           bool include_user_agent_shadow_tree);

  std::vector<int> VisitContainerChildren(
      blink::Node* container,
      bool include_event_listeners,
      bool include_user_agent_shadow_tree);
  std::vector<int> VisitPseudoElements(
      blink::Element* parent,
      bool include_event_listeners,
      bool include_user_agent_shadow_tree);
  std::vector<automation::NameValuePtr> BuildArrayForElementAttributes(blink::Element*);

  // Adds a LayoutTreeNode for the LayoutObject of the given Node to
  // |layout_tree_nodes_| and returns its index. Returns -1 if the Node has no
  // associated LayoutObject.
  int VisitLayoutTreeNode(blink::Node*, int node_index);

  // Returns the index of the ComputedStyle in |computed_styles_| for the given
  // Node. Adds a new ComputedStyle if necessary, but ensures no duplicates are
  // added to |computed_styles_|. Returns -1 if the node has no values for
  // styles in |style_whitelist_|.
  int GetStyleIndexForNode(blink::Node*);

  // Traverses the PaintLayer tree in paint order to fill |paint_order_map_|.
  void TraversePaintLayerTree(blink::Document*);
  void VisitPaintLayer(blink::PaintLayer*);

  std::vector<automation::EventListenerPtr> BuildObjectsForEventListeners(
    const blink::V8EventListenerInfoList& event_information,
    v8::Local<v8::Context> context,
    const v8_inspector::StringView& object_group_id);

  automation::EventListenerPtr BuildObjectForEventListener(v8::Local<v8::Context>,
    const blink::V8EventListenerInfo&,
    const v8_inspector::StringView& object_group_id);

  struct VectorStringHashTraits;
  using ComputedStylesMap = WTF::HashMap<Vector<String>,
                                         int,
                                         VectorStringHashTraits,
                                         VectorStringHashTraits>;
  using CSSPropertyWhitelist = Vector<std::pair<String, blink::CSSPropertyID>>;
  using PaintOrderMap = WTF::HashMap<blink::PaintLayer*, int>;

  int32_t application_id_;
  std::vector<automation::DOMSnapshotNodePtr> dom_nodes_;
  std::vector<automation::LayoutTreeNodePtr> layout_tree_nodes_;
  std::vector<automation::ComputedStylePtr> computed_styles_;
  // Maps a style string vector to an index in |computed_styles_|. Used to avoid
  // duplicate entries in |computed_styles_|.
  std::unique_ptr<ComputedStylesMap> computed_styles_map_;
  std::unique_ptr<Vector<std::pair<String, blink::CSSPropertyID>>> css_property_whitelist_;
  // Maps a PaintLayer to its paint order index.
  std::unique_ptr<PaintOrderMap> paint_order_map_;
  
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::DOMSnapshot> binding_;
  // State of current snapshot.
  int next_paint_order_index_ = 0;

  blink::Member<blink::InspectorDOMDebuggerAgent> dom_debugger_agent_;
  
  DISALLOW_COPY_AND_ASSIGN(DOMSnapshotDispatcher); 
};

}

#endif