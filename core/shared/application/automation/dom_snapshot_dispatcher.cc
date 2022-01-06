// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/dom_snapshot_dispatcher.h"

#include "core/shared/application/automation/dom_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/script_event_listener.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_target.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/attribute_collection.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_debugger_agent.h"
#include "third_party/blink/renderer/core/inspector/resolve_node.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/line/inline_text_box.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_stacking_node.h"
#include "third_party/blink/renderer/core/paint/paint_layer_stacking_node_iterator.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

namespace {

String DocumentURLString(blink::Document* document) {
  if (!document || document->Url().IsNull())
    return "";
  return document->Url().GetString();
}

String DocumentBaseURLString(blink::Document* document) {
  return document->BaseURL().GetString();
}

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

gfx::Rect BuildRectForFloatRect(const blink::FloatRect& rect) {
  return gfx::Rect(rect.X(), rect.Y(), rect.Width(), rect.Height());
}

blink::Document* GetEmbeddedDocument(blink::PaintLayer* layer) {
  // Documents are embedded on their own PaintLayer via a LayoutEmbeddedContent.
  if (layer->GetLayoutObject().IsLayoutEmbeddedContent()) {
    blink::FrameView* frame_view =
        ToLayoutEmbeddedContent(layer->GetLayoutObject()).ChildFrameView();
    if (frame_view && frame_view->IsLocalFrameView()) {
      blink::LocalFrameView* local_frame_view = ToLocalFrameView(frame_view);
      return local_frame_view->GetFrame().GetDocument();
    }
  }
  return nullptr;
}

}

struct DOMSnapshotDispatcher::VectorStringHashTraits
    : public WTF::GenericHashTraits<Vector<String>> {
  static unsigned GetHash(const Vector<String>& vec) {
    unsigned h = DefaultHash<size_t>::Hash::GetHash(vec.size());
    for (size_t i = 0; i < vec.size(); i++) {
      h = WTF::HashInts(h, DefaultHash<String>::Hash::GetHash(vec[i]));
    }
    return h;
  }

  static bool Equal(const Vector<String>& a, const Vector<String>& b) {
    if (a.size() != b.size())
      return false;
    for (size_t i = 0; i < a.size(); i++) {
      if (a[i] != b[i])
        return false;
    }
    return true;
  }

  static void ConstructDeletedValue(Vector<String>& vec, bool) {
    new (NotNull, &vec) Vector<String>(WTF::kHashTableDeletedValue);
  }

  static bool IsDeletedValue(const Vector<String>& vec) {
    return vec.IsHashTableDeletedValue();
  }

  static bool IsEmptyValue(const Vector<String>& vec) { return vec.IsEmpty(); }

  static const bool kEmptyValueIsZero = false;
  static const bool safe_to_compare_to_empty_or_deleted = false;
  static const bool kHasIsEmptyValueFunction = true;
};

// static 
void DOMSnapshotDispatcher::Create(automation::DOMSnapshotRequest request, PageInstance* page_instance) {
  new DOMSnapshotDispatcher(std::move(request), page_instance);
}

DOMSnapshotDispatcher::DOMSnapshotDispatcher(automation::DOMSnapshotRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

DOMSnapshotDispatcher::DOMSnapshotDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

DOMSnapshotDispatcher::~DOMSnapshotDispatcher() {

}

void DOMSnapshotDispatcher::Init(IPC::SyncChannel* channel) {

}

void DOMSnapshotDispatcher::Bind(automation::DOMSnapshotAssociatedRequest request) {
  //DLOG(INFO) << "DOMSnapshotDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void DOMSnapshotDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void DOMSnapshotDispatcher::GetSnapshot(const std::vector<std::string>& style_whitelist, bool include_event_listeners, bool include_paint_order, bool include_user_agent_shadow_tree, GetSnapshotCallback callback) {
  blink::Document* document = page_instance_->inspected_frames()->Root()->GetDocument();
  if (!document) {
    //DLOG(ERROR) << "Document is not available";
    std::move(callback).Run(
      std::vector<automation::DOMSnapshotNodePtr>(),
      std::vector<automation::LayoutTreeNodePtr>(),
      std::vector<automation::ComputedStylePtr>());
    return;
  }

  // Setup snapshot.
  computed_styles_map_ = std::make_unique<ComputedStylesMap>();
  css_property_whitelist_ = std::make_unique<CSSPropertyWhitelist>();

  // Look up the CSSPropertyIDs for each entry in |style_whitelist|.
  for (size_t i = 0; i < style_whitelist.size(); i++) {
    String cur_style = String::FromUTF8(style_whitelist[i].data());
    blink::CSSPropertyID property_id = blink::cssPropertyID(cur_style);
    if (property_id == blink::CSSPropertyInvalid)
      continue;
    css_property_whitelist_->push_back(
        std::make_pair(cur_style, property_id));
  }

  if (include_paint_order) {
    paint_order_map_ = std::make_unique<PaintOrderMap>();
    next_paint_order_index_ = 0;
    TraversePaintLayerTree(document);
  }

  // Actual traversal.
  VisitNode(document, include_event_listeners, include_user_agent_shadow_tree);

  // Extract results from state and reset.
  std::move(callback).Run(
    std::move(dom_nodes_),
    std::move(layout_tree_nodes_),
    std::move(computed_styles_));
  computed_styles_map_.reset();
  css_property_whitelist_.reset();
  paint_order_map_.reset();
}

int DOMSnapshotDispatcher::VisitNode(blink::Node* node,
                                     bool include_event_listeners,
                                     bool include_user_agent_shadow_tree) {
  // Update layout tree before traversal of document so that we inspect a
  // current and consistent state of all trees. No need to do this if paint
  // order was calculated, since layout trees were already updated during
  // TraversePaintLayerTree().
  if (node->IsDocumentNode() && !paint_order_map_) {
    node->GetDocument().UpdateStyleAndLayoutTree();
  }

  String node_value;
  switch (node->getNodeType()) {
    case blink::Node::kTextNode:
    case blink::Node::kAttributeNode:
    case blink::Node::kCommentNode:
    case blink::Node::kCdataSectionNode:
    case blink::Node::kDocumentFragmentNode:
      node_value = node->nodeValue();
      break;
    default:
      break;
  }

  // Create DOMNode object and add it to the result array before traversing
  // children, so that parents appear before their children in the array.
  automation::DOMSnapshotNodePtr owned_value = automation::DOMSnapshotNode::New();
  owned_value->node_type = static_cast<int>(node->getNodeType());
  owned_value->node_name = std::string(node->nodeName().Utf8().data());
  owned_value->node_value = std::string(node_value.Utf8().data());
  owned_value->backend_node_id = blink::DOMNodeIds::IdForNode(node);

  automation::DOMSnapshotNode* value = owned_value.get();
  int index = dom_nodes_.size();
  dom_nodes_.push_back(std::move(owned_value));

  int layoutNodeIndex = VisitLayoutTreeNode(node, index);
  if (layoutNodeIndex != -1)
    value->layout_node_index = layoutNodeIndex;

  if (node->WillRespondToMouseClickEvents())
    value->is_clickable = true;

  if (include_event_listeners && node->GetDocument().GetFrame()) {
    blink::ScriptState* script_state =
      blink::ToScriptStateForMainWorld(node->GetDocument().GetFrame());
    if (script_state->ContextIsValid()) {
      blink::ScriptState::Scope scope(script_state);
      v8::Local<v8::Context> context = script_state->GetContext();
      blink::V8EventListenerInfoList event_information;
      DOMSnapshotDispatcher::CollectEventListeners(
          script_state->GetIsolate(), node, v8::Local<v8::Value>(), node, true,
          &event_information);
      if (!event_information.IsEmpty()) {
        value->event_listeners = 
         BuildObjectsForEventListeners(
              event_information, 
              context, 
              v8_inspector::StringView());
      }
    }
  }

  if (node->IsElementNode()) {
    blink::Element* element = blink::ToElement(node);
    value->attributes = BuildArrayForElementAttributes(element);

    if (node->IsFrameOwnerElement()) {
      const blink::HTMLFrameOwnerElement* frame_owner = blink::ToHTMLFrameOwnerElement(node);
      if (blink::LocalFrame* frame =
              frame_owner->ContentFrame() &&
                      frame_owner->ContentFrame()->IsLocalFrame()
                  ? blink::ToLocalFrame(frame_owner->ContentFrame())
                  : nullptr) {
        value->frame_id = std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data());
      }
      if (blink::Document* doc = frame_owner->contentDocument()) {
        value->content_document_index = VisitNode(
            doc, include_event_listeners, include_user_agent_shadow_tree);
      }
    }

    if (node->parentNode() && node->parentNode()->IsDocumentNode()) {
      blink::LocalFrame* frame = node->GetDocument().GetFrame();
      if (frame)
        value->frame_id = std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data());
    }

    if (auto* link_element = ToHTMLLinkElementOrNull(*element)) {
      if (link_element->IsImport() && link_element->import() &&
          DOMDispatcher::InnerParentNode(link_element->import()) ==
              link_element) {
        value->imported_document_index = 
            VisitNode(link_element->import(), include_event_listeners,
                      include_user_agent_shadow_tree);
      }
    }

    if (auto* template_element = ToHTMLTemplateElementOrNull(*element)) {
      value->template_content_index = VisitNode(template_element->content(),
                                               include_event_listeners,
                                               include_user_agent_shadow_tree);
    }

    if (auto* textarea_element = ToHTMLTextAreaElementOrNull(*element))
      value->text_value = std::string(textarea_element->value().Utf8().data());

    if (auto* input_element = ToHTMLInputElementOrNull(*element)) {
      value->input_value = std::string(input_element->value().Utf8().data());
      if ((input_element->type() == blink::InputTypeNames::radio) ||
          (input_element->type() == blink::InputTypeNames::checkbox)) {
        value->input_checked = input_element->checked();
      }
    }

    if (auto* option_element = ToHTMLOptionElementOrNull(*element))
      value->option_selected = option_element->Selected();

    if (element->GetPseudoId()) {
      automation::PseudoType pseudo_type;
      if (DOMDispatcher::GetPseudoElementType(element->GetPseudoId(),
                                              &pseudo_type)) {
        value->pseudo_type = pseudo_type;
      }
    } else {
      value->pseudo_element_indexes = VisitPseudoElements(
          element, include_event_listeners, include_user_agent_shadow_tree);
    }

    blink::HTMLImageElement* image_element = ToHTMLImageElementOrNull(node);
    if (image_element)
      value->current_source_url = std::string(image_element->currentSrc().Utf8().data());
  } else if (node->IsDocumentNode()) {
    blink::Document* document = ToDocument(node);
    value->document_url = std::string(DocumentURLString(document).Utf8().data());
    value->base_url = std::string(DocumentBaseURLString(document).Utf8().data());
    if (document->ContentLanguage())
      value->content_language = std::string(document->ContentLanguage().Utf8().data());
    if (document->EncodingName())
      value->document_encoding = std::string(document->EncodingName().Utf8().data());
    value->frame_id = std::string(blink::IdentifiersFactory::FrameId(document->GetFrame()).Utf8().data());
  } else if (node->IsDocumentTypeNode()) {
    blink::DocumentType* doc_type = ToDocumentType(node);
    value->public_id = std::string(doc_type->publicId().Utf8().data());
    value->system_id = std::string(doc_type->systemId().Utf8().data());
  }
  if (node->IsInShadowTree()) {
    value->shadow_root_type = GetShadowRootType(node->ContainingShadowRoot());
  }

  if (node->IsContainerNode()) {
    value->child_node_indexes = VisitContainerChildren(
        node, include_event_listeners, include_user_agent_shadow_tree);
  }
  return index;
}

blink::Node* DOMSnapshotDispatcher::FirstChild(
  const blink::Node& node,
  bool include_user_agent_shadow_tree) {
  DCHECK(include_user_agent_shadow_tree || !node.IsInUserAgentShadowRoot());
  if (!include_user_agent_shadow_tree) {
    blink::ShadowRoot* shadow_root = node.GetShadowRoot();
    if (shadow_root && shadow_root->GetType() == blink::ShadowRootType::kUserAgent) {
      blink::Node* child = node.firstChild();
      while (child && !child->CanParticipateInFlatTree())
        child = child->nextSibling();
      return child;
    }
  }
  return blink::FlatTreeTraversal::FirstChild(node);
}

bool DOMSnapshotDispatcher::HasChildren(
    const blink::Node& node,
    bool include_user_agent_shadow_tree) {
  return FirstChild(node, include_user_agent_shadow_tree);
}

blink::Node* DOMSnapshotDispatcher::NextSibling(
    const blink::Node& node,
    bool include_user_agent_shadow_tree) {
  DCHECK(include_user_agent_shadow_tree || !node.IsInUserAgentShadowRoot());
  if (!include_user_agent_shadow_tree) {
    if (node.ParentElementShadowRoot() &&
        node.ParentElementShadowRoot()->GetType() == blink::ShadowRootType::kUserAgent) {
      blink::Node* sibling = node.nextSibling();
      while (sibling && !sibling->CanParticipateInFlatTree())
        sibling = sibling->nextSibling();
      return sibling;
    }
  }
  return blink::FlatTreeTraversal::NextSibling(node);
}

std::vector<int> DOMSnapshotDispatcher::VisitContainerChildren(
  blink::Node* container,
  bool include_event_listeners,
  bool include_user_agent_shadow_tree) {
  std::vector<int> children;

  if (!HasChildren(*container, include_user_agent_shadow_tree))
    return std::vector<int>();

  blink::Node* child = FirstChild(*container, include_user_agent_shadow_tree);
  while (child) {
    children.push_back(VisitNode(child, include_event_listeners,
                                 include_user_agent_shadow_tree));
    child = NextSibling(*child, include_user_agent_shadow_tree);
  }

  return children;
}

std::vector<int> DOMSnapshotDispatcher::VisitPseudoElements(
  blink::Element* parent,
  bool include_event_listeners,
  bool include_user_agent_shadow_tree) {
  if (!parent->GetPseudoElement(blink::kPseudoIdBefore) &&
      !parent->GetPseudoElement(blink::kPseudoIdAfter)) {
    return std::vector<int>();
  }

  std::vector<int> pseudo_elements;

  if (parent->GetPseudoElement(blink::kPseudoIdBefore)) {
    pseudo_elements.push_back(
        VisitNode(parent->GetPseudoElement(blink::kPseudoIdBefore),
                  include_event_listeners, include_user_agent_shadow_tree));
  }
  if (parent->GetPseudoElement(blink::kPseudoIdAfter)) {
    pseudo_elements.push_back(VisitNode(parent->GetPseudoElement(blink::kPseudoIdAfter),
                                       include_event_listeners,
                                       include_user_agent_shadow_tree));
  }

  return pseudo_elements;
}

std::vector<automation::NameValuePtr> DOMSnapshotDispatcher::BuildArrayForElementAttributes(blink::Element* element) {
  std::vector<automation::NameValuePtr> attributes_value;
  blink::AttributeCollection attributes = element->Attributes();
  for (const auto& attribute : attributes) {
    automation::NameValuePtr name_value = automation::NameValue::New();
    name_value->name = std::string(attribute.GetName().ToString().Utf8().data());
    name_value->value = std::string(attribute.Value().Utf8().data());
    attributes_value.push_back(std::move(name_value));
  }
  return attributes_value;
}

int DOMSnapshotDispatcher::VisitLayoutTreeNode(blink::Node* node, int node_index) {
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return -1;

  auto layout_tree_node = automation::LayoutTreeNode::New();
  layout_tree_node->dom_node_index = node_index;
  layout_tree_node->bounding_box = BuildRectForFloatRect(
                                   layout_object->AbsoluteBoundingBoxRect());

  int style_index = GetStyleIndexForNode(node);
  if (style_index != -1)
    layout_tree_node->style_index = style_index;

  if (paint_order_map_) {
    blink::PaintLayer* paint_layer = layout_object->EnclosingLayer();

    // We visited all PaintLayers when building |paint_order_map_|.
    DCHECK(paint_order_map_->Contains(paint_layer));

    if (int paint_order = paint_order_map_->at(paint_layer))
      layout_tree_node->paint_order = paint_order;
  }

  if (layout_object->IsText()) {
    blink::LayoutText* layout_text = ToLayoutText(layout_object);
    layout_tree_node->layout_text = std::string(layout_text->GetText().Utf8().data());
    if (layout_text->HasTextBoxes()) {
      std::vector<automation::InlineTextBoxPtr> inline_text_nodes;
      for (const blink::InlineTextBox* text_box : layout_text->TextBoxes()) {
        auto inline_text_node = automation::InlineTextBox::New();
        blink::FloatRect local_coords_text_box_rect(text_box->FrameRect());
        blink::FloatRect absolute_coords_text_box_rect =
            layout_object->LocalToAbsoluteQuad(local_coords_text_box_rect)
                .BoundingBox();
        inline_text_node->start_character_index = text_box->Start();
        inline_text_node->num_characters = text_box->Len();
        inline_text_node->bounding_box = BuildRectForFloatRect(absolute_coords_text_box_rect);
        inline_text_nodes.push_back(std::move(inline_text_node));
      }
      layout_tree_node->inline_text_nodes = std::move(inline_text_nodes);
    }
  }

  int index = layout_tree_nodes_.size();
  layout_tree_nodes_.push_back(std::move(layout_tree_node));
  return index;
}

int DOMSnapshotDispatcher::GetStyleIndexForNode(blink::Node* node) {
  blink::CSSComputedStyleDeclaration* computed_style_info =
    blink::CSSComputedStyleDeclaration::Create(node, true);

  Vector<String> style;
  bool all_properties_empty = true;
  for (const auto& pair : *css_property_whitelist_) {
    String value = computed_style_info->GetPropertyValue(pair.second);
    if (!value.IsEmpty())
      all_properties_empty = false;
    style.push_back(value);
  }

  // -1 means an empty style.
  if (all_properties_empty)
    return -1;

  ComputedStylesMap::iterator it = computed_styles_map_->find(style);
  if (it != computed_styles_map_->end())
    return it->value;

  // It's a distinct style, so append to |computedStyles|.
  std::vector<automation::NameValuePtr> style_properties;

  for (size_t i = 0; i < style.size(); i++) {
    if (style[i].IsEmpty())
      continue;
    auto name_value = automation::NameValue::New();
    name_value->name = std::string(((*css_property_whitelist_)[i].first).Utf8().data());
    name_value->value = std::string(style[i].Utf8().data());
    style_properties.push_back(std::move(name_value));
  }

  size_t index = computed_styles_.size();
  auto computed_style = automation::ComputedStyle::New();
  computed_style->properties = std::move(style_properties);
       
  computed_styles_.push_back(std::move(computed_style));
  computed_styles_map_->insert(std::move(style), index);
  return index;
}

void DOMSnapshotDispatcher::TraversePaintLayerTree(blink::Document* document) {
  // Update layout tree before traversal of document so that we inspect a
  // current and consistent state of all trees.
  document->UpdateStyleAndLayoutTree();

  blink::PaintLayer* root_layer = document->GetLayoutView()->Layer();
  // LayoutView requires a PaintLayer.
  DCHECK(root_layer);

  VisitPaintLayer(root_layer);
}

void DOMSnapshotDispatcher::VisitPaintLayer(blink::PaintLayer* layer) {
  DCHECK(!paint_order_map_->Contains(layer));

  paint_order_map_->Set(layer, next_paint_order_index_);
  next_paint_order_index_++;

  // If there is an embedded document, integrate it into the painting order.
  blink::Document* embedded_document = GetEmbeddedDocument(layer);
  if (embedded_document)
    TraversePaintLayerTree(embedded_document);

  // If there's an embedded document, there shouldn't be any children.
  DCHECK(!embedded_document || !layer->FirstChild());

  if (!embedded_document) {
    blink::PaintLayerStackingNode* node = layer->StackingNode();
    blink::PaintLayerStackingNodeIterator iterator(*node, blink::kAllChildren);
    while (blink::PaintLayerStackingNode* child_node = iterator.Next()) {
      VisitPaintLayer(child_node->Layer());
    }
  }
}

std::vector<automation::EventListenerPtr> DOMSnapshotDispatcher::BuildObjectsForEventListeners(
    const blink::V8EventListenerInfoList& event_information,
    v8::Local<v8::Context> context,
    const v8_inspector::StringView& object_group_id) {
  std::vector<automation::EventListenerPtr> listeners_array;
  // Make sure listeners with |use_capture| true come first because they have
  // precedence.
  for (const auto& info : event_information) {
    if (!info.use_capture)
      continue;
    automation::EventListenerPtr listener_object = BuildObjectForEventListener(context, info, object_group_id);
    if (listener_object)
      listeners_array.push_back(std::move(listener_object));
  }
  for (const auto& info : event_information) {
    if (info.use_capture)
      continue;
    automation::EventListenerPtr listener_object = BuildObjectForEventListener(context, info, object_group_id);
    if (listener_object)
      listeners_array.push_back(std::move(listener_object));
  }
  return listeners_array;
}

automation::EventListenerPtr DOMSnapshotDispatcher::BuildObjectForEventListener(
    v8::Local<v8::Context> context,
    const blink::V8EventListenerInfo& info,
    const v8_inspector::StringView& object_group_id) {

  if (info.handler.IsEmpty())
    return nullptr;

  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::Function> function = blink::EventListenerEffectiveFunction(isolate, info.handler);
  if (function.IsEmpty())
    return nullptr;

  String script_id;
  int line_number;
  int column_number;
  blink::GetFunctionLocation(function, script_id, line_number, column_number);

  automation::EventListenerPtr value = automation::EventListener::New();
  value->type = std::string(info.event_type.Utf8().data());
  value->use_capture = info.use_capture;
  value->passive = info.passive;
  value->once = info.once ;
  value->script_id = std::string(script_id.Utf8().data());
  value->line_number = line_number;
  value->column_number = column_number;
          
  if (object_group_id.length()) {
    // value->setHandler(v8_session_->wrapObject(
    //     context, function, object_group_id, false /* generatePreview */));
    // value->setOriginalHandler(v8_session_->wrapObject(
    //     context, info.handler, object_group_id, false /* generatePreview */));
    if (info.backend_node_id) {
      value->backend_node_id = info.backend_node_id;
    }
  }
  return value;
}

// static
void DOMSnapshotDispatcher::CollectEventListeners(
  v8::Isolate* isolate,
  blink::EventTarget* target,
  v8::Local<v8::Value> target_wrapper,
  blink::Node* target_node,
  bool report_for_all_contexts,
  blink::V8EventListenerInfoList* event_information) {
  if (!target->GetExecutionContext())
    return;

  blink::ExecutionContext* execution_context = target->GetExecutionContext();

  // Nodes and their Listeners for the concerned event types (order is top to
  // bottom).
  Vector<AtomicString> event_types = target->EventTypes();
  for (size_t j = 0; j < event_types.size(); ++j) {
    AtomicString& type = event_types[j];
    blink::EventListenerVector* listeners = target->GetEventListeners(type);
    if (!listeners)
      continue;
    for (size_t k = 0; k < listeners->size(); ++k) {
      blink::EventListener* event_listener = listeners->at(k).Callback();
      if (event_listener->GetType() != blink::EventListener::kJSEventListenerType)
        continue;
      blink::V8AbstractEventListener* v8_listener =
          static_cast<blink::V8AbstractEventListener*>(event_listener);
      v8::Local<v8::Context> context = blink::ToV8Context(execution_context, v8_listener->World());
      // Optionally hide listeners from other contexts.
      if (!report_for_all_contexts && context != isolate->GetCurrentContext())
        continue;
      // getListenerObject() may cause JS in the event attribute to get
      // compiled, potentially unsuccessfully.  In that case, the function
      // returns the empty handle without an exception.
      v8::Local<v8::Object> handler =
          v8_listener->GetListenerObject(execution_context);
      if (handler.IsEmpty())
        continue;
      bool use_capture = listeners->at(k).Capture();
      int backend_node_id = 0;
      if (target_node) {
        backend_node_id = blink::DOMNodeIds::IdForNode(target_node);
        target_wrapper = blink::NodeV8Value(
            report_for_all_contexts ? context : isolate->GetCurrentContext(),
            target_node);
      }
      event_information->push_back(blink::V8EventListenerInfo(
          type, use_capture, listeners->at(k).Passive(),
          listeners->at(k).Once(), handler, backend_node_id));
    }
  }
}

void DOMSnapshotDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}