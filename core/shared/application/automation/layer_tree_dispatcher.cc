// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/layer_tree_dispatcher.h"

#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "third_party/blink/renderer/core/inspector/inspector_layer_tree_agent.h"
#include "third_party/blink/public/platform/web_float_point.h"
#include "third_party/blink/public/platform/web_layer.h"
#include "third_party/blink/public/platform/web_layer_sticky_position_constraint.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/compositing/composited_layer_mapping.h"
#include "third_party/blink/renderer/core/paint/compositing/paint_layer_compositor.h"
#include "third_party/blink/renderer/platform/geometry/int_rect.h"
#include "third_party/blink/renderer/platform/graphics/compositing_reasons.h"
#include "third_party/blink/renderer/platform/graphics/compositor_element_id.h"
#include "third_party/blink/renderer/platform/graphics/graphics_layer.h"
#include "third_party/blink/renderer/platform/graphics/picture_snapshot.h"
#include "third_party/blink/renderer/platform/transforms/transformation_matrix.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

namespace {

inline String IdForLayer(const blink::GraphicsLayer* graphics_layer) {
  return String::Number(graphics_layer->PlatformLayer()->Id());
}

void ParseRect(const gfx::Rect& object, blink::FloatRect* rect) {
  *rect = blink::FloatRect(object.x(), object.y(), object.width(), object.height());
}

gfx::Rect BuildObjectForRect(const blink::WebRect& rect) {
  gfx::Rect rrect;
  rrect.set_x(rect.x); 
  rrect.set_y(rect.y); 
  rrect.set_height(rect.height);
  rrect.set_width(rect.width);
  return rrect;
}

automation::ScrollRectPtr BuildScrollRect(
  const blink::WebRect& rect,
  automation::ScrollRectType type) {
  gfx::Rect rect_object = BuildObjectForRect(rect);
  automation::ScrollRectPtr scroll_rect_object = automation::ScrollRect::New();
  scroll_rect_object->rect = std::move(rect_object);
  scroll_rect_object->type = type;
  return scroll_rect_object;
}

std::vector<automation::ScrollRectPtr> BuildScrollRectsForLayer(
  blink::GraphicsLayer* graphics_layer,
  bool report_wheel_scrollers) {
  std::vector<automation::ScrollRectPtr> scroll_rects;
  blink::WebLayer* web_layer = graphics_layer->PlatformLayer();
  blink::WebVector<blink::WebRect> non_fast_scrollable_rects =
      web_layer->NonFastScrollableRegion();
  for (size_t i = 0; i < non_fast_scrollable_rects.size(); ++i) {
    scroll_rects.push_back(BuildScrollRect(
        non_fast_scrollable_rects[i],
        automation::ScrollRectType::kSCROLL_RECT_TYPE_REPAINTS_ON_SCROLL));
  }
  blink::WebVector<blink::WebRect> touch_event_handler_rects =
      web_layer->TouchEventHandlerRegion();
  for (size_t i = 0; i < touch_event_handler_rects.size(); ++i) {
    scroll_rects.push_back(BuildScrollRect(
        touch_event_handler_rects[i],
        automation::ScrollRectType::kSCROLL_RECT_TYPE_TOUCH_EVENT_HANDLER));
  }
  if (report_wheel_scrollers) {
    blink::WebRect web_rect(web_layer->GetPosition().x, web_layer->GetPosition().y,
                            web_layer->Bounds().width, web_layer->Bounds().height);
    scroll_rects.push_back(BuildScrollRect(
        web_rect,
        automation::ScrollRectType::kSCROLL_RECT_TYPE_WHEEL_EVENT_HANDLER));
  }
  return scroll_rects;
}

// TODO(flackr): We should be getting the sticky position constraints from the
// property tree once blink is able to access them. https://crbug.com/754339
blink::GraphicsLayer* FindLayerByElementId(blink::GraphicsLayer* root,
                                    blink::CompositorElementId element_id) {
  if (root->PlatformLayer()->GetElementId() == element_id)
    return root;
  for (size_t i = 0, size = root->Children().size(); i < size; ++i) {
    if (blink::GraphicsLayer* layer = FindLayerByElementId(root->Children()[i], element_id))
      return layer;
  }
  return nullptr;
}

blink::GraphicsLayer* FindLayerById(blink::GraphicsLayer* root, int layer_id) {
  if (root->PlatformLayer()->Id() == layer_id)
    return root;
  for (size_t i = 0, size = root->Children().size(); i < size; ++i) {
    if (blink::GraphicsLayer* layer = FindLayerById(root->Children()[i], layer_id))
      return layer;
  }
  return nullptr;
}

automation::StickyPositionConstraintPtr BuildStickyInfoForLayer(blink::GraphicsLayer* root, blink::WebLayer* layer) {
  blink::WebLayerStickyPositionConstraint constraints =
      layer->StickyPositionConstraint();
  if (!constraints.is_sticky)
    return nullptr;

  gfx::Rect sticky_box_rect = BuildObjectForRect(constraints.scroll_container_relative_sticky_box_rect);

  gfx::Rect containing_block_rect =
      BuildObjectForRect(
          constraints.scroll_container_relative_containing_block_rect);

  automation::StickyPositionConstraintPtr
      constraints_obj = automation::StickyPositionConstraint::New();
  constraints_obj->sticky_box_rect = std::move(sticky_box_rect);
  constraints_obj->containing_block_rect = std::move(containing_block_rect);
  
  if (constraints.nearest_element_shifting_sticky_box) {
    constraints_obj->nearest_layer_shifting_sticky_box = std::string(String::Number(
        FindLayerByElementId(root,
                             constraints.nearest_element_shifting_sticky_box)
            ->PlatformLayer()
            ->Id()).Utf8().data());
  }
  if (constraints.nearest_element_shifting_containing_block) {
    constraints_obj->nearest_layer_shifting_containing_block = std::string(String::Number(
        FindLayerByElementId(
            root, constraints.nearest_element_shifting_containing_block)
            ->PlatformLayer()
            ->Id()).Utf8().data());
  }

  return constraints_obj;
}

automation::LayerPtr BuildObjectForLayer(
  blink::GraphicsLayer* root,
  blink::GraphicsLayer* graphics_layer,
  int node_id,
  bool report_wheel_event_listeners) {
  blink::WebLayer* web_layer = graphics_layer->PlatformLayer();
  automation::LayerPtr layer_object = automation::Layer::New();

  layer_object->layer_id = std::string(IdForLayer(graphics_layer).Utf8().data());
  layer_object->offset_x = web_layer->GetPosition().x;
  layer_object->offset_y = web_layer->GetPosition().y;
  layer_object->width = web_layer->Bounds().width;
  layer_object->height = web_layer->Bounds().height;
  layer_object->paint_count = graphics_layer->PaintCount();
  layer_object->draws_content = web_layer->DrawsContent();
          
  if (node_id)
    layer_object->backend_node_id = node_id;

  blink::GraphicsLayer* parent = graphics_layer->Parent();
  if (parent)
    layer_object->parent_layer_id = std::string(IdForLayer(parent).Utf8().data());
  if (!graphics_layer->ContentsAreVisible())
    layer_object->invisible = true;
  const blink::TransformationMatrix& transform = graphics_layer->Transform();
  if (!transform.IsIdentity()) {
    blink::TransformationMatrix::FloatMatrix4 flattened_matrix;
    transform.ToColumnMajorFloatArray(flattened_matrix);
    std::vector<double> transform_array;
    for (size_t i = 0; i < arraysize(flattened_matrix); ++i)
      transform_array.push_back(flattened_matrix[i]);
    layer_object->transform = std::move(transform_array);
    const blink::FloatPoint3D& transform_origin = graphics_layer->TransformOrigin();
    // FIXME: rename these to setTransformOrigin*
    if (web_layer->Bounds().width > 0)
      layer_object->anchor_x = (transform_origin.X() /
                               web_layer->Bounds().width);
    else
      layer_object->anchor_x = 0.0;
    if (web_layer->Bounds().height > 0)
      layer_object->anchor_y = (transform_origin.Y() /
                               web_layer->Bounds().height);
    else
      layer_object->anchor_y = 0.0;
    layer_object->anchor_z = transform_origin.Z();
  }
  std::vector<automation::ScrollRectPtr> scroll_rects = BuildScrollRectsForLayer(graphics_layer, report_wheel_event_listeners);
  if (scroll_rects.size() > 0)
    layer_object->scroll_rects = std::move(scroll_rects);
  automation::StickyPositionConstraintPtr sticky_info = BuildStickyInfoForLayer(root, web_layer);
  if (sticky_info)
    layer_object->sticky_position_constraint = std::move(sticky_info);
  return layer_object;
}

}

class InspectorLayerTreeAgentImpl : public blink::InspectorLayerTreeAgent,
                                    public blink::InspectorLayerTreeAgent::Client {
public:
  InspectorLayerTreeAgentImpl(LayerTreeDispatcher* dispatcher): 
    blink::InspectorLayerTreeAgent(dispatcher->page_instance_->inspected_frames(), 
                                   this),
    dispatcher_(dispatcher) {}

  void LayerTreeDidChange() override {
    dispatcher_->LayerTreeDidChange();
  }
  
  void DidPaint(const blink::GraphicsLayer* graphics_layer, blink::GraphicsContext& context, const blink::LayoutRect& rect) override {
    dispatcher_->DidPaint(graphics_layer, context, rect);
  }

  bool IsInspectorLayer(blink::GraphicsLayer* layer) override {
    return true;
  }

private:
  LayerTreeDispatcher* dispatcher_;
};

unsigned LayerTreeDispatcher::last_snapshot_id_ = 0;

// static 
void LayerTreeDispatcher::Create(automation::LayerTreeRequest request, PageInstance* page_instance) {
  new LayerTreeDispatcher(std::move(request), page_instance);
}

LayerTreeDispatcher::LayerTreeDispatcher(
  automation::LayerTreeRequest request, 
  PageInstance* page_instance): 
    application_id_(-1),
    page_instance_(page_instance),
    binding_(this),
    suppress_layer_paint_events_(false),
    enabled_(false) {
  
}

LayerTreeDispatcher::LayerTreeDispatcher(
  PageInstance* page_instance): 
    application_id_(-1),
    page_instance_(page_instance),
    binding_(this),
    suppress_layer_paint_events_(false),
    enabled_(false) {
  
}

LayerTreeDispatcher::~LayerTreeDispatcher() {

}

void LayerTreeDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&layer_client_ptr_);
}

void LayerTreeDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void LayerTreeDispatcher::Bind(automation::LayerTreeAssociatedRequest request) {
  //DLOG(INFO) << "LayerTreeDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

bool LayerTreeDispatcher::LayerById(const String& layer_id,
                                    blink::GraphicsLayer*& result) {
  bool ok;
  int id = layer_id.ToInt(&ok);
  if (!ok) {
    //DLOG(ERROR) << "Invalid layer id";
    return false;
  }
  blink::PaintLayerCompositor* compositor = GetPaintLayerCompositor();
  if (!compositor) {
    //DLOG(ERROR) << "Not in compositing mode";
    return false;
  }

  result = FindLayerById(RootGraphicsLayer(), id);
  if (!result) {
    //DLOG(ERROR) << "No layer matching given id found";
    return false;
  }
  return true;
}

void LayerTreeDispatcher::CompositingReasons(const std::string& layer_id, CompositingReasonsCallback callback) {
  std::vector<std::string> reasons;
  blink::GraphicsLayer* graphics_layer = nullptr;
  bool ok = LayerById(String::FromUTF8(layer_id.data()), graphics_layer);
  if (!ok) {
    std::move(callback).Run(std::move(reasons));
    return;
  }
  blink::CompositingReasons reasons_bitmask = graphics_layer->GetCompositingReasons();
  for (const char* name : blink::CompositingReason::ShortNames(reasons_bitmask)) {
    reasons.push_back(std::string(name));
  }
  std::move(callback).Run(std::move(reasons));
}

void LayerTreeDispatcher::Disable() {
  page_instance_->probe_sink()->removeInspectorLayerTreeAgent(layer_agent_impl_.Get());
  snapshot_by_id_.clear();
  enabled_ = false;
}

void LayerTreeDispatcher::Enable() {
  //DLOG(INFO) << "LayerTreeDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  page_instance_->probe_sink()->addInspectorLayerTreeAgent(layer_agent_impl_.Get());
  blink::Document* document = page_instance_->inspected_frames()->Root()->GetDocument();
  if (document && document->Lifecycle().GetState() >= blink::DocumentLifecycle::kCompositingClean) {
    LayerTreeDidChange();
  }
  enabled_ = true;
}

void LayerTreeDispatcher::LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, LoadSnapshotCallback callback) {
  if (!tiles.size()) {
    //DLOG(ERROR) << "Invalid argument, no tiles provided";
    std::move(callback).Run(std::string());
    return;
  }
  Vector<scoped_refptr<blink::PictureSnapshot::TilePictureStream>> decoded_tiles;
  decoded_tiles.Grow(tiles.size());
  for (size_t i = 0; i < tiles.size(); ++i) {
    automation::PictureTile* tile = tiles[i].get();
    decoded_tiles[i] = base::AdoptRef(new blink::PictureSnapshot::TilePictureStream());
    decoded_tiles[i]->layer_offset.Set(tile->x, tile->y);
    // FromUTF8() wont mess with the binary payload?
    String picture_str = String::FromUTF8(tile->picture.data());
    if (!Base64Decode(picture_str, decoded_tiles[i]->data)) {
      //DLOG(ERROR) << "Invalid base64 encoding";
      std::move(callback).Run(std::string());
      return;
    }
  }
  scoped_refptr<blink::PictureSnapshot> snapshot = blink::PictureSnapshot::Load(decoded_tiles);
  if (!snapshot) {
    //DLOG(ERROR) << "Invalid snapshot format";
    std::move(callback).Run(std::string());
    return;
  }
  if (snapshot->IsEmpty()) {
    //DLOG(ERROR) << "Empty snapshot";
    std::move(callback).Run(std::string());
    return;
  }

  String snapshot_id = String::Number(++last_snapshot_id_);
  bool new_entry = snapshot_by_id_.insert(snapshot_id, snapshot).is_new_entry;
  DCHECK(new_entry);
  std::move(callback).Run(std::string(snapshot_id.Utf8().data()));
}

void LayerTreeDispatcher::MakeSnapshot(const std::string& layer_id, MakeSnapshotCallback callback) {
  blink::GraphicsLayer* layer = nullptr;
  bool ok = LayerById(String::FromUTF8(layer_id.data()), layer);
  if (!ok) {
    //DLOG(ERROR) << "Layer " << layer_id << " not found";
    std::move(callback).Run(std::string());
    return;
  }
  if (!layer->DrawsContent()) {
    //DLOG(ERROR) << "Layer does not draw content";
    std::move(callback).Run(std::string());
    return;
  }

  blink::IntSize size = ExpandedIntSize(layer->Size());
  blink::IntRect interest_rect(blink::IntPoint(0, 0), size);
  suppress_layer_paint_events_ = true;

  // If we hit a devtool break point in the middle of document lifecycle, for
  // example, https://crbug.com/788219, this will prevent crash when clicking
  // the "layer" panel.
  if (page_instance_->inspected_frames()->Root()->GetDocument() && page_instance_->inspected_frames()->Root()
                                                      ->GetDocument()
                                                      ->Lifecycle()
                                                      .LifecyclePostponed()) {
    std::move(callback).Run(std::string());
    //DLOG(ERROR) << "Layer does not draw content";
    return;
  }

  page_instance_->inspected_frames()->Root()->View()->UpdateAllLifecyclePhasesExceptPaint();
  for (auto frame = page_instance_->inspected_frames()->begin();
       frame != page_instance_->inspected_frames()->end(); ++frame) {
    frame->GetDocument()->Lifecycle().AdvanceTo(blink::DocumentLifecycle::kInPaint);
  }
  layer->Paint(&interest_rect);
  for (auto frame = page_instance_->inspected_frames()->begin();
       frame != page_instance_->inspected_frames()->end(); ++frame) {
    frame->GetDocument()->Lifecycle().AdvanceTo(blink::DocumentLifecycle::kPaintClean);
  }

  suppress_layer_paint_events_ = false;

  auto snapshot = base::AdoptRef(new blink::PictureSnapshot(
      ToSkPicture(layer->CapturePaintRecord(), interest_rect)));

  String snapshot_id = String::Number(++last_snapshot_id_);
  bool new_entry = snapshot_by_id_.insert(snapshot_id, snapshot).is_new_entry;
  DCHECK(new_entry);
  std::move(callback).Run(std::string(snapshot_id.Utf8().data()));
}

void LayerTreeDispatcher::ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, ProfileSnapshotCallback callback) {
  const blink::PictureSnapshot* snapshot = nullptr;
  bool ok = GetSnapshotById(String::FromUTF8(snapshot_id.data()), snapshot);
  std::vector<std::vector<double>> out_timings;
  if (!ok) {
    std::move(callback).Run(std::move(out_timings));
    return;
  }
  blink::FloatRect rect;
  if (clip_rect.has_value())
    ParseRect(clip_rect.value(), &rect);
  std::unique_ptr<blink::PictureSnapshot::Timings> timings = snapshot->Profile(
      min_repeat_count, min_duration,
      clip_rect.has_value() ? &rect : nullptr);
  for (size_t i = 0; i < timings->size(); ++i) {
    const Vector<double>& row = (*timings)[i];
    std::vector<double> out_row;
    for (size_t j = 0; j < row.size(); ++j)
      out_row.push_back(row[j]);
    out_timings.push_back(std::move(out_row));
  }
  std::move(callback).Run(std::move(out_timings));
}

void LayerTreeDispatcher::ReleaseSnapshot(const std::string& snapshot_id) {
  SnapshotById::iterator it = snapshot_by_id_.find(String::FromUTF8(snapshot_id.data()));
  if (it == snapshot_by_id_.end()) {
    //DLOG(ERROR) << "Snapshot not found";
    return;
  }
  snapshot_by_id_.erase(it);
}

void LayerTreeDispatcher::ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, ReplaySnapshotCallback callback) {
  const blink::PictureSnapshot* snapshot = nullptr;
  bool ok = GetSnapshotById(String::FromUTF8(snapshot_id.data()), snapshot);
  if (!ok) {
    std::move(callback).Run(std::string());
    return;
  }
  std::unique_ptr<Vector<char>> base64_data = snapshot->Replay(from_step, to_step, scale == 0 ? 1.0 : scale);
  if (!base64_data) {
    //DLOG(ERROR) << "Image encoding failed";
    std::move(callback).Run(std::string());
    return;
  }
  StringBuilder url;
  url.Append("data:image/png;base64,");
  url.ReserveCapacity(url.length() + base64_data->size());
  url.Append(base64_data->begin(), base64_data->size());
  std::move(callback).Run(std::string(url.ToString().Utf8().data()));
}

void LayerTreeDispatcher::SnapshotCommandLog(const std::string& snapshot_id, SnapshotCommandLogCallback callback) {
  const blink::PictureSnapshot* snapshot = nullptr;
  std::string result;
  bool ok = GetSnapshotById(String::FromUTF8(snapshot_id.data()), snapshot);
  if (!ok) {
    std::move(callback).Run(std::move(result));
    return;
  }
  // protocol::ErrorSupport errors;
  // std::unique_ptr<protocol::Value> log_value = protocol::StringUtil::parseJSON(
  //     snapshot->SnapshotCommandLog()->ToJSONString());
  // *command_log =
  //     Array<protocol::DictionaryValue>::fromValue(log_value.get(), &errors);
  // if (errors.hasErrors())
  //   return Response::Error(errors.errors());
  // return Response::OK();
  String json_str = snapshot->SnapshotCommandLog()->ToJSONString();
  std::move(callback).Run(std::string(json_str.Utf8().data()));
}

void LayerTreeDispatcher::LayerTreeDidChange() {
  GetClient()->OnLayerTreeDidChange(BuildLayerTree());
}

void LayerTreeDispatcher::DidPaint(const blink::GraphicsLayer* graphics_layer, blink::GraphicsContext& context, const blink::LayoutRect& rect) {
  if (suppress_layer_paint_events_)
    return;
  // Should only happen for LocalFrameView paints when compositing is off.
  // Consider different instrumentation method for that.
  if (!graphics_layer)
    return;

  gfx::Rect dom_rect(rect.X().ToInt(), rect.Y().ToInt(), rect.Width().ToInt(), rect.Height().ToInt());
  GetClient()->OnLayerPainted(std::string(IdForLayer(graphics_layer).Utf8().data()), std::move(dom_rect));
}

automation::LayerTreeClient* LayerTreeDispatcher::GetClient() const {
  return layer_client_ptr_.get();
}

std::vector<automation::LayerPtr> LayerTreeDispatcher::BuildLayerTree() {
  blink::PaintLayerCompositor* compositor = GetPaintLayerCompositor();
  if (!compositor || !compositor->InCompositingMode())
    return std::vector<automation::LayerPtr>();

  LayerIdToNodeIdMap layer_id_to_node_id_map;
  std::vector<automation::LayerPtr> layers;
  BuildLayerIdToNodeIdMap(compositor->RootLayer(), layer_id_to_node_id_map);
  auto* layer_for_scrolling = page_instance_->inspected_frames()->Root()
                                  ->View()
                                  ->LayoutViewportScrollableArea()
                                  ->LayerForScrolling();
  int scrolling_layer_id =
      layer_for_scrolling ? layer_for_scrolling->PlatformLayer()->Id() : 0;
  bool have_blocking_wheel_event_handlers =
      page_instance_->inspected_frames()->Root()->GetChromeClient().EventListenerProperties(
          page_instance_->inspected_frames()->Root(), blink::WebEventListenerClass::kMouseWheel) ==
      blink::WebEventListenerProperties::kBlocking;

  GatherGraphicsLayers(RootGraphicsLayer(), layer_id_to_node_id_map, layers,
                       have_blocking_wheel_event_handlers, scrolling_layer_id);
  return layers;
}

void LayerTreeDispatcher::BuildLayerIdToNodeIdMap(blink::PaintLayer* root, LayerIdToNodeIdMap& layer_id_to_node_id_map) {
  if (root->HasCompositedLayerMapping()) {
    if (blink::Node* node = root->GetLayoutObject().GeneratingNode()) {
      blink::GraphicsLayer* graphics_layer =
          root->GetCompositedLayerMapping()->ChildForSuperlayers();
      layer_id_to_node_id_map.Set(graphics_layer->PlatformLayer()->Id(),
                                  blink::DOMNodeIds::IdForNode(node));
    }
  }
  for (blink::PaintLayer* child = root->FirstChild(); child;
       child = child->NextSibling())
    BuildLayerIdToNodeIdMap(child, layer_id_to_node_id_map);
  if (!root->GetLayoutObject().IsLayoutIFrame())
    return;
  blink::FrameView* child_frame_view =
      ToLayoutEmbeddedContent(root->GetLayoutObject()).ChildFrameView();
  if (!child_frame_view || !child_frame_view->IsLocalFrameView())
    return;
  blink::LayoutView* child_layout_view =
      ToLocalFrameView(child_frame_view)->GetLayoutView();
  if (!child_layout_view)
    return;
  blink::PaintLayerCompositor* child_compositor = child_layout_view->Compositor();
  if (!child_compositor)
    return;
  BuildLayerIdToNodeIdMap(child_compositor->RootLayer(),
                          layer_id_to_node_id_map);
}

void LayerTreeDispatcher::GatherGraphicsLayers(
  blink::GraphicsLayer* layer,
  HashMap<int, int>& layer_id_to_node_id_map,
  std::vector<automation::LayerPtr>& layers,
  bool has_wheel_event_handlers,
  int scrolling_layer_id) {
  // if (client_->IsInspectorLayer(layer))
  //   return;
  int layer_id = layer->PlatformLayer()->Id();
  layers.push_back(BuildObjectForLayer(
      RootGraphicsLayer(), layer, layer_id_to_node_id_map.at(layer_id),
      has_wheel_event_handlers && layer_id == scrolling_layer_id));
  for (size_t i = 0, size = layer->Children().size(); i < size; ++i)
    GatherGraphicsLayers(layer->Children()[i], layer_id_to_node_id_map, layers,
                         has_wheel_event_handlers, scrolling_layer_id);
}

blink::GraphicsLayer* LayerTreeDispatcher::RootGraphicsLayer() {
  return page_instance_->inspected_frames()->Root()
      ->GetPage()
      ->GetVisualViewport()
      .RootGraphicsLayer();
}

blink::PaintLayerCompositor* LayerTreeDispatcher::GetPaintLayerCompositor() {
  auto* layout_view = page_instance_->inspected_frames()->Root()->ContentLayoutObject();
  blink::PaintLayerCompositor* compositor =
      layout_view ? layout_view->Compositor() : nullptr;
  return compositor;
}

bool LayerTreeDispatcher::GetSnapshotById(
  const String& snapshot_id,
  const blink::PictureSnapshot*& result) {
  SnapshotById::iterator it = snapshot_by_id_.find(snapshot_id);
  if (it == snapshot_by_id_.end()) {
    //DLOG(ERROR) << "Snapshot not found";
    return false;
  }
  result = it->value.get();
  return true;
}

void LayerTreeDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  layer_agent_impl_ = new InspectorLayerTreeAgentImpl(this);
  layer_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  
  Enable();
}

}