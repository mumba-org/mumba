// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_LAYER_TREE_DISPATCHER_H_
#define MUMBA_APPLICATION_LAYER_TREE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/core/inspector/inspector_base_agent.h"
#include "third_party/blink/renderer/core/page/page_overlay.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class GraphicsContext;
class GraphicsLayer;
class InspectedFrames;
class LayoutRect;
class PictureSnapshot;
class PaintLayer;
class PaintLayerCompositor;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class ApplicationWindowDispatcher;
class InspectorLayerTreeAgentImpl;
class PageInstance;

class LayerTreeDispatcher : public automation::LayerTree {
public:
  static void Create(automation::LayerTreeRequest request, PageInstance* page_instance);

  LayerTreeDispatcher(automation::LayerTreeRequest request, PageInstance* page_instance);
  LayerTreeDispatcher(PageInstance* page_instance);
  ~LayerTreeDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::LayerTreeAssociatedRequest request);

  void Register(int32_t application_id) override;
  void CompositingReasons(const std::string& layer_id, CompositingReasonsCallback callback) override;
  void Disable() override;
  void Enable() override;
  void LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, LoadSnapshotCallback callback) override;
  void MakeSnapshot(const std::string& layer_id, MakeSnapshotCallback callback) override;
  void ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, ProfileSnapshotCallback callback) override;
  void ReleaseSnapshot(const std::string& snapshot_id) override;
  void ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, ReplaySnapshotCallback callback) override;
  void SnapshotCommandLog(const std::string& snapshot_id, SnapshotCommandLogCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  std::vector<automation::LayerPtr> BuildLayerTree();

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorLayerTreeAgentImpl;
  static unsigned last_snapshot_id_;

  void LayerTreeDidChange();
  void DidPaint(const blink::GraphicsLayer*, blink::GraphicsContext&, const blink::LayoutRect&);
  automation::LayerTreeClient* GetClient() const;
  typedef HashMap<int, int> LayerIdToNodeIdMap;
  void BuildLayerIdToNodeIdMap(blink::PaintLayer*, LayerIdToNodeIdMap&);
  void GatherGraphicsLayers(
    blink::GraphicsLayer*,
    HashMap<int, int>& layer_id_to_node_id_map,
    std::vector<automation::LayerPtr>&,
    bool has_wheel_event_handlers,
    int scrolling_root_layer_id);
  blink::GraphicsLayer* RootGraphicsLayer();
  blink::PaintLayerCompositor* GetPaintLayerCompositor();
  bool LayerById(const String& layer_id,
                 blink::GraphicsLayer*& result);
  bool GetSnapshotById(
    const String& snapshot_id,
    const blink::PictureSnapshot*& result);

  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::LayerTree> binding_;
  automation::LayerTreeClientAssociatedPtr layer_client_ptr_;
  std::string pending_script_to_evaluate_on_load_once_;
  std::string script_to_evaluate_on_load_once_;
  // hack to receive the events back from probe
  blink::Persistent<InspectorLayerTreeAgentImpl> layer_agent_impl_;
  typedef HashMap<String, scoped_refptr<blink::PictureSnapshot>> SnapshotById;
  SnapshotById snapshot_by_id_;
  bool suppress_layer_paint_events_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(LayerTreeDispatcher); 
};

}

#endif