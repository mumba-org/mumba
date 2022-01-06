// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_APPLICATION_AUTOMATION_INSPECTOR_INSPECTOR_HIGHLIGHT_H_
#define CORE_APPLICATION_AUTOMATION_INSPECTOR_INSPECTOR_HIGHLIGHT_H_

#include "core/shared/common/mojom/automation.mojom.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/inspector/protocol/DOM.h"
#include "third_party/blink/renderer/platform/geometry/float_quad.h"
#include "third_party/blink/renderer/platform/geometry/layout_rect.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/handle.h"

namespace blink {
class Color;  
}

namespace application {

struct InspectorHighlightConfig {
  USING_FAST_MALLOC(InspectorHighlightConfig);

 public:
  InspectorHighlightConfig();

  blink::Color content;
  blink::Color content_outline;
  blink::Color padding;
  blink::Color border;
  blink::Color margin;
  blink::Color event_target;
  blink::Color shape;
  blink::Color shape_margin;
  blink::Color css_grid;

  bool show_info;
  bool show_rulers;
  bool show_extension_lines;
  bool display_as_material;

  String selector_list;
};

class InspectorHighlight {
  STACK_ALLOCATED();

 public:
  InspectorHighlight(blink::Node*,
                     const InspectorHighlightConfig&,
                     bool append_element_info);
  explicit InspectorHighlight(float scale);
  ~InspectorHighlight();

  static automation::BoxModelPtr GetBoxModel(blink::Node*);
  static InspectorHighlightConfig DefaultConfig();
  static bool BuildNodeQuads(blink::Node*,
                             blink::FloatQuad* content,
                             blink::FloatQuad* padding,
                             blink::FloatQuad* border,
                             blink::FloatQuad* margin);

  void AppendPath(std::unique_ptr<base::ListValue> path,
                  const blink::Color& fill_color,
                  const blink::Color& outline_color,
                  const String& name = String());
  void AppendQuad(const blink::FloatQuad&,
                  const blink::Color& fill_color,
                  const blink::Color& outline_color = blink::Color::kTransparent,
                  const String& name = String());
  void AppendEventTargetQuads(blink::Node* event_target_node,
                              const InspectorHighlightConfig&);
  std::unique_ptr<base::DictionaryValue> AsProtocolValue() const;

 private:
  void AppendNodeHighlight(blink::Node*, const InspectorHighlightConfig&);
  void AppendPathsForShapeOutside(blink::Node*, const InspectorHighlightConfig&);

  std::unique_ptr<base::DictionaryValue> element_info_;
  std::unique_ptr<base::ListValue> highlight_paths_;
  std::unique_ptr<base::ListValue> grid_info_;
  bool show_rulers_;
  bool show_extension_lines_;
  bool display_as_material_;
  float scale_;
};

}  // namespace application

#endif  // CORE_APPLICATION_AUTOMATION_INSPECTOR_INSPECTOR_HIGHLIGHT_H_
