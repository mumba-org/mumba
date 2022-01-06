// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/inspector_highlight.h"

#include "base/macros.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_grid.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/platform_chrome_client.h"

namespace application {

namespace {

class PathBuilder {
  STACK_ALLOCATED();

 public:
  PathBuilder() : path_(std::make_unique<base::ListValue>()) {}
  virtual ~PathBuilder() = default;

  std::unique_ptr<base::ListValue> Release() { return std::move(path_); }

  void AppendPath(const blink::Path& path, float scale) {
    blink::Path transform_path(path);
    transform_path.Transform(blink::AffineTransform().Scale(scale));
    transform_path.Apply(this, &PathBuilder::AppendPathElement);
  }

 protected:
  virtual blink::FloatPoint TranslatePoint(const blink::FloatPoint& point) { return point; }

 private:
  static void AppendPathElement(void* path_builder,
                                const blink::PathElement* path_element) {
    static_cast<PathBuilder*>(path_builder)->AppendPathElement(path_element);
  }

  void AppendPathElement(const blink::PathElement*);
  void AppendPathCommandAndPoints(const char* command,
                                  const blink::FloatPoint points[],
                                  size_t length);

  std::unique_ptr<base::ListValue> path_;
  DISALLOW_COPY_AND_ASSIGN(PathBuilder);
};

void PathBuilder::AppendPathCommandAndPoints(const char* command,
                                             const blink::FloatPoint points[],
                                             size_t length) {
  auto comm_value = std::make_unique<base::Value>(command);
  path_->Append(std::move(comm_value));
  for (size_t i = 0; i < length; i++) {
    blink::FloatPoint point = TranslatePoint(points[i]);
    auto x_value = std::make_unique<base::Value>(point.X());
    auto y_value = std::make_unique<base::Value>(point.Y());
    path_->Append(std::move(x_value));
    path_->Append(std::move(y_value));
  }
}

void PathBuilder::AppendPathElement(const blink::PathElement* path_element) {
  switch (path_element->type) {
    // The points member will contain 1 value.
    case blink::kPathElementMoveToPoint:
      AppendPathCommandAndPoints("M", path_element->points, 1);
      break;
    // The points member will contain 1 value.
    case blink::kPathElementAddLineToPoint:
      AppendPathCommandAndPoints("L", path_element->points, 1);
      break;
    // The points member will contain 3 values.
    case blink::kPathElementAddCurveToPoint:
      AppendPathCommandAndPoints("C", path_element->points, 3);
      break;
    // The points member will contain 2 values.
    case blink::kPathElementAddQuadCurveToPoint:
      AppendPathCommandAndPoints("Q", path_element->points, 2);
      break;
    // The points member will contain no values.
    case blink::kPathElementCloseSubpath:
      AppendPathCommandAndPoints("Z", nullptr, 0);
      break;
  }
}

class ShapePathBuilder : public PathBuilder {
 public:
  ShapePathBuilder(blink::LocalFrameView& view,
                   blink::LayoutObject& layout_object,
                   const blink::ShapeOutsideInfo& shape_outside_info)
      : view_(&view),
        layout_object_(layout_object),
        shape_outside_info_(shape_outside_info) {}

  static std::unique_ptr<base::ListValue> BuildPath(
      blink::LocalFrameView& view,
      blink::LayoutObject& layout_object,
      const blink::ShapeOutsideInfo& shape_outside_info,
      const blink::Path& path,
      float scale) {
    ShapePathBuilder builder(view, layout_object, shape_outside_info);
    builder.AppendPath(path, scale);
    return builder.Release();
  }

 protected:
  blink::FloatPoint TranslatePoint(const blink::FloatPoint& point) override {
    blink::FloatPoint layout_object_point =
        shape_outside_info_.ShapeToLayoutObjectPoint(point);
    return view_->ContentsToViewport(
        RoundedIntPoint(layout_object_.LocalToAbsolute(layout_object_point)));
  }

 private:
  blink::Member<blink::LocalFrameView> view_;
  blink::LayoutObject& layout_object_;
  const blink::ShapeOutsideInfo& shape_outside_info_;
};

std::vector<double> BuildArrayForQuad(
    const blink::FloatQuad& quad) {
  std::vector<double> array;
  array.push_back(quad.P1().X());
  array.push_back(quad.P1().Y());
  array.push_back(quad.P2().X());
  array.push_back(quad.P2().Y());
  array.push_back(quad.P3().X());
  array.push_back(quad.P3().Y());
  array.push_back(quad.P4().X());
  array.push_back(quad.P4().Y());
  return array;
}

blink::Path QuadToPath(const blink::FloatQuad& quad) {
  blink::Path quad_path;
  quad_path.MoveTo(quad.P1());
  quad_path.AddLineTo(quad.P2());
  quad_path.AddLineTo(quad.P3());
  quad_path.AddLineTo(quad.P4());
  quad_path.CloseSubpath();
  return quad_path;
}

blink::FloatPoint ContentsPointToViewport(const blink::LocalFrameView* view,
                                          blink::FloatPoint point_in_contents) {
  blink::LayoutPoint point_in_frame =
      view->ContentsToFrame(blink::LayoutPoint(point_in_contents));
  blink::FloatPoint point_in_root_frame =
      blink::FloatPoint(view->ConvertToRootFrame(point_in_frame));
  return blink::FloatPoint(view->GetPage()->GetVisualViewport().RootFrameToViewport(
      point_in_root_frame));
}

void ContentsQuadToViewport(const blink::LocalFrameView* view, blink::FloatQuad& quad) {
  quad.SetP1(ContentsPointToViewport(view, quad.P1()));
  quad.SetP2(ContentsPointToViewport(view, quad.P2()));
  quad.SetP3(ContentsPointToViewport(view, quad.P3()));
  quad.SetP4(ContentsPointToViewport(view, quad.P4()));
}

const blink::ShapeOutsideInfo* ShapeOutsideInfoForNode(blink::Node* node,
                                                       blink::Shape::DisplayPaths* paths,
                                                       blink::FloatQuad* bounds) {
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object || !layout_object->IsBox() ||
      !ToLayoutBox(layout_object)->GetShapeOutsideInfo())
    return nullptr;

  blink::LocalFrameView* containing_view = node->GetDocument().View();
  blink::LayoutBox* layout_box = ToLayoutBox(layout_object);
  const blink::ShapeOutsideInfo* shape_outside_info =
      layout_box->GetShapeOutsideInfo();

  shape_outside_info->ComputedShape().BuildDisplayPaths(*paths);

  blink::LayoutRect shape_bounds =
      shape_outside_info->ComputedShapePhysicalBoundingBox();
  *bounds = layout_box->LocalToAbsoluteQuad(blink::FloatRect(shape_bounds));
  ContentsQuadToViewport(containing_view, *bounds);

  return shape_outside_info;
}

std::unique_ptr<base::DictionaryValue> BuildElementInfo(blink::Element* element) {
  std::unique_ptr<base::DictionaryValue> element_info = std::make_unique<base::DictionaryValue>();
  blink::Element* real_element = element;
  blink::PseudoElement* pseudo_element = nullptr;
  if (element->IsPseudoElement()) {
    pseudo_element = ToPseudoElement(element);
    real_element = element->ParentOrShadowHostElement();
  }
  bool is_xhtml = real_element->GetDocument().IsXHTMLDocument();
  
  String tag_str = is_xhtml ? real_element->nodeName()
                            : real_element->nodeName().DeprecatedLower();
  std::unique_ptr<base::Value> tag_val = std::make_unique<base::Value>(std::string(tag_str.Utf8().data(), tag_str.length()));

  std::unique_ptr<base::Value> id_val = std::make_unique<base::Value>(std::string(
    real_element->GetIdAttribute().Utf8().data(), 
    real_element->GetIdAttribute().length()));

  element_info->Set("tagName", std::move(tag_val));
  element_info->Set("idValue", std::move(id_val));
  StringBuilder class_names;
  if (real_element->HasClass() && real_element->IsStyledElement()) {
    HashSet<AtomicString> used_class_names;
    const blink::SpaceSplitString& class_names_string = real_element->ClassNames();
    size_t class_name_count = class_names_string.size();
    for (size_t i = 0; i < class_name_count; ++i) {
      const AtomicString& class_name = class_names_string[i];
      if (!used_class_names.insert(class_name).is_new_entry)
        continue;
      class_names.Append('.');
      class_names.Append(class_name);
    }
  }
  if (pseudo_element) {
    if (pseudo_element->GetPseudoId() == blink::kPseudoIdBefore)
      class_names.Append("::before");
    else if (pseudo_element->GetPseudoId() == blink::kPseudoIdAfter)
      class_names.Append("::after");
  }
  if (!class_names.IsEmpty()) {
    String class_names_str = class_names.ToString();
    std::unique_ptr<base::Value> class_val = std::make_unique<base::Value>(std::string(class_names_str.Utf8().data(), class_names_str.length()));
    element_info->Set("className", std::move(class_val));
  }

  blink::LayoutObject* layout_object = element->GetLayoutObject();
  blink::LocalFrameView* containing_view = element->GetDocument().View();
  if (!layout_object || !containing_view)
    return element_info;

  // layoutObject the getBoundingClientRect() data in the tooltip
  // to be consistent with the rulers (see http://crbug.com/262338).
  blink::DOMRect* bounding_box = element->getBoundingClientRect();
  String width_str = String::Number(bounding_box->width());
  String height_str = String::Number(bounding_box->height());
  std::unique_ptr<base::Value> width_val = std::make_unique<base::Value>(std::string(width_str.Utf8().data(), width_str.length()));
  std::unique_ptr<base::Value> height_val = std::make_unique<base::Value>(std::string(height_str.Utf8().data(), height_str.length()));
  
  element_info->Set("nodeWidth", std::move(width_val));
  element_info->Set("nodeHeight", std::move(height_val));
  
  return element_info;
}

std::unique_ptr<base::DictionaryValue> BuildGapAndPositions(
  double origin,
  blink::LayoutUnit gap,
  const Vector<blink::LayoutUnit>& positions,
  float scale) {
  std::unique_ptr<base::DictionaryValue> result = std::make_unique<base::DictionaryValue>();
  
  std::unique_ptr<base::Value> floor_val = std::make_unique<base::Value>(floor(origin * scale));
  std::unique_ptr<base::Value> gap_val = std::make_unique<base::Value>(round(gap * scale));
  result->Set("origin", std::move(floor_val));
  result->Set("gap", std::move(gap_val));

  std::unique_ptr<base::ListValue> spans = std::make_unique<base::ListValue>();
  for (const blink::LayoutUnit& position : positions) {
    std::unique_ptr<base::Value> pos_val = std::make_unique<base::Value>(round(position * scale));
    spans->Append(std::move(pos_val));
  }
  result->Set(
    "positions", 
    std::move(spans));

  return result;
}

std::unique_ptr<base::DictionaryValue> BuildGridInfo(
  blink::LayoutGrid* layout_grid,
  blink::FloatPoint origin,
  blink::Color color,
  float scale,
  bool isPrimary) {
  std::unique_ptr<base::DictionaryValue> grid_info = std::make_unique<base::DictionaryValue>();
  grid_info->SetDictionary(
     "rows", 
     BuildGapAndPositions(origin.Y(),
                        layout_grid->GridGap(blink::kForRows) +
                          layout_grid->GridItemOffset(blink::kForRows),
                        layout_grid->RowPositions(), scale));
  grid_info->SetDictionary(
      "columns",
      BuildGapAndPositions(origin.X(),
                           layout_grid->GridGap(blink::kForColumns) +
                            layout_grid->GridItemOffset(blink::kForColumns),
                           layout_grid->ColumnPositions(), scale));
  String color_str = color.Serialized();
  auto color_value = std::make_unique<base::Value>(std::string(color_str.Utf8().data(), color_str.length()));
  grid_info->Set(
      "color", 
      std::move(color_value));
  grid_info->Set(
      "isPrimaryGrid", 
      std::make_unique<base::Value>(isPrimary));
  return grid_info;
}

}  // namespace

InspectorHighlight::InspectorHighlight(float scale)
    : highlight_paths_(std::make_unique<base::ListValue>()),
      show_rulers_(false),
      show_extension_lines_(false),
      display_as_material_(false),
      scale_(scale) {}

InspectorHighlightConfig::InspectorHighlightConfig()
    : show_info(false),
      show_rulers(false),
      show_extension_lines(false),
      display_as_material(false) {}

InspectorHighlight::InspectorHighlight(
    blink::Node* node,
    const InspectorHighlightConfig& highlight_config,
    bool append_element_info)
    : highlight_paths_(std::make_unique<base::ListValue>()),
      show_rulers_(highlight_config.show_rulers),
      show_extension_lines_(highlight_config.show_extension_lines),
      display_as_material_(highlight_config.display_as_material),
      scale_(1.f) {
  blink::LocalFrameView* frame_view = node->GetDocument().View();
  if (frame_view)
    scale_ = 1.f / frame_view->GetChromeClient()->WindowToViewportScalar(1.f);
  AppendPathsForShapeOutside(node, highlight_config);
  AppendNodeHighlight(node, highlight_config);
  if (append_element_info && node->IsElementNode())
    element_info_ = BuildElementInfo(ToElement(node));
}

InspectorHighlight::~InspectorHighlight() = default;

void InspectorHighlight::AppendQuad(const blink::FloatQuad& quad,
                                    const blink::Color& fill_color,
                                    const blink::Color& outline_color,
                                    const String& name) {
  blink::Path path = QuadToPath(quad);
  PathBuilder builder;
  builder.AppendPath(path, scale_);
  AppendPath(builder.Release(), fill_color, outline_color, name);
}

void InspectorHighlight::AppendPath(std::unique_ptr<base::ListValue> path,
                                    const blink::Color& fill_color,
                                    const blink::Color& outline_color,
                                    const String& name) {
  std::unique_ptr<base::DictionaryValue> object = std::make_unique<base::DictionaryValue>();
  object->Set(
    "path", 
    std::move(path));
  String fill_color_str = fill_color.Serialized();
  object->Set(
      "fillColor", 
      std::make_unique<base::Value>(std::string(fill_color_str.Utf8().data(), fill_color_str.length())));
  if (outline_color != blink::Color::kTransparent) {
    String outline_color_str = outline_color.Serialized();
    object->Set(
        "outlineColor", 
        std::make_unique<base::Value>(std::string(outline_color_str.Utf8().data(), outline_color_str.length())));
  }
  if (!name.IsEmpty()) {
    object->Set(
        "name", 
        std::make_unique<base::Value>(std::string(name.Utf8().data(), name.length())));
  }
  highlight_paths_->Append(std::move(object));
}

void InspectorHighlight::AppendEventTargetQuads(
  blink::Node* event_target_node,
  const InspectorHighlightConfig& highlight_config) {
  if (event_target_node->GetLayoutObject()) {
    blink::FloatQuad border, unused;
    if (BuildNodeQuads(event_target_node, &unused, &unused, &border, &unused))
      AppendQuad(border, highlight_config.event_target);
  }
}

void InspectorHighlight::AppendPathsForShapeOutside(
  blink::Node* node,
  const InspectorHighlightConfig& config) {
  blink::Shape::DisplayPaths paths;
  blink::FloatQuad bounds_quad;

  const blink::ShapeOutsideInfo* shape_outside_info =
      ShapeOutsideInfoForNode(node, &paths, &bounds_quad);
  if (!shape_outside_info)
    return;

  if (!paths.shape.length()) {
    AppendQuad(bounds_quad, config.shape);
    return;
  }

  AppendPath(ShapePathBuilder::BuildPath(
              *node->GetDocument().View(), *node->GetLayoutObject(),
              *shape_outside_info, paths.shape, scale_),
             config.shape, blink::Color::kTransparent);
  if (paths.margin_shape.length())
    AppendPath(ShapePathBuilder::BuildPath(
                   *node->GetDocument().View(), *node->GetLayoutObject(),
                   *shape_outside_info, paths.margin_shape, scale_),
               config.shape_margin, blink::Color::kTransparent);
}

void InspectorHighlight::AppendNodeHighlight(
  blink::Node* node,
  const InspectorHighlightConfig& highlight_config) {
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return;

  // LayoutSVGRoot should be highlighted through the isBox() code path, all
  // other SVG elements should just dump their absoluteQuads().
  if (layout_object->GetNode() && layout_object->GetNode()->IsSVGElement() &&
      !layout_object->IsSVGRoot()) {
    Vector<blink::FloatQuad> quads;
    layout_object->AbsoluteQuads(quads);
    blink::LocalFrameView* containing_view = layout_object->GetFrameView();
    for (size_t i = 0; i < quads.size(); ++i) {
      if (containing_view)
        ContentsQuadToViewport(containing_view, quads[i]);
      AppendQuad(quads[i], highlight_config.content,
                 highlight_config.content_outline);
    }
    return;
  }

  blink::FloatQuad content, padding, border, margin;
  if (!BuildNodeQuads(node, &content, &padding, &border, &margin))
    return;
  AppendQuad(content, highlight_config.content,
             highlight_config.content_outline, "content");
  AppendQuad(padding, highlight_config.padding, blink::Color::kTransparent, "padding");
  AppendQuad(border, highlight_config.border, blink::Color::kTransparent, "border");
  AppendQuad(margin, highlight_config.margin, blink::Color::kTransparent, "margin");

  if (highlight_config.css_grid == blink::Color::kTransparent)
    return;

  grid_info_ = std::make_unique<base::ListValue>();
  if (layout_object->IsLayoutGrid()) {
    grid_info_->Append(
      BuildGridInfo(ToLayoutGrid(layout_object),
                      border.P1(), highlight_config.css_grid,
                      scale_, true));
  }
  blink::LayoutObject* parent = layout_object->Parent();
  if (!parent || !parent->IsLayoutGrid())
    return;
  if (!BuildNodeQuads(parent->GetNode(), &content, &padding, &border, &margin))
    return;
  grid_info_->Append(
    BuildGridInfo(
        ToLayoutGrid(parent), 
        border.P1(),
        highlight_config.css_grid, 
        scale_,
        false));
}

std::unique_ptr<base::DictionaryValue> InspectorHighlight::AsProtocolValue() const {
  std::unique_ptr<base::DictionaryValue> object = std::make_unique<base::DictionaryValue>();
  object->Set("paths", std::make_unique<base::Value>(highlight_paths_->Clone()));
  object->Set("showRulers", std::make_unique<base::Value>(show_rulers_));
  object->Set("showExtensionLines", std::make_unique<base::Value>(show_extension_lines_));
  if (element_info_) {
    object->Set("elementInfo", std::make_unique<base::Value>(element_info_->Clone()));
  }
  object->Set("displayAsMaterial", std::make_unique<base::Value>(display_as_material_));
  if (grid_info_ && grid_info_->GetSize() > 0) {
    object->Set("gridInfo", std::make_unique<base::Value>(grid_info_->Clone()));
  }
  return object;
}

// static
automation::BoxModelPtr InspectorHighlight::GetBoxModel(blink::Node* node) {
  node->GetDocument().EnsurePaintLocationDataValidForNode(node);
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  blink::LocalFrameView* view = node->GetDocument().View();
  if (!layout_object || !view)
    return nullptr;

  blink::FloatQuad content, padding, border, margin;
  if (!BuildNodeQuads(node, &content, &padding, &border, &margin))
    return nullptr;

  blink::AdjustForAbsoluteZoom::AdjustFloatQuad(content, *layout_object);
  blink::AdjustForAbsoluteZoom::AdjustFloatQuad(padding, *layout_object);
  blink::AdjustForAbsoluteZoom::AdjustFloatQuad(border, *layout_object);
  blink::AdjustForAbsoluteZoom::AdjustFloatQuad(margin, *layout_object);

  float scale = 1 / view->GetPage()->GetVisualViewport().Scale();
  content.Scale(scale, scale);
  padding.Scale(scale, scale);
  border.Scale(scale, scale);
  margin.Scale(scale, scale);

  blink::IntRect bounding_box =
      view->ContentsToRootFrame(layout_object->AbsoluteBoundingBoxRect());
  blink::LayoutBoxModelObject* model_object =
      layout_object->IsBoxModelObject() ? ToLayoutBoxModelObject(layout_object)
                                        : nullptr;

  automation::BoxModelPtr model = automation::BoxModel::New();
  model->content = BuildArrayForQuad(content);
  model->padding = BuildArrayForQuad(padding);
  model->border = BuildArrayForQuad(border);
  model->margin = BuildArrayForQuad(margin);
  model->width = model_object ? blink::AdjustForAbsoluteZoom::AdjustInt(
                                       model_object->PixelSnappedOffsetWidth(
                                           model_object->OffsetParent()),
                                       model_object)
                                 : bounding_box.Width();

  model->height = model_object ? blink::AdjustForAbsoluteZoom::AdjustInt(
                                        model_object->PixelSnappedOffsetHeight(
                                            model_object->OffsetParent()),
                                        model_object)
                                  : bounding_box.Height();

  blink::Shape::DisplayPaths paths;
  blink::FloatQuad bounds_quad;
  if (const blink::ShapeOutsideInfo* shape_outside_info =
          ShapeOutsideInfoForNode(node, &paths, &bounds_quad)) {
    auto new_shape_outside = automation::ShapeOutsideInfo::New();
    new_shape_outside->bounds = BuildArrayForQuad(bounds_quad);
    new_shape_outside->shape.push_back(
        ShapePathBuilder::BuildPath(*view, *layout_object,
                                  *shape_outside_info, paths.shape,
                                  1.f));
    new_shape_outside->margin_shape.push_back(
                ShapePathBuilder::BuildPath(*view, *layout_object,
                                            *shape_outside_info,
                                            paths.margin_shape, 1.f));
    model->shape_outside = std::move(new_shape_outside);
  }

  return model;
}

bool InspectorHighlight::BuildNodeQuads(blink::Node* node,
                                        blink::FloatQuad* content,
                                        blink::FloatQuad* padding,
                                        blink::FloatQuad* border,
                                        blink::FloatQuad* margin) {
  blink::LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return false;

  blink::LocalFrameView* containing_view = layout_object->GetFrameView();
  if (!containing_view)
    return false;
  if (!layout_object->IsBox() && !layout_object->IsLayoutInline())
    return false;

  blink::LayoutRect content_box;
  blink::LayoutRect padding_box;
  blink::LayoutRect border_box;
  blink::LayoutRect margin_box;

  if (layout_object->IsBox()) {
    blink::LayoutBox* layout_box = ToLayoutBox(layout_object);

    // LayoutBox returns the "pure" content area box, exclusive of the
    // scrollbars (if present), which also count towards the content area in
    // CSS.
    const int vertical_scrollbar_width = layout_box->VerticalScrollbarWidth();
    const int horizontal_scrollbar_height =
        layout_box->HorizontalScrollbarHeight();
    content_box = layout_box->ContentBoxRect();
    content_box.SetWidth(content_box.Width() + vertical_scrollbar_width);
    content_box.SetHeight(content_box.Height() + horizontal_scrollbar_height);

    padding_box = layout_box->PaddingBoxRect();
    padding_box.SetWidth(padding_box.Width() + vertical_scrollbar_width);
    padding_box.SetHeight(padding_box.Height() + horizontal_scrollbar_height);

    border_box = layout_box->BorderBoxRect();

    margin_box = blink::LayoutRect(border_box.X() - layout_box->MarginLeft(),
                            border_box.Y() - layout_box->MarginTop(),
                            border_box.Width() + layout_box->MarginWidth(),
                            border_box.Height() + layout_box->MarginHeight());
  } else {
    blink::LayoutInline* layout_inline = ToLayoutInline(layout_object);

    // LayoutInline's bounding box includes paddings and borders, excludes
    // margins.
    border_box = blink::LayoutRect(layout_inline->LinesBoundingBox());
    padding_box = blink::LayoutRect(border_box.X() + layout_inline->BorderLeft(),
                             border_box.Y() + layout_inline->BorderTop(),
                             border_box.Width() - layout_inline->BorderLeft() -
                                 layout_inline->BorderRight(),
                             border_box.Height() - layout_inline->BorderTop() -
                                 layout_inline->BorderBottom());
    content_box =
        blink::LayoutRect(padding_box.X() + layout_inline->PaddingLeft(),
                   padding_box.Y() + layout_inline->PaddingTop(),
                   padding_box.Width() - layout_inline->PaddingLeft() -
                       layout_inline->PaddingRight(),
                   padding_box.Height() - layout_inline->PaddingTop() -
                       layout_inline->PaddingBottom());
    // Ignore marginTop and marginBottom for inlines.
    margin_box = blink::LayoutRect(
        border_box.X() - layout_inline->MarginLeft(), border_box.Y(),
        border_box.Width() + layout_inline->MarginWidth(), border_box.Height());
  }

  *content = layout_object->LocalToAbsoluteQuad(blink::FloatRect(content_box));
  *padding = layout_object->LocalToAbsoluteQuad(blink::FloatRect(padding_box));
  *border = layout_object->LocalToAbsoluteQuad(blink::FloatRect(border_box));
  *margin = layout_object->LocalToAbsoluteQuad(blink::FloatRect(margin_box));

  ContentsQuadToViewport(containing_view, *content);
  ContentsQuadToViewport(containing_view, *padding);
  ContentsQuadToViewport(containing_view, *border);
  ContentsQuadToViewport(containing_view, *margin);

  return true;
}

// static
InspectorHighlightConfig InspectorHighlight::DefaultConfig() {
  InspectorHighlightConfig config;
  config.content = blink::Color(255, 0, 0, 0);
  config.content_outline = blink::Color(128, 0, 0, 0);
  config.padding = blink::Color(0, 255, 0, 0);
  config.border = blink::Color(0, 0, 255, 0);
  config.margin = blink::Color(255, 255, 255, 0);
  config.event_target = blink::Color(128, 128, 128, 0);
  config.shape = blink::Color(0, 0, 0, 0);
  config.shape_margin = blink::Color(128, 128, 128, 0);
  config.show_info = true;
  config.show_rulers = true;
  config.show_extension_lines = true;
  config.display_as_material = false;
  config.css_grid = blink::Color(128, 128, 128, 0);
  return config;
}

}  // namespace blink
