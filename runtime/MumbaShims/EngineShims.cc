// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "EngineShims.h"
#include "EngineHelper.h"
#include "StorageHelper.h"

#include "base/guid.h"
#include "core/shared/domain/storage/storage_manager.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/application/application_driver.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/renderer/platform/blob/blob_bytes_provider.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"

namespace {

struct Memento {
  void* state = nullptr;
  void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url) = nullptr;
};

struct BlobDataState {
  std::unique_ptr<blink::BlobData> ptr;
  scoped_refptr<blink::BlobDataHandle> handle;
};

void CreateApplicationState(
  void* state, void* app_state, const char* name, const char* uuid, const char* url) {
  Memento* memento = reinterpret_cast<Memento*>(state);
  // the lifetime of this object should be handled by the caller
  ApplicationState* wrapper = new ApplicationState(reinterpret_cast<domain::Application*>(app_state));
  memento->foreach(memento->state, wrapper, name, uuid, url);  
}

void GetInfoCb(CGetInfoCallback cb, void* state, automation::GPUInfoPtr gpu, const std::string& model_name, const std::string& model_version, const std::string& command_line) {
  cb(state, gpu.get(), model_name.data(), model_version.data(), command_line.data());
}

void GetVersionCb(
  CGetVersionCallback cb,
  void* state,
  const std::string& protocol_version, 
  const std::string& product, 
  const std::string& revision, 
  const std::string& user_agent, 
  const std::string& js_version) {
  cb(state, protocol_version.data(), product.data(), revision.data(), user_agent.data(), js_version.data());
}

void GetHostCommandLineCb(CGetHostCommandLineCallback cb, void* state, const std::vector<std::string>& args) {
  const char* args_arr[args.size()];
  size_t i = 0;
  for (const std::string& arg : args) {
    args_arr[i] = arg.data();
    i++;
  }
  cb(state, args_arr, args.size());
}

void GetHistogramsCb(CGetHistogramsCallback cb, void* state, std::vector<automation::HistogramPtr> ptrs) {
  void* ptrs_arr[ptrs.size()];
  size_t i = 0;
  for (const automation::HistogramPtr& ptr : ptrs) {
    ptrs_arr[i] = ptr.get();
    i++;
  }
  cb(state, ptrs_arr, ptrs.size());
}

void GetHistogramCb(CGetHistogramCallback cb, void* state, automation::HistogramPtr ptr) {
  cb(state, ptr.get());
}

void GetWindowBoundsCb(CGetWindowBoundsCallback cb, void* state, automation::BoundsPtr bounds) {
  cb(state, bounds.get());
}

void GetWindowForTargetCb(CGetWindowForTargetCallback cb, void* state, int32_t window_id, automation::BoundsPtr bounds) {
  cb(state, window_id, bounds.get());
}

void AddScriptToEvaluateOnNewDocumentCb(CAddScriptToEvaluateOnNewDocumentCallback cb, void* state, const std::string& str) {
  cb(state, str.data());
}

void NavigateCb(CNavigateCallback cb, void* state, const std::string& frame_id, int32_t loader_id, const std::string& error_text) {
  cb(state, frame_id.data(), loader_id, error_text.data());
}

void GetNavigationHistoryCb(CGetNavigationHistoryCallback cb, void* state, int32_t index, std::vector<automation::NavigationEntryPtr> entries) {
  void* ptrs_arr[entries.size()];
  size_t i = 0;
  for (const automation::NavigationEntryPtr& ptr : entries) {
    ptrs_arr[i] = ptr.get();
    i++;
  }
  cb(state, index, ptrs_arr, entries.size());
}

void GetCookiesCb(CGetCookiesCallback cb, void* state, std::vector<automation::CookiePtr> cookies) {
  void* ptrs_arr[cookies.size()];
  size_t i = 0;
  for (const automation::CookiePtr& ptr : cookies) {
    ptrs_arr[i] = ptr.get();
    i++;
  }
  cb(state, ptrs_arr, cookies.size());  
}

void GetResourceTreeCb(CGetResourceTreeCallback cb, void* state, automation::FrameResourceTreePtr resource_tree) {
  cb(state, resource_tree.get());
}

void GetFrameTreeCb(CGetFrameTreeCallback cb, void* state, automation::FrameTreePtr frame_tree) {
  cb(state, frame_tree.get());
}

void GetResourceContentCb(CGetResourceContentCallback cb, void* state, const std::string& content, bool base64_encoded) {
  cb(state, content.data(), base64_encoded);
}

void SearchInResourceCb(CSearchInResourceCallback cb, void* state, std::vector<automation::SearchMatchPtr> match_ptrs) {
  void* ptrs_arr[match_ptrs.size()];
  size_t i = 0;
  for (const automation::SearchMatchPtr& ptr : match_ptrs) {
    ptrs_arr[i] = ptr.get();
    i++;
  }
  cb(state, ptrs_arr, match_ptrs.size());
}

void CaptureScreenshotCb(CCaptureScreenshotCallback cb, void* state, const std::string& base64_data)  {
  cb(state, base64_data.data());
}

void PrintToPDFCb(CPrintToPDFCallback cb, void* state, const std::string& base64_data) {
  cb(state, base64_data.data());
}

void GetAppManifestCb(CGetAppManifestCallback cb, void* state, const std::string& url, const std::vector<std::string>& errors, const base::Optional<std::string>& data) {
  const char* errors_arr[errors.size()];
  size_t i = 0;
  for (const std::string& error : errors) {
    errors_arr[i] = error.data();
    i++;
  }
  cb(state, url.data(), errors_arr, errors.size(), data.has_value() ? data.value().data() : nullptr);
}

void GetLayoutMetricsCb(CGetLayoutMetricsCallback cb, void* state, automation::LayoutViewportPtr layout_viewport, automation::VisualViewportPtr visual_viewport, const gfx::Rect& content_size) {
  cb(state, layout_viewport.get(), visual_viewport.get(), content_size.x(), content_size.y(), content_size.width(), content_size.height());
}

void CreateIsolatedWorldCb(CCreateIsolatedWorldCallback cb, void* state, int32_t id) {
  cb(state, id);
}

void CanClearBrowserCacheCb(CCanClearBrowserCacheCallback cb, void* state, bool result) {
  cb(state, result ? 1 : 0);
}

void CanClearBrowserCookiesCb(CCanClearBrowserCookiesCallback cb, void* state, bool result) {
  cb(state, result ? 1 : 0);
}

void CanEmulateNetworkConditionsCb(CCanEmulateNetworkConditionsCallback cb, void* state, bool result) {
  cb(state, result ? 1 : 0);
}

void GetAllCookiesCb(CGetAllCookiesCallback cb, void* state, std::vector<automation::CookiePtr> cookies) {
  void* cookies_arr[cookies.size()];
  size_t i = 0;
  for (const automation::CookiePtr& ptr : cookies) {
    cookies_arr[i] = ptr.get();
    i++;
  }
  cb(state, cookies_arr, cookies.size());
}

void GetCertificateCb(CGetCertificateCallback cb, void* state, const std::vector<std::string>& table_names) {
  const char* tables_arr[table_names.size()];
  size_t i = 0;
  for (const std::string& table : table_names) {
    tables_arr[i] = table.data();
    i++;
  }
  cb(state, tables_arr, table_names.size());
}

// void GetCookiesCb(GetCookiesCallback cb, std::vector<automation::CookiePtr> cookies) {
//   void* cookies_arr[cookies.size()];
//   size_t i = 0;
//   for (const automation::CookiePtr& ptr : cookies) {
//     cookies_arr[i] = ptr.get();
//     i++;
//   }
//   cb(state, cookies_arr, cookies.size());
// }

void GetResponseBodyCb(CGetResponseBodyCallback cb, void* state, const std::string& body, bool base64_encoded) {
  cb(state, body.data(), base64_encoded ? 1 : 0);
}

void GetRequestPostDataCb(CGetRequestPostDataCallback cb, void* state, const std::string& post_data) {
  cb(state, post_data.data());
}

void GetResponseBodyForInterceptionCb(CGetResponseBodyForInterceptionCallback cb, void* state, const std::string& body, bool base64_encoded) {
  cb(state, body.data(), base64_encoded);
}

void TakeResponseBodyForInterceptionAsStreamCb(CTakeResponseBodyForInterceptionAsStreamCallback cb, void* state, const std::string& stream) {
  cb(state, stream.data());
}

void SearchInResponseBodyCb(CSearchInResponseBodyCallback cb, void* state, std::vector<automation::SearchMatchPtr> matches) {
  void* matches_arr[matches.size()];
  size_t i = 0;
  for (const automation::SearchMatchPtr& ptr : matches) {
    matches_arr[i] = ptr.get();
    i++;
  }
  cb(state, matches_arr, matches.size());
}

void SetCookieCb(CSetCookieCallback cb, void* state, bool result) {
  cb(state, result);
}

void CompositingReasonsCb(CCompositingReasonsCallback cb, void* state, const std::vector<std::string>& compositing_reasons) {
  const char* reasons[compositing_reasons.size()];
  size_t i = 0;
  for (const auto& reason : compositing_reasons) {
    reasons[i] = reason.data();
    i++;
  }  
  cb(state, reasons, compositing_reasons.size());
}

void LoadSnapshotCb(CLoadSnapshotCallback cb, void* state, const std::string& snapshot_id) {
  cb(state, snapshot_id.data());
}

void MakeSnapshotCb(CMakeSnapshotCallback cb, void* state, const std::string& snapshot_id) {
  cb(state, snapshot_id.data());
}

void ProfileSnapshotCb(CProfileSnapshotCallback cb, void* state, const std::vector<std::vector<double>>& timings) {
  double** arr = (double **)malloc(timings.size() * sizeof(double));
  size_t i = 0;
  size_t x = 0;
  for (const auto& timing : timings) {
    arr[i] = (double *)malloc(timing.size() * sizeof(double));
    for (; x < timing.size(); x++) {
      arr[i][x] = timing[x];
    }
    i++;
  }
  cb(state, arr, timings.size(), x);
  
  for (i = 0;i < timings.size(); i++) {
    free(arr[i]);
  }
  free(arr);
}

void ReplaySnapshotCb(CReplaySnapshotCallback cb, void* state, const std::string& data_url) {
  cb(state, data_url.data());
}

void SnapshotCommandLogCb(CSnapshotCommandLogCallback cb, void* state, const std::string& command_log) {
  cb(state, command_log.data());
}

void DispatchKeyEventCb(CDispatchKeyEventCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void DispatchMouseEventCb(CDispatchMouseEventCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void DispatchTouchEventCb(CDispatchTouchEventCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void EmulateTouchFromMouseEventCb(CEmulateTouchFromMouseEventCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void SynthesizePinchGestureCb(CSynthesizePinchGestureCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void SynthesizeScrollGestureCb(CSynthesizeScrollGestureCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void SynthesizeTapGestureCb(CSynthesizeTapGestureCallback cb, void* state, bool result) {
  cb(state, result != 0);
}

void ClearObjectStoreCb(CClearObjectStoreCallback cb, void* state, bool success) {
  cb(state, success != 0);
}

void DeleteDatabaseCb(CDeleteDatabaseCallback cb, void* state, bool success) {
  cb(state, success != 0);
}

void DeleteObjectStoreEntriesCb(CDeleteObjectStoreEntriesCallback cb, void* state, bool success) {
  cb(state, success != 0);
}

void RequestDataCb(CRequestDataCallback cb, void* state, std::vector<automation::IndexedDBDataEntryPtr> entries, bool has_more) {
  void* arr[entries.size()];
  size_t i = 0;
  for (const auto& entry : entries) {
    arr[i] = entry.get();
    i++;
  }  
  cb(state, arr, entries.size(), has_more != 0);
}

void RequestDatabaseCb(CRequestDatabaseCallback cb, void* state, automation::DatabaseWithObjectStoresPtr database_with_object_stores) {
  cb(state, database_with_object_stores.get());
}

void RequestDatabaseNamesCb(CRequestDatabaseNamesCallback cb, void* state, const std::vector<std::string>& stores) {
  const char* arr[stores.size()];
  size_t i = 0;
  for (const auto& store : stores) {
    arr[i] = store.data();
    i++;
  }  
  cb(state, arr, stores.size());
}

void ReadCb(CReadCallback cb, void* state, bool base64_encoded, const std::string& data, bool eof) {
  cb(state, base64_encoded ? 1 : 0, data.data(), eof ? 1 : 0);
}

void ResolveBlobCb(CResolveBlobCallback cb, void* state, const std::string& uuid) {
  cb(state, uuid.data());
}

void BeginFrameCb(CBeginFrameCallback cb, void* state, bool has_damage, const base::Optional<std::string>& screenshot_data) {
  cb(state, has_damage ? 1 : 0, screenshot_data.has_value() ? screenshot_data.value().data() : nullptr);
}

void GetDOMStorageItemsCb(CGetDOMStorageItemsCallback cb, void* state, const std::vector<std::vector<std::string>>& items) {
  const char*** arr = (const char ***)malloc(items.size());
  size_t i = 0;
  size_t x = 0;
  for (; i < items.size(); i++) {
    arr[i] = (const char **)malloc(items[i].size());
    for (; x < items[i].size(); x++) {
      arr[i][x] = (char *)malloc(items[i][x].size() * sizeof(char));
      arr[i][x] = items[i][x].data();
    }
  }
  cb(state, arr, items.size(), x);
  for (i = 0; i < items.size(); i++) {
    for (x = 0; x < items[i].size(); x++) {
      free(const_cast<char *>(arr[i][x]));
    }
    free(arr[i]);
  }
  free(arr);
}

void ExecuteSQLCb(CExecuteSQLCallback cb, void* state, const base::Optional<std::vector<std::string>>& column_names, base::Optional<std::vector<std::unique_ptr<base::Value>>> values, automation::ErrorPtr sql_error) {
  size_t len = column_names.has_value() ? column_names.value().size() : 0;
  size_t values_len = values.has_value() ? values.value().size() : 0;
  const char* names_arr[len];
  void* values_arr[values_len];

  for (size_t i = 0; i < len; i++) {
    names_arr[i] = column_names.value()[i].data();
  }

  for (size_t i = 0; i < values_len; i++) {
    values_arr[i] = values.value()[i].get();
  }

  cb(state, names_arr, len, values_arr, values_len, sql_error.get());
}

void GetDatabaseTableNamesCb(CGetDatabaseTableNamesCallback cb, void* state, const std::vector<std::string>& table_names) {
  const char* arr[table_names.size()];
  size_t i = 0;
  for (const auto& table : table_names) {
    arr[i] = table.data();
    i++;
  }  
  cb(state, arr, table_names.size());
}

void CanEmulateCb(CCanEmulateCallback cb, void* state, bool result) {
  cb(state, result);
}

void SetVirtualTimePolicyCb(CSetVirtualTimePolicyCallback cb, void* state, int64_t virtual_time_base, int64_t virtual_time_ticks_base) {
  cb(state, virtual_time_base, virtual_time_ticks_base);
}

void GetSnapshotCb(CGetSnapshotCallback cb, void* state, std::vector<automation::DOMSnapshotNodePtr> dom_nodes, std::vector<automation::LayoutTreeNodePtr> layout_tree_nodes, std::vector<automation::ComputedStylePtr> computed_styles) {
  void* dom_arr[dom_nodes.size()];
  void* layout_arr[layout_tree_nodes.size()];
  void* styles_arr[computed_styles.size()];

  for (size_t i = 0; i < dom_nodes.size(); i++) {
    dom_arr[i] = dom_nodes[i].get();
  }

  for (size_t i = 0; i < layout_tree_nodes.size(); i++) {
    layout_arr[i] = layout_tree_nodes[i].get();
  }

  for (size_t i = 0; i < computed_styles.size(); i++) {
    styles_arr[i] = computed_styles[i].get();
  }

  cb(state, dom_arr, dom_nodes.size(), layout_arr, layout_tree_nodes.size(), styles_arr, computed_styles.size());
}

void CollectClassNamesFromSubtreeCb(CCollectClassNamesFromSubtreeCallback cb, void* state, const std::vector<std::string>& class_names) {
  const char* names_arr[class_names.size()];

  for (size_t i = 0; i < class_names.size(); i++) {
    names_arr[i] = class_names[i].data();
  }

  cb(state, names_arr, class_names.size());
}

void CopyToCb(CCopyToCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void DescribeNodeCb(CDescribeNodeCallback cb, void* state, automation::DOMNodePtr node) {
  cb(state, node.get());
}

void GetAttributesCb(CGetAttributesCallback cb, void* state, const std::vector<std::string>& attr) {
  const char* attr_arr[attr.size()];

  for (size_t i = 0; i < attr.size(); i++) {
    attr_arr[i] = attr[i].data();
  }

  cb(state, attr_arr, attr.size());
}

void GetBoxModelCb(CGetBoxModelCallback cb, void* state, automation::BoxModelPtr model) {
  cb(state, model.get());
}

void GetDocumentCb(CGetDocumentCallback cb, void* state, automation::DOMNodePtr doc) {
  cb(state, doc.get());
}

void GetFlattenedDocumentCb(CGetFlattenedDocumentCallback cb, void* state, std::vector<automation::DOMNodePtr> nodes) {
  void* nodes_arr[nodes.size()];

  for (size_t i = 0; i < nodes.size(); i++) {
    nodes_arr[i] = nodes[i].get();
  }

  cb(state, nodes_arr, nodes.size());
}

void GetNodeForLocationCb(CGetNodeForLocationCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void GetOuterHTMLCb(CGetOuterHTMLCallback cb, void* state, const std::string& outer_html) {
  cb(state, outer_html.data());
}

void GetRelayoutBoundaryCb(CGetRelayoutBoundaryCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void GetSearchResultsCb(CGetSearchResultsCallback cb, void* state, const std::vector<int32_t>& nodes_id) {
  int32_t nodes_arr[nodes_id.size()];
  for (size_t i = 0; i < nodes_id.size(); i++) {
    nodes_arr[i] = nodes_id[i];
  }
  cb(state, nodes_arr, nodes_id.size());
}

void MoveToCb(CMoveToCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void PerformSearchCb(CPerformSearchCallback cb, void* state, const std::string& search_id, int32_t result_count) {
  cb(state, search_id.data(), result_count);
}

void PushNodeByPathToFrontendCb(CPushNodeByPathToFrontendCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void PushNodesByBackendIdsToFrontendCb(CPushNodesByBackendIdsToFrontendCallback cb, void* state, const std::vector<int32_t>& nodes_id) {
  int32_t nodes_arr[nodes_id.size()];
  for (size_t i = 0; i < nodes_id.size(); i++) {
    nodes_arr[i] = nodes_id[i];
  }
  cb(state, nodes_arr, nodes_id.size());
}

void QuerySelectorCb(CQuerySelectorCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void QuerySelectorAllCb(CQuerySelectorAllCallback cb, void* state, const std::vector<int32_t>& nodes_id) {
  int32_t nodes_arr[nodes_id.size()];
  for (size_t i = 0; i < nodes_id.size(); i++) {
    nodes_arr[i] = nodes_id[i];
  }
  cb(state, nodes_arr, nodes_id.size());
}

void RequestNodeCb(CRequestNodeCallback cb, void* state, int32_t node_id) {
  cb(state, node_id);
}

void ResolveNodeCb(CResolveNodeCallback cb, void* state, automation::RemoteObjectPtr object) {
  cb(state, object.get());
}

void SetNodeNameCb(CSetNodeNameCallback cb, void* state, int32_t id) {
  cb(state, id);
}

void GetFrameOwnerCb(CGetFrameOwnerCallback cb, void* state, int32_t id) {
  cb(state, id);  
}

void AddRuleCb(CAddRuleCallback cb, void* state, automation::CSSRulePtr rule) {
  cb(state, rule.get());
}

void CollectClassNamesCb(CCollectClassNamesCallback cb, void* state, const std::vector<std::string>& names) {
  const char* names_arr[names.size()];

  for (size_t i = 0; i < names.size(); i++) {
    names_arr[i] = names[i].data();
  }

  cb(state, names_arr, names.size());
}

void CreateStyleSheetCb(CCreateStyleSheetCallback cb, void* state, const std::string& style_sheet_id) {
  cb(state, style_sheet_id.data());
}

void GetBackgroundColorsCb(CGetBackgroundColorsCallback cb, void* state, const base::Optional<std::vector<std::string>>& background_colors, const base::Optional<std::string>& computed_font_size, const base::Optional<std::string>& computed_font_weight, const base::Optional<std::string>& computed_body_font_size) {
  size_t len = background_colors.has_value() ? background_colors.value().size() : 0;
  const char* colors_arr[len];
  for (size_t i = 0; i < len; i++) {
    colors_arr[i] = background_colors.value()[i].data();
  }
  cb(state, colors_arr, 
     len,
     computed_font_size.has_value() ?
      computed_font_size.value().data() :
      nullptr,
     computed_font_weight.has_value() ? 
      computed_font_weight.value().data() : 
      nullptr,
     computed_body_font_size.has_value() ? 
      computed_body_font_size.value().data() : 
      nullptr);
}

void GetComputedStyleForNodeCb(CGetComputedStyleForNodeCallback cb, void* state, std::vector<automation::CSSComputedStylePropertyPtr> styles) {
  void* nodes_arr[styles.size()];

  for (size_t i = 0; i < styles.size(); i++) {
    nodes_arr[i] = styles[i].get();
  }
  cb(state, nodes_arr, styles.size());
}

void GetInlineStylesForNodeCb(CGetInlineStylesForNodeCallback cb, void* state, automation::CSSStylePtr inline_style, automation::CSSStylePtr attributes_style) {
  cb(state, inline_style.get(), attributes_style.get());
}

void GetMatchedStylesForNodeCb(CGetMatchedStylesForNodeCallback cb, void* state, 
  automation::CSSStylePtr inline_style, 
  automation::CSSStylePtr attributes_style, 
  base::Optional<std::vector<automation::RuleMatchPtr>> matched_css_rules, 
  base::Optional<std::vector<automation::PseudoElementMatchesPtr>> pseudo_elements, 
  base::Optional<std::vector<automation::InheritedStyleEntryPtr>> inherited, 
  base::Optional<std::vector<automation::CSSKeyframesRulePtr>> css_keyframes_rules) {
  
  size_t matched_css_rules_len = matched_css_rules.has_value() ? matched_css_rules.value().size() : 0;
  size_t pseudo_elements_len = pseudo_elements.has_value() ? pseudo_elements.value().size() : 0;
  size_t inherited_len = inherited.has_value() ? inherited.value().size() : 0;
  size_t css_keyframes_rules_len = css_keyframes_rules.has_value() ? css_keyframes_rules.value().size() : 0;

  void* matched_arr[matched_css_rules_len];
  void* pseudo_arr[pseudo_elements_len];
  void* inherited_arr[inherited_len];
  void* css_arr[css_keyframes_rules_len];

  for (size_t i = 0; i < matched_css_rules_len; i++) {
    matched_arr[i] = matched_css_rules.value()[i].get();
  }

  for (size_t i = 0; i < pseudo_elements_len; i++) {
    pseudo_arr[i] = pseudo_elements.value()[i].get();
  }

  for (size_t i = 0; i < inherited_len; i++) {
    inherited_arr[i] = inherited.value()[i].get();
  }

  for (size_t i = 0; i < css_keyframes_rules_len; i++) {
    css_arr[i] = css_keyframes_rules.value()[i].get();
  }

  cb(state, inline_style.get(), attributes_style.get(), matched_arr, matched_css_rules_len, pseudo_arr, pseudo_elements_len, inherited_arr, inherited_len, css_arr, css_keyframes_rules_len);
}

void GetMediaQueriesCb(CGetMediaQueriesCallback cb, void* state, std::vector<automation::CSSMediaPtr> media) {
  void* nodes_arr[media.size()];

  for (size_t i = 0; i < media.size(); i++) {
    nodes_arr[i] = media[i].get();
  }
  
  cb(state, nodes_arr, media.size());
}

void GetPlatformFontsForNodeCb(CGetPlatformFontsForNodeCallback cb, void* state, std::vector<automation::PlatformFontUsagePtr> usage) {
  void* nodes_arr[usage.size()];

  for (size_t i = 0; i < usage.size(); i++) {
    nodes_arr[i] = usage[i].get();
  }

  cb(state, nodes_arr, usage.size());
}

void GetStyleSheetTextCb(CGetStyleSheetTextCallback cb, void* state, const std::string& text) {
  cb(state, text.data());
}

void SetKeyframeKeyCb(CSetKeyframeKeyCallback cb, void* state, automation::CSSValuePtr value) {
  cb(state, value.get());
}

void SetMediaTextCb(CSetMediaTextCallback cb, void* state, automation::CSSMediaPtr media) {
  cb(state, media.get());
}

void SetRuleSelectorCb(CSetRuleSelectorCallback cb, void* state, automation::SelectorListPtr selector) {
  cb(state, selector.get());
}

void SetStyleSheetTextCb(CSetStyleSheetTextCallback cb, void* state, const base::Optional<std::string>& text) {
  cb(state, text.has_value() ? text.value().data() : nullptr);
}

void SetStyleTextsCb(CSetStyleTextsCallback cb, void* state, std::vector<automation::CSSStylePtr> styles) {
  void* nodes_arr[styles.size()];

  for (size_t i = 0; i < styles.size(); i++) {
    nodes_arr[i] = styles[i].get();
  }

  cb(state, nodes_arr, styles.size());
}

void StopRuleUsageTrackingCb(CStopRuleUsageTrackingCallback cb, void* state, std::vector<automation::CSSRuleUsagePtr> usage) {
  void* nodes_arr[usage.size()];

  for (size_t i = 0; i < usage.size(); i++) {
    nodes_arr[i] = usage[i].get();
  }

  cb(state, nodes_arr, usage.size());
}

void TakeCoverageDeltaCb(CTakeCoverageDeltaCallback cb, void* state, std::vector<automation::CSSRuleUsagePtr> usage) {
  void* nodes_arr[usage.size()];

  for (size_t i = 0; i < usage.size(); i++) {
    nodes_arr[i] = usage[i].get();
  }

  cb(state, nodes_arr, usage.size());
}

void HasCacheCb(CHasCacheCallback cb, void* state, bool success) {
  cb(state, success ? 1 : 0);
}

void DeleteCacheCb(CDeleteCacheCallback cb, void* state, bool success) {
  cb(state, success ? 1 : 0);
}

void OpenCacheCb(COpenCacheCallback cb, void* state, int code) {
  cb(state, code);
}

void DeleteEntryCb(CDeleteEntryCallback cb, void* state, bool success) {
  cb(state, success);
}

void PutEntryCb(CPutEntryCallback cb, void* state, bool success) {
  cb(state, success ? 1 : 0);
}

void RequestCacheNamesCb(CRequestCacheNamesCallback cb, void* state, std::vector<automation::CachePtr> cache_entries) {
  void* nodes_arr[cache_entries.size()];

  for (size_t i = 0; i < cache_entries.size(); i++) {
    nodes_arr[i] = cache_entries[i].get();
  }

  cb(state, nodes_arr, cache_entries.size());
}

void RequestCachedResponseCb(CRequestCachedResponseCallback cb, void* state, automation::CachedResponsePtr response) {
  cb(state, response->body.data(), response->body.size());
}

void RequestEntriesCb(CRequestEntriesCallback cb, void* state, std::vector<automation::DataEntryPtr> cache_entries, bool has_more) {
  void* nodes_arr[cache_entries.size()];

  for (size_t i = 0; i < cache_entries.size(); i++) {
    nodes_arr[i] = cache_entries[i].get();
  }

  cb(state, nodes_arr, cache_entries.size(), has_more);
}

void GetApplicationCacheForFrameCb(CGetApplicationCacheForFrameCallback cb, void* state, automation::ApplicationCachePtr app_cache) {
  cb(state, app_cache.get());
}

void GetFramesWithManifestsCb(CGetFramesWithManifestsCallback cb, void* state, std::vector<automation::FrameWithManifestPtr> frames) {
  void* nodes_arr[frames.size()];

  for (size_t i = 0; i < frames.size(); i++) {
    nodes_arr[i] = frames[i].get();
  }

  cb(state, nodes_arr, frames.size());
}

void GetManifestForFrameCb(CGetManifestForFrameCallback cb, void* state, const std::string& manifest) {
  cb(state, manifest.data());
}

void GetCurrentTimeCb(CGetCurrentTimeCallback cb, void* state, int32_t time) {
  cb(state, time);
}

void GetPlaybackRateCb(CGetPlaybackRateCallback cb, void* state, int32_t rate) {
  cb(state, rate);
}

void ResolveAnimationCb(CResolveAnimationCallback cb, void* state, automation::AnimationPtr anim) {
  cb(state, anim.get());
}

void GetPartialAXTreeCb(CGetPartialAXTreeCallback cb, void* state, std::vector<automation::AXNodePtr> nodes) {
  void* nodes_arr[nodes.size()];

  for (size_t i = 0; i < nodes.size(); i++) {
    nodes_arr[i] = nodes[i].get();
  }

  cb(state, nodes_arr, nodes.size());
}

} // namespace

EngineInstanceRef _EngineCreate(
  void* state,
  CEngineCallbacks callbacks) {
  std::unique_ptr<EngineClientImpl> client =
    std::unique_ptr<EngineClientImpl>(new EngineClientImpl(state, callbacks));
  _EngineInstance* module_state = new _EngineInstance(std::move(client));
  return module_state;
}

void _EngineDestroy(EngineInstanceRef handle) {
  delete reinterpret_cast<_EngineInstance *>(handle);
}

EngineClientRef _EngineGetClient(EngineInstanceRef handle) {
  return reinterpret_cast<_EngineInstance *>(handle)->client();
}

void _EngineForeachApplication(EngineInstanceRef handle, void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url)) {
  domain::ModuleState* module_state = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  DCHECK(module_state);
  Memento memento;
  memento.state = state; 
  memento.foreach = foreach;
  module_state->ForeachApplication(&memento, &CreateApplicationState);
}

StorageRef _EngineStorageCreate(EngineInstanceRef handle, void* state, StorageShareCallbacks callbacks) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  scoped_refptr<domain::StorageContext> context = module->storage_manager()->GetOrCreateContext();
  return new StorageState(std::move(context), module, state, std::move(callbacks));
}

// PlaceRegistryRef _EngineGetPlaceRegistry(EngineInstanceRef handle) {
//   domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
//   return module->route_registry();
// }

void _ApplicationHostDestroy(ApplicationHostRef handle) {
  delete reinterpret_cast<ApplicationState *>(handle);
}

void _ApplicationHostBindCallbacks(ApplicationHostRef handle, void* state, CApplicationHostCallbacks callbacks) {
  reinterpret_cast<ApplicationState *>(handle)->set_callbacks(state, std::move(callbacks));
}

void _ApplicationHostInstanceLaunch(ApplicationHostRef handle, 
  int id, 
  const char* url,
  int window_mode,
  int initial_bounds_x,
  int initial_bounds_y,
  int initial_bounds_w,
  int initial_bounds_h,
  int window_open_disposition,
  int fullscreen,
  int headless) {

  reinterpret_cast<ApplicationState *>(handle)->application()->CreateInstance(
    id, 
    url,
    static_cast<domain::WindowMode>(window_mode),
    gfx::Rect(initial_bounds_x, initial_bounds_y, initial_bounds_w, initial_bounds_h),
    static_cast<ui::mojom::WindowOpenDisposition>(window_open_disposition),
    fullscreen != 0,
    headless != 0);
}

void _ApplicationHostInstanceKill(ApplicationHostRef handle, int id) {
  reinterpret_cast<ApplicationState *>(handle)->application()->KillInstance(id);
}

void _ApplicationHostInstanceClose(ApplicationHostRef handle, int id) {
  reinterpret_cast<ApplicationState *>(handle)->application()->CloseInstance(id);
}

void _ApplicationHostInstanceActivate(ApplicationHostRef handle, int id) {
  reinterpret_cast<ApplicationState *>(handle)->application()->ActivateInstance(id);
}

void _ApplicationHostSetPageCallbacks(ApplicationHostRef handle, CPageCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->page_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetOverlayCallbacks(ApplicationHostRef handle, COverlayCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->overlay_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetWorkerCallbacks(ApplicationHostRef handle, CWorkerCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->worker_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetStorageCallbacks(ApplicationHostRef handle, CStorageCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->storage_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetTetheringCallbacks(ApplicationHostRef handle, CTetheringCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->tethering_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetNetworkCallbacks(ApplicationHostRef handle, CNetworkCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->network_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetLayerTreeCallbacks(ApplicationHostRef handle, CLayerTreeCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->layer_tree_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetHeadlessCallbacks(ApplicationHostRef handle, CHeadlessCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->headless_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetDOMStorageCallbacks(ApplicationHostRef handle, CDOMStorageCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->dom_storage_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetDatabaseCallback(ApplicationHostRef handle, CDatabaseCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->database_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetEmulationCallbacks(ApplicationHostRef handle, CEmulationCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->emulation_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetDOMCallbacks(ApplicationHostRef handle, CDOMCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->dom_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetCSSCallbacks(ApplicationHostRef handle, CCSSCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->css_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetApplicationCacheCallbacks(ApplicationHostRef handle, CApplicationCacheCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->application_cache_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetAnimationCallbacks(ApplicationHostRef handle, CAnimationCallbacks cbs) {
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->animation_callbacks_ = std::move(cbs);
}

void _ApplicationHostSetDriverStateForInstance(ApplicationHostRef handle, int id, void* state) {
  //DLOG(INFO) << "_ApplicationHostSetDriverStateForInstance";
  domain::Application* app = reinterpret_cast<ApplicationState *>(handle)->application();
  app->set_driver_state(id, state);
}

// SystemInfo
void _ApplicationHostSystemInfoGetInfo(ApplicationHostRef handle, int instance_id, CGetInfoCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->system_info()->GetInfo(base::BindOnce(&GetInfoCb, base::Unretained(callback), base::Unretained(state)));
}

// Host
void _ApplicationHostHostClose(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->Close();
}

void _ApplicationHostHostGetVersion(ApplicationHostRef handle, int instance_id, CGetVersionCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetVersion(base::BindOnce(&GetVersionCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostGetHostCommandLine(ApplicationHostRef handle, int instance_id, CGetHostCommandLineCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetHostCommandLine(base::BindOnce(&GetHostCommandLineCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostGetHistograms(ApplicationHostRef handle, int instance_id, const char* /* optional */ query, CGetHistogramsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetHistograms(query ? std::string(query) : std::string(), base::BindOnce(&GetHistogramsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostGetHistogram(ApplicationHostRef handle, int instance_id, const char* name, CGetHistogramCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetHistogram(std::string(name), base::BindOnce(&GetHistogramCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostGetWindowBounds(ApplicationHostRef handle, int instance_id, int32_t window_id, CGetWindowBoundsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetWindowBounds(window_id, base::BindOnce(&GetWindowBoundsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostGetWindowForTarget(ApplicationHostRef handle, int instance_id, const char* target_id, CGetWindowForTargetCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->host()->GetWindowForTarget(std::string(target_id), base::BindOnce(&GetWindowForTargetCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHostSetWindowBounds(ApplicationHostRef handle, int instance_id, int32_t window_id, BoundsPtrRef bounds) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::BoundsPtr* ptr = reinterpret_cast<automation::BoundsPtr*>(bounds);
  // WARNING: the caller must know the reference is no good after that
  driver->host()->SetWindowBounds(window_id, std::move(*ptr));
}

// Overlay
void _ApplicationHostOverlayDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->Disable();
}

void _ApplicationHostOverlayEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->Enable();
}

void _ApplicationHostOverlayHideHighlight(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->HideHighlight();
}

void _ApplicationHostOverlayHighlightFrame(ApplicationHostRef handle, int instance_id, const char* frame_id, RGBAPtrRef content_color, RGBAPtrRef content_outline_color) {
  automation::RGBAPtr* content_ptr = reinterpret_cast<automation::RGBAPtr*>(content_color);
  automation::RGBAPtr* content_outline_ptr = reinterpret_cast<automation::RGBAPtr*>(content_outline_color);
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->HighlightFrame(std::string(frame_id), std::move(*content_ptr), std::move(*content_outline_ptr));
}

void _ApplicationHostOverlayHighlightNode(ApplicationHostRef handle, int instance_id, HighlightConfigPtrRef highlight_config, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id) {
  automation::HighlightConfigPtr* ptr = reinterpret_cast<automation::HighlightConfigPtr*>(highlight_config);
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->HighlightNode(std::move(*ptr), node_id, backend_node_id, std::string(object_id));
}

void _ApplicationHostOverlayHighlightQuad(ApplicationHostRef handle, int instance_id, const double* quad, int quad_count, RGBAPtrRef color, RGBAPtrRef outline_color) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::RGBAPtr* color_ptr = reinterpret_cast<automation::RGBAPtr*>(color);
  automation::RGBAPtr* outline_color_ptr = reinterpret_cast<automation::RGBAPtr*>(outline_color);  
  std::vector<double> quad_vec;
  for(int i = 0; i < quad_count; ++i) {
    quad_vec.push_back(quad[i]);
  }
  driver->overlay()->HighlightQuad(quad_vec, std::move(*color_ptr), std::move(*outline_color_ptr));
}

void _ApplicationHostOverlayHighlightRect(ApplicationHostRef handle, 
  int instance_id, 
  int32_t x, 
  int32_t y, 
  int32_t width, 
  int32_t height, 
  int color_r,
  int color_g,
  int color_b,
  float color_a,
  int outline_r,
  int outline_g,
  int outline_b,
  float outline_a) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::RGBAPtr color = automation::RGBA::New(color_r, color_g, color_b, color_a);
  automation::RGBAPtr outline_color = automation::RGBA::New(outline_r, outline_g, outline_b, outline_a);
  driver->overlay()->HighlightRect(x, y, width, height, std::move(color), std::move(outline_color));
}

void _ApplicationHostOverlaySetInspectMode(ApplicationHostRef handle, int instance_id, InspectModeEnum mode, HighlightConfigPtrRef highlight_config) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::HighlightConfigPtr* ptr = reinterpret_cast<automation::HighlightConfigPtr*>(highlight_config);
  driver->overlay()->SetInspectMode(static_cast<automation::InspectMode>(mode), std::move(*ptr));
}

void _ApplicationHostOverlaySetPausedInDebuggerMessage(ApplicationHostRef handle, int instance_id, const char* /* optional */ message) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetPausedInDebuggerMessage(std::string(message));
}

void _ApplicationHostOverlaySetShowDebugBorders(ApplicationHostRef handle, int instance_id, int /* bool */ show) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetShowDebugBorders(show != 0);
}

void _ApplicationHostOverlaySetShowFPSCounter(ApplicationHostRef handle, int instance_id, int /* bool */ show) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetShowFPSCounter(show != 0);
}

void _ApplicationHostOverlaySetShowPaintRects(ApplicationHostRef handle, int instance_id, int /* bool */ result) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetShowPaintRects(result != 0);
}

void _ApplicationHostOverlaySetShowScrollBottleneckRects(ApplicationHostRef handle, int instance_id, int /* bool */ show) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetShowScrollBottleneckRects(show != 0);
}

void _ApplicationHostOverlaySetShowViewportSizeOnResize(ApplicationHostRef handle, int instance_id, int /* bool */ show) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetShowViewportSizeOnResize(show != 0);
}

void _ApplicationHostOverlaySetSuspended(ApplicationHostRef handle, int instance_id, int /* bool */ suspended) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->overlay()->SetSuspended(suspended != 0);
}

// Page
void _ApplicationHostPageEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->Enable();
}

void _ApplicationHostPageDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->Disable();
}

void _ApplicationHostPageAddScriptToEvaluateOnNewDocument(ApplicationHostRef handle, int instance_id, const char* source, CAddScriptToEvaluateOnNewDocumentCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->AddScriptToEvaluateOnNewDocument(std::string(source), base::BindOnce(&AddScriptToEvaluateOnNewDocumentCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageRemoveScriptToEvaluateOnNewDocument(ApplicationHostRef handle, int instance_id, const char* identifier) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->RemoveScriptToEvaluateOnNewDocument(std::string(identifier));
}

void _ApplicationHostPageSetAutoAttachToCreatedPages(ApplicationHostRef handle, int instance_id, int /* bool */ auto_attach) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetAutoAttachToCreatedPages(auto_attach != 0);
}

void _ApplicationHostPageSetLifecycleEventsEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetLifecycleEventsEnabled(enabled != 0);
}

void _ApplicationHostPageReload(ApplicationHostRef handle, int instance_id, int /* bool */ ignore_cache, const char* script_to_evaluate_on_load) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->Reload(ignore_cache != 0, std::string(script_to_evaluate_on_load));
}

void _ApplicationHostPageSetAdBlockingEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetAdBlockingEnabled(enabled != 0);
}

void _ApplicationHostPageNavigate(ApplicationHostRef handle, int instance_id, const char* url, const char* referrer, TransitionTypeEnum transition_type, CNavigateCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->Navigate(
    std::string(url), 
    std::string(referrer), 
    static_cast<automation::TransitionType>(transition_type),
    base::BindOnce(&NavigateCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageStopLoading(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->StopLoading();
}

void _ApplicationHostPageGetNavigationHistory(ApplicationHostRef handle, int instance_id, CGetNavigationHistoryCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetNavigationHistory(base::BindOnce(&GetNavigationHistoryCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageNavigateToHistoryEntry(ApplicationHostRef handle, int instance_id, int32_t entry_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->NavigateToHistoryEntry(entry_id);
}

void _ApplicationHostPageGetCookies(ApplicationHostRef handle, int instance_id, CGetCookiesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetCookies(base::BindOnce(&GetCookiesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageDeleteCookie(ApplicationHostRef handle, int instance_id, const char* cookie_name, const char* url) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->DeleteCookie(std::string(cookie_name), std::string(url));
}

void _ApplicationHostPageGetResourceTree(ApplicationHostRef handle, int instance_id, CGetResourceTreeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetResourceTree(base::BindOnce(&GetResourceTreeCb, base::Unretained(callback), base::Unretained(state)));
}
 
void _ApplicationHostPageGetFrameTree(ApplicationHostRef handle, int instance_id, CGetFrameTreeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetFrameTree(base::BindOnce(&GetFrameTreeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageGetResourceContent(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* url, CGetResourceContentCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetResourceContent(std::string(frame_id), std::string(url), base::BindOnce(&GetResourceContentCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageSearchInResource(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* url, const char* query, int /* bool */ case_sensitive, int /* bool */ is_regex, CSearchInResourceCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SearchInResource(
    std::string(frame_id), 
    std::string(url), 
    std::string(query), 
    case_sensitive != 0, 
    is_regex != 0,
    base::BindOnce(&SearchInResourceCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageSetDocumentContent(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* html) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetDocumentContent(std::string(frame_id), std::string(html));
}

void _ApplicationHostPageSetDeviceMetricsOverride(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height, int32_t device_scale_factor, int /* bool */ mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, int /* bool */ dont_set_visible_size, ScreenOrientationPtrRef screen_orientation, ViewportPtrRef viewport) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::ScreenOrientationPtr* screen_orientation_ptr = reinterpret_cast<automation::ScreenOrientationPtr*>(screen_orientation);
  automation::ViewportPtr* viewport_ptr = reinterpret_cast<automation::ViewportPtr*>(viewport);
  driver->pages()->SetDeviceMetricsOverride(
    width,
    height,
    device_scale_factor, 
    mobile != 0, 
    scale,
    screen_width,
    screen_height,
    position_x,
    position_y, 
    dont_set_visible_size != 0,
    std::move(*screen_orientation_ptr),
    std::move(*viewport_ptr));
}

void _ApplicationHostPageClearDeviceMetricsOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->ClearDeviceMetricsOverride();
}

void _ApplicationHostPageSetGeolocationOverride(ApplicationHostRef handle, int instance_id, int32_t latitude, int32_t longitude, int32_t accuracy) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetGeolocationOverride(latitude, longitude, accuracy);
}

void _ApplicationHostPageClearGeolocationOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->ClearGeolocationOverride();
}

void _ApplicationHostPageSetDeviceOrientationOverride(ApplicationHostRef handle, int instance_id, int32_t alpha, int32_t beta, int32_t gamma) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetDeviceOrientationOverride(alpha, beta, gamma);
}

void _ApplicationHostPageClearDeviceOrientationOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->ClearDeviceOrientationOverride();
}

void _ApplicationHostPageSetTouchEmulationEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, const char* configuration) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetTouchEmulationEnabled(enabled != 0 , std::string(configuration));
}

void _ApplicationHostPageCaptureScreenshot(ApplicationHostRef handle, int instance_id, FrameFormatEnum format, int32_t quality, ViewportPtrRef clip, int /* bool */ from_surface, CCaptureScreenshotCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::ViewportPtr* clip_ptr = reinterpret_cast<automation::ViewportPtr*>(clip);
  driver->pages()->CaptureScreenshot(
    static_cast<automation::FrameFormat>(format), 
    quality, 
    std::move(*clip_ptr), 
    from_surface != 0, 
    base::BindOnce(&CaptureScreenshotCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPagePrintToPDF(ApplicationHostRef handle, int instance_id, int /* bool */ landscape, int /* bool */ display_header_footer, int /* bool */ print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const char* /* optional */ page_ranges, int /* bool */ ignore_invalid_page_ranges, CPrintToPDFCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->PrintToPDF(
    landscape != 0, 
    display_header_footer != 0, 
    print_background != 0, 
    scale, 
    paper_width, 
    paper_height, 
    margin_top, 
    margin_bottom, 
    margin_left, 
    margin_right, 
    page_ranges, 
    ignore_invalid_page_ranges != 0,
    base::BindOnce(&PrintToPDFCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageStartScreencast(ApplicationHostRef handle, int instance_id, FrameFormatEnum format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->StartScreencast(static_cast<automation::FrameFormat>(format), quality, max_width, max_height, every_nth_frame);
}

void _ApplicationHostPageStopScreencast(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->StopScreencast();
}

void _ApplicationHostPageSetBypassCSP(ApplicationHostRef handle, int instance_id, int /* bool */ enable) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetBypassCSP(enable != 0);
}

void _ApplicationHostPageScreencastFrameAck(ApplicationHostRef handle, int instance_id, int32_t session_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->ScreencastFrameAck(session_id);
}

void _ApplicationHostPageHandleJavaScriptDialog(ApplicationHostRef handle, int instance_id, int /* bool */ accept, const char* prompt_text) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->HandleJavaScriptDialog(accept != 0, std::string(prompt_text));
}

void _ApplicationHostPageGetAppManifest(ApplicationHostRef handle, int instance_id, CGetAppManifestCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetAppManifest(base::BindOnce(&GetAppManifestCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageRequestAppBanner(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->RequestAppBanner();
}

void _ApplicationHostPageGetLayoutMetrics(ApplicationHostRef handle, int instance_id, CGetLayoutMetricsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->GetLayoutMetrics(base::BindOnce(&GetLayoutMetricsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageCreateIsolatedWorld(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* /* optional */ world_name, int /* bool */ grant_universal_access, CCreateIsolatedWorldCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->CreateIsolatedWorld(
    std::string(frame_id), 
    std::string(world_name), 
    grant_universal_access != 0,
    base::BindOnce(&CreateIsolatedWorldCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostPageBringToFront(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->BringToFront();
}

void _ApplicationHostPageSetDownloadBehavior(ApplicationHostRef handle, int instance_id, const char* behavior, const char* /* optional */ download_path) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->SetDownloadBehavior(std::string(behavior), std::string(download_path));
}

void _ApplicationHostPageClose(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->pages()->Close();
}

// Worker
void _ApplicationHostWorkerDeliverPushMessage(ApplicationHostRef handle, int instance_id, const char* origin, const char* registration_id, const char* data) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->DeliverPushMessage(origin, registration_id, data);
}

void _ApplicationHostWorkerDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->Disable();
}

void _ApplicationHostWorkerDispatchSyncEvent(ApplicationHostRef handle, int instance_id, const char* origin, const char* registration_id, const char* tag, int /* bool */ last_chance) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->DispatchSyncEvent(origin, registration_id, tag, last_chance != 0);
}

void _ApplicationHostWorkerEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->Enable();
}

void _ApplicationHostWorkerInspectWorker(ApplicationHostRef handle, int instance_id, const char* version_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->InspectWorker(version_id);
}

void _ApplicationHostWorkerSetForceUpdateOnPageLoad(ApplicationHostRef handle, int instance_id, int /* bool */ force_update_on_pageload) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->SetForceUpdateOnPageLoad(force_update_on_pageload != 0);
}

void _ApplicationHostWorkerSkipWaiting(ApplicationHostRef handle, int instance_id, const char* scope_url) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->SkipWaiting(scope_url);
}

void _ApplicationHostWorkerStartWorker(ApplicationHostRef handle, int instance_id, const char* scope_url) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->StartWorker(scope_url);
}

void _ApplicationHostWorkerStopAllWorkers(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->StopAllWorkers();
}

void _ApplicationHostWorkerStopWorker(ApplicationHostRef handle, int instance_id, const char* version_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->StopWorker(version_id);
}

void _ApplicationHostWorkerUnregister(ApplicationHostRef handle, int instance_id, const char* scope_url) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->Unregister(scope_url);
}

void _ApplicationHostWorkerUpdateRegistration(ApplicationHostRef handle, int instance_id, const char* scope_url) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->UpdateRegistration(scope_url);
}

void _ApplicationHostWorkerSendMessageToTarget(ApplicationHostRef handle, int instance_id, const char* message, const char* /* optional */ session_id, const char* /* optional */ target_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->worker()->SendMessageToTarget(
    message, 
    session_id, 
    target_id);
}
// Storage

void _ApplicationHostStorageClearDataForOrigin(ApplicationHostRef handle, int instance_id, const char* origin, StorageTypeEnum* storage_types, int storage_types_count) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<automation::StorageType> types;
  for (int i = 0; i < storage_types_count; i++) {
    types.push_back(static_cast<automation::StorageType>(storage_types[i]));
  }
  driver->storage()->ClearDataForOrigin(
    origin,
    types);
}

void _ApplicationHostStorageGetUsageAndQuota(ApplicationHostRef handle, int instance_id, const char* origin, int64_t usage, int64_t quota, UsageForTypePtrRef* usage_breakdown, int usage_breakdown_count) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<automation::UsageForTypePtr> usages;
  for (int i = 0; i < usage_breakdown_count; i++) {
    automation::UsageForTypePtr* usage_ptr = reinterpret_cast<automation::UsageForTypePtr*>(usage_breakdown[i]);
    usages.push_back(std::move(*usage_ptr));
  }
  driver->storage()->GetUsageAndQuota(origin, usage, quota, std::move(usages));
}

void _ApplicationHostStorageTrackCacheStorageForOrigin(ApplicationHostRef handle, int instance_id, const char* origin) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->storage()->TrackCacheStorageForOrigin(origin);
}

void _ApplicationHostStorageTrackIndexedDBForOrigin(ApplicationHostRef handle, int instance_id, const char* origin) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->storage()->TrackIndexedDBForOrigin(origin);
}

void _ApplicationHostStorageUntrackCacheStorageForOrigin(ApplicationHostRef handle, int instance_id, const char* origin) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->storage()->UntrackCacheStorageForOrigin(origin);
}

void _ApplicationHostStorageUntrackIndexedDBForOrigin(ApplicationHostRef handle, int instance_id, const char* origin) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->storage()->UntrackIndexedDBForOrigin(origin);
}

// Tethering

void _ApplicationHostTetheringBind(ApplicationHostRef handle, int instance_id, int32_t port) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->tethering()->Bind(port);
}

void _ApplicationHostTetheringUnbind(ApplicationHostRef handle, int instance_id, int32_t port) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->tethering()->Unbind(port);
}

// Network
void _ApplicationHostNetworkCanClearBrowserCache(ApplicationHostRef handle, int instance_id, CCanClearBrowserCacheCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->CanClearBrowserCache(
    base::BindOnce(&CanClearBrowserCacheCb, base::Unretained(callback), base::Unretained(state)));
    // htoexorabalayqciystalgaaonosvlartytcekspfyomemanarelacedatononaoyleyotma
}

void _ApplicationHostNetworkCanClearBrowserCookies(ApplicationHostRef handle, int instance_id, CCanClearBrowserCookiesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->CanClearBrowserCookies(
    base::BindOnce(&CanClearBrowserCookiesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkCanEmulateNetworkConditions(ApplicationHostRef handle, int instance_id, CCanEmulateNetworkConditionsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->CanEmulateNetworkConditions(
    base::BindOnce(&CanEmulateNetworkConditionsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkClearBrowserCache(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->ClearBrowserCache();
}

void _ApplicationHostNetworkClearBrowserCookies(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->ClearBrowserCookies();
}

void _ApplicationHostNetworkContinueInterceptedRequest(ApplicationHostRef handle, int instance_id, const char* interception_id, ErrorReasonEnum error_reason, const char* /* optional */ raw_response, const char* /* optional */ url, const char* /* optional */ method, const char* /* optional */ post_data, /* optional */ const char** header_keys, int header_keys_count, /* optional */ const char** header_values, int header_values_count, AuthChallengeResponsePtrRef auth_challenge_response) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::AuthChallengeResponsePtr* challenge = reinterpret_cast<automation::AuthChallengeResponsePtr*>(auth_challenge_response);
  base::flat_map<std::string, std::string> headers;
  
  for (int i = 0; i < header_keys_count; i++) {
    headers.emplace(std::make_pair(std::string(header_keys[i]), std::string(header_values[i])));
  }

  driver->network()->ContinueInterceptedRequest(
    std::string(interception_id), 
    static_cast<automation::ErrorReason>(error_reason),
    raw_response,
    url,
    method,
    post_data,
    std::move(headers),
    std::move(*challenge));
}

void _ApplicationHostNetworkDeleteCookies(ApplicationHostRef handle, int instance_id, const char* name, const char* /* optional */ url, const char* /* optional */ domain, const char* /* optional */ path) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->DeleteCookies(
    name, 
    url, 
    domain, 
    path);
}

void _ApplicationHostNetworkDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->Disable();
}

void _ApplicationHostNetworkEmulateNetworkConditions(ApplicationHostRef handle, int instance_id, int /* bool */ offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, ConnectionTypeEnum connection_type) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->EmulateNetworkConditions(
    offline, 
    latency, 
    download_throughput, 
    upload_throughput, 
    static_cast<automation::ConnectionType>(connection_type));
}

void _ApplicationHostNetworkEnable(ApplicationHostRef handle, int instance_id, int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->Enable(max_total_buffer_size, max_resource_buffer_size, max_post_data_size);
}

void _ApplicationHostNetworkGetAllCookies(ApplicationHostRef handle, int instance_id, CGetAllCookiesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->GetAllCookies(
    base::BindOnce(&GetAllCookiesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkGetCertificate(ApplicationHostRef handle, int instance_id, const char* origin, CGetCertificateCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->GetCertificate(origin, base::BindOnce(&GetCertificateCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkGetCookies(ApplicationHostRef handle, int instance_id, /* optional */ const char** urls, int urls_count, CGetCookiesCallback callback, void* state) {
  std::vector<std::string> url_vec;
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  if (urls_count > 0) {
    for (int i = 0; i < urls_count; i++) {
      url_vec.push_back(urls[i]);
    }
    driver->network()->GetCookies(
      std::move(url_vec),
      base::BindOnce(&GetCookiesCb, base::Unretained(callback), base::Unretained(state)));  
    return;
  } 
  driver->network()->GetCookies(std::move(url_vec), base::BindOnce(&GetCookiesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkGetResponseBody(ApplicationHostRef handle, int instance_id, const char* request_id, CGetResponseBodyCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->GetResponseBody(
    request_id,
    base::BindOnce(&GetResponseBodyCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkGetRequestPostData(ApplicationHostRef handle, int instance_id, const char* request_id, CGetRequestPostDataCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->GetRequestPostData(
    request_id,
    base::BindOnce(&GetRequestPostDataCb, 
                    base::Unretained(callback),
                    base::Unretained(state)));
}

void _ApplicationHostNetworkGetResponseBodyForInterception(ApplicationHostRef handle, int instance_id, const char* interception_id, CGetResponseBodyForInterceptionCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->GetResponseBodyForInterception(
    interception_id,
    base::BindOnce(&GetResponseBodyForInterceptionCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkTakeResponseBodyForInterceptionAsStream(ApplicationHostRef handle, int instance_id, const char* interception_id, CTakeResponseBodyForInterceptionAsStreamCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->TakeResponseBodyForInterceptionAsStream(
    interception_id, 
    base::BindOnce(&TakeResponseBodyForInterceptionAsStreamCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkReplayXHR(ApplicationHostRef handle, int instance_id, const char* request_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->ReplayXHR(request_id);
}

void _ApplicationHostNetworkSearchInResponseBody(ApplicationHostRef handle, int instance_id, const char* request_id, const char* query, int /* bool */ case_sensitive, int /* bool */ is_regex, CSearchInResponseBodyCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SearchInResponseBody(
    request_id,
    query, 
    case_sensitive != 0, 
    is_regex != 0,
    base::BindOnce(&SearchInResponseBodyCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkSetBlockedURLs(ApplicationHostRef handle, int instance_id, const char** urls, int urls_count) {
  std::vector<std::string> url_vec;
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  for (int i = 0; i < urls_count; i++) {
    url_vec.push_back(urls[i]);
  }
  driver->network()->SetBlockedURLs(std::move(url_vec));
}

void _ApplicationHostNetworkSetBypassServiceWorker(ApplicationHostRef handle, int instance_id, int /* bool */ bypass) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SetBypassServiceWorker(bypass != 0);
}

void _ApplicationHostNetworkSetCacheDisabled(ApplicationHostRef handle, int instance_id, int /* bool */ cache_disabled) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SetCacheDisabled(cache_disabled != 0);
}

void _ApplicationHostNetworkSetCookie(ApplicationHostRef handle, int instance_id, const char* name, const char* value, const char* /* optional */ url, const char* /* optional */ domain, const char* /* optional */ path, int /* bool */ secure, int /* bool */ http_only, CookieSameSiteEnum same_site, int64_t expires, CSetCookieCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SetCookie(
    name, value, url, domain, path, secure != 0, http_only != 0, static_cast<automation::CookieSameSite>(same_site), expires,
    base::BindOnce(&SetCookieCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostNetworkSetCookies(ApplicationHostRef handle, int instance_id, CookieParamPtrRef* cookies, int cookies_count) {
  std::vector<automation::CookieParamPtr> cookies_vec; 
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  for (int i = 0; i < cookies_count; i++) {
    automation::CookieParamPtr* cookie = reinterpret_cast<automation::CookieParamPtr*>(cookies[i]);
    cookies_vec.push_back(std::move(*cookie));
  }
  driver->network()->SetCookies(std::move(cookies_vec));
}

void _ApplicationHostNetworkSetDataSizeLimits(ApplicationHostRef handle, int instance_id, int32_t max_total_size, int32_t max_resource_size) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SetDataSizeLimits(max_total_size, max_resource_size);
}

void _ApplicationHostNetworkSetExtraHTTPHeaders(ApplicationHostRef handle, int instance_id, const char** headers_keys, int header_keys_count, const char** headers_values, int header_values_count) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  base::flat_map<std::string, std::string> headers;  
  for (int i = 0; i < header_keys_count; i++) {
    headers.emplace(std::make_pair(std::string(headers_keys[i]), std::string(headers_values[i])));
  }
  driver->network()->SetExtraHTTPHeaders(std::move(headers));
}

void _ApplicationHostNetworkSetRequestInterception(ApplicationHostRef handle, int instance_id, RequestPatternPtrRef* patterns, int patterns_count) {
  std::vector<automation::RequestPatternPtr> patterns_vec; 
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  for (int i = 0; i < patterns_count; i++) {
    automation::RequestPatternPtr* pattern = reinterpret_cast<automation::RequestPatternPtr*>(patterns[i]);
    patterns_vec.push_back(std::move(*pattern));
  }
  driver->network()->SetRequestInterception(std::move(patterns_vec));
}

void _ApplicationHostNetworkSetUserAgentOverride(ApplicationHostRef handle, int instance_id, const char* user_agent) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->network()->SetUserAgentOverride(user_agent);
}


void _ApplicationHostLayerTreeCompositingReasons(ApplicationHostRef handle, int instance_id, const char* layer_id, CCompositingReasonsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->CompositingReasons(
    layer_id,
    base::BindOnce(&CompositingReasonsCb, base::Unretained(callback), base::Unretained(state)));
} 

void _ApplicationHostLayerTreeDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->Disable();
}

void _ApplicationHostLayerTreeEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->Enable();
}

void _ApplicationHostLayerTreeLoadSnapshot(ApplicationHostRef handle, int instance_id, PictureTilePtrRef* tiles, int tiles_count, CLoadSnapshotCallback callback, void* state) {
  std::vector<automation::PictureTilePtr> tiles_vec;
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  for (int i = 0; i < tiles_count; i++) {
    automation::PictureTilePtr* ptr = reinterpret_cast<automation::PictureTilePtr*>(tiles[i]);
    tiles_vec.push_back(std::move(*ptr));
  }
  driver->layer_tree()->LoadSnapshot(std::move(tiles_vec),
    base::BindOnce(&LoadSnapshotCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostLayerTreeMakeSnapshot(ApplicationHostRef handle, int instance_id, const char* layer_id, CMakeSnapshotCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->MakeSnapshot(
    layer_id, 
    base::BindOnce(&MakeSnapshotCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostLayerTreeProfileSnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id, int32_t min_repeat_count, int32_t min_duration, int clip_rect_x, int clip_rect_y, int clip_rect_w, int clip_rect_h, CProfileSnapshotCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->ProfileSnapshot(
    snapshot_id, 
    min_repeat_count,
    min_duration, 
    gfx::Rect(clip_rect_x, clip_rect_y, clip_rect_w, clip_rect_h),
    base::BindOnce(&ProfileSnapshotCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostLayerTreeReleaseSnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->ReleaseSnapshot(snapshot_id);
}

void _ApplicationHostLayerTreeReplaySnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, CReplaySnapshotCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->ReplaySnapshot(snapshot_id, from_step, to_step, scale,
    base::BindOnce(&ReplaySnapshotCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostLayerTreeSnapshotCommandLog(ApplicationHostRef handle, int instance_id, const char* snapshot_id, CSnapshotCommandLogCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->layer_tree()->SnapshotCommandLog(snapshot_id,
   base::BindOnce(&SnapshotCommandLogCb, base::Unretained(callback), base::Unretained(state)));
}

// Input
void _ApplicationHostInputDispatchKeyEvent(ApplicationHostRef handle, int instance_id, KeyEventTypeEnum type, int32_t modifiers, int64_t timestamp, const char* /* optional */ text, const char* /* optional */ unmodified_text, const char* /* optional */ key_identifier, const char* /* optional */ code, const char* /* optional */ key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, int /* bool */ auto_repeat, int /* bool */ is_keypad, int /* bool */ is_system_key, int32_t location, CDispatchKeyEventCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->DispatchKeyEvent(
    static_cast<automation::KeyEventType>(type),
    modifiers, 
    timestamp, 
    text, 
    unmodified_text, 
    key_identifier, 
    code, 
    key, 
    windows_virtual_key_code, 
    native_virtual_key_code, 
    auto_repeat != 0, 
    is_keypad != 0, 
    is_system_key != 0, 
    location,
    base::BindOnce(&DispatchKeyEventCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputDispatchMouseEvent(ApplicationHostRef handle, int instance_id, MouseEventTypeEnum type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, MouseButtonEnum button, int32_t click_count, int32_t delta_x, int32_t delta_y, CDispatchMouseEventCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->DispatchMouseEvent(
    static_cast<automation::MouseEventType>(type),
    x, 
    y, 
    modifiers, 
    timestamp, 
    static_cast<automation::MouseButton>(button), 
    click_count, 
    delta_x, 
    delta_y, 
    base::BindOnce(&DispatchMouseEventCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputDispatchTouchEvent(ApplicationHostRef handle, int instance_id, TouchEventTypeEnum type, TouchPointPtrRef* touch_points, int touch_points_count, int32_t modifiers, int64_t timestamp, CDispatchTouchEventCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<automation::TouchPointPtr> points;
  for (int i = 0; i < touch_points_count; i++) {
    automation::TouchPointPtr* point = reinterpret_cast<automation::TouchPointPtr*>(touch_points[i]);
    points.push_back(std::move(*point));
  }
  driver->input()->DispatchTouchEvent(
    static_cast<automation::TouchEventType>(type),
    std::move(points), 
    modifiers, 
    timestamp,
    base::BindOnce(&DispatchTouchEventCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputEmulateTouchFromMouseEvent(ApplicationHostRef handle, int instance_id, MouseEventTypeEnum type, int32_t x, int32_t y, MouseButtonEnum button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, CEmulateTouchFromMouseEventCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->EmulateTouchFromMouseEvent(
    static_cast<automation::MouseEventType>(type),
    x, 
    y, 
    static_cast<automation::MouseButton>(button), 
    timestamp, 
    delta_x, 
    delta_y, 
    modifiers,
    click_count,
    base::BindOnce(&EmulateTouchFromMouseEventCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputSetIgnoreInputEvents(ApplicationHostRef handle, int instance_id, int /* bool */ ignore) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->SetIgnoreInputEvents(ignore != 0);
}

void _ApplicationHostInputSynthesizePinchGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, GestureSourceTypeEnum gesture_source_type, CSynthesizePinchGestureCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->SynthesizePinchGesture(
    x, 
    y, 
    scale_factor, 
    relative_speed, 
    static_cast<automation::GestureSourceType>(gesture_source_type), 
    base::BindOnce(&SynthesizePinchGestureCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputSynthesizeScrollGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, int /* bool */ prevent_fling, int32_t speed, GestureSourceTypeEnum gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const char* /* optional */ interaction_marker_name, CSynthesizeScrollGestureCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->SynthesizeScrollGesture(
    x, 
    y, 
    x_distance, 
    y_distance, 
    x_overscroll, 
    y_overscroll, 
    prevent_fling != 0, 
    speed, 
    static_cast<automation::GestureSourceType>(gesture_source_type), 
    repeat_count, 
    repeat_delay_ms, 
    interaction_marker_name,
    base::BindOnce(&SynthesizeScrollGestureCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostInputSynthesizeTapGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t duration, int32_t tap_count, GestureSourceTypeEnum gesture_source_type, CSynthesizeTapGestureCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->input()->SynthesizeTapGesture(
    x, 
    y, 
    duration, 
    tap_count,
    static_cast<automation::GestureSourceType>(gesture_source_type), 
    base::BindOnce(&SynthesizeTapGestureCb, base::Unretained(callback), base::Unretained(state)));
}

// IndexedDB

void _ApplicationHostIndexedDBDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->Disable();
}

void _ApplicationHostIndexedDBEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->Enable();
}

void _ApplicationHostIndexedDBClearObjectStore(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, CClearObjectStoreCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->ClearObjectStore(
    security_origin, 
    database_name, 
    object_store_name,
    base::BindOnce(&ClearObjectStoreCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIndexedDBDeleteDatabase(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, CDeleteDatabaseCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->DeleteDatabase(
    security_origin, 
    database_name, 
    base::BindOnce(&DeleteDatabaseCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIndexedDBDeleteObjectStoreEntries(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, KeyRangePtrRef keyRange, CDeleteObjectStoreEntriesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::KeyRangePtr* range = reinterpret_cast<automation::KeyRangePtr*>(keyRange);
  driver->indexed_db()->DeleteObjectStoreEntries(
    security_origin, 
    database_name, 
    object_store_name,
    std::move(*range),
    base::BindOnce(&DeleteObjectStoreEntriesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIndexedDBRequestData(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, const char* index_name, int32_t skip_count, int32_t page_size, KeyRangePtrRef key_range, CRequestDataCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::KeyRangePtr* range = reinterpret_cast<automation::KeyRangePtr*>(key_range);
  driver->indexed_db()->RequestData(
    security_origin, 
    database_name, 
    object_store_name, 
    index_name, 
    skip_count, 
    page_size, 
    std::move(*range), 
    base::BindOnce(&RequestDataCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIndexedDBRequestDatabase(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, CRequestDatabaseCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->RequestDatabase(
    security_origin, 
    database_name, 
    base::BindOnce(&RequestDatabaseCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIndexedDBRequestDatabaseNames(ApplicationHostRef handle, int instance_id, const char* security_origin, CRequestDatabaseNamesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->indexed_db()->RequestDatabaseNames(
    security_origin, 
    base::BindOnce(&RequestDatabaseNamesCb, base::Unretained(callback), base::Unretained(state)));
}

// IO
void _ApplicationHostIOClose(ApplicationHostRef handle, int instance_id, const char* handl) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->io()->Close(handl);
}

void _ApplicationHostIORead(ApplicationHostRef handle, int instance_id, const char* handl, int32_t offset, int32_t size, CReadCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->io()->Read(
    handl, 
    offset,
    size, 
    base::BindOnce(&ReadCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostIOResolveBlob(ApplicationHostRef handle, int instance_id, const char* object_id, CResolveBlobCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->io()->ResolveBlob(
    object_id,
    base::BindOnce(&ResolveBlobCb, base::Unretained(callback), base::Unretained(state)));
}

// Headless

void _ApplicationHostHeadlessBeginFrame(ApplicationHostRef handle, int instance_id, int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, int /* bool */ no_display_updates, ScreenshotParamsPtrRef screenshot, CBeginFrameCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::ScreenshotParamsPtr* screenshot_ptr = reinterpret_cast<automation::ScreenshotParamsPtr*>(screenshot);
  driver->headless()->BeginFrame(
    frame_time, 
    frame_time_ticks, 
    deadline, 
    deadline_ticks, 
    interval, 
    no_display_updates != 0, 
    std::move(*screenshot_ptr), 
    base::BindOnce(&BeginFrameCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostHeadlessEnterDeterministicMode(ApplicationHostRef handle, int instance_id, int32_t initial_date) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->headless()->EnterDeterministicMode(initial_date);
}

void _ApplicationHostHeadlessDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->headless()->Disable();
}

void _ApplicationHostHeadlessEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->headless()->Enable();
}

// DOMStorage
void _ApplicationHostDOMStorageClear(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storage_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::StorageIdPtr* storage_ptr = reinterpret_cast<automation::StorageIdPtr*>(storage_id);
  driver->dom_storage()->Clear(std::move(*storage_ptr));
}

void _ApplicationHostDOMStorageDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom_storage()->Disable();
}

void _ApplicationHostDOMStorageEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom_storage()->Enable();
}

void _ApplicationHostDOMStorageGetDOMStorageItems(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storageId, CGetDOMStorageItemsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::StorageIdPtr* storage_ptr = reinterpret_cast<automation::StorageIdPtr*>(storageId);
  driver->dom_storage()->GetDOMStorageItems(
    std::move(*storage_ptr),
    base::BindOnce(&GetDOMStorageItemsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMStorageRemoveDOMStorageItem(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storage_id, const char* key) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::StorageIdPtr* storage_ptr = reinterpret_cast<automation::StorageIdPtr*>(storage_id);
  driver->dom_storage()->RemoveDOMStorageItem(
    std::move(*storage_ptr),
    key);
}

void _ApplicationHostDOMStorageSetDOMStorageItem(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storageId, const char* key, const char* value) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::StorageIdPtr* storage_ptr = reinterpret_cast<automation::StorageIdPtr*>(storageId);
  driver->dom_storage()->SetDOMStorageItem(
    std::move(*storage_ptr),
    key,
    value);
}

// Database
void _ApplicationHostDatabaseDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->database()->Disable();
}

void _ApplicationHostDatabaseEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->database()->Enable();
}

void _ApplicationHostDatabaseExecuteSQL(ApplicationHostRef handle, int instance_id, const char* database_id, const char* query, CExecuteSQLCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->database()->ExecuteSQL(
    database_id, 
    query,
    base::BindOnce(&ExecuteSQLCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDatabaseGetDatabaseTableNames(ApplicationHostRef handle, int instance_id, const char* database_id, CGetDatabaseTableNamesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->database()->GetDatabaseTableNames(
    database_id,
    base::BindOnce(&GetDatabaseTableNamesCb, base::Unretained(callback), base::Unretained(state)));
}

// DeviceOrientation
void _ApplicationHostDeviceOrientationClearDeviceOrientationOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->device_orientation()->ClearDeviceOrientationOverride();
}

void _ApplicationHostDeviceOrientationSetDeviceOrientationOverride(ApplicationHostRef handle, int instance_id, int32_t alpha, int32_t beta, int32_t gamma) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->device_orientation()->SetDeviceOrientationOverride(alpha, beta, gamma);
}

// Emulation
void _ApplicationHostEmulationCanEmulate(ApplicationHostRef handle, int instance_id, CCanEmulateCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->CanEmulate(
    base::BindOnce(&CanEmulateCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostEmulationClearDeviceMetricsOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->ClearDeviceMetricsOverride();
}

void _ApplicationHostEmulationClearGeolocationOverride(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->ClearGeolocationOverride();
}

void _ApplicationHostEmulationResetPageScaleFactor(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->ResetPageScaleFactor();
}

void _ApplicationHostEmulationSetCPUThrottlingRate(ApplicationHostRef handle, int instance_id, int32_t rate) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetCPUThrottlingRate(rate);
}

void _ApplicationHostEmulationSetDefaultBackgroundColorOverride(ApplicationHostRef handle, int instance_id, RGBAPtrRef color) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::RGBAPtr* color_ptr = reinterpret_cast<automation::RGBAPtr*>(color);
  driver->emulation()->SetDefaultBackgroundColorOverride(std::move(*color_ptr));
}

void _ApplicationHostEmulationSetDeviceMetricsOverride(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height, float device_scale_factor, int /* bool */ mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, int /* bool */ dont_set_visible_size, ScreenOrientationPtrRef screen_orientation, ViewportPtrRef viewport) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::ScreenOrientationPtr* screen_orientation_ptr = reinterpret_cast<automation::ScreenOrientationPtr*>(screen_orientation);
  automation::ViewportPtr* viewport_ptr = reinterpret_cast<automation::ViewportPtr*>(viewport);
  driver->emulation()->SetDeviceMetricsOverride(
    width, 
    height, 
    device_scale_factor, 
    mobile != 0, 
    scale, 
    screen_width, 
    screen_height, 
    position_x, 
    position_y, 
    dont_set_visible_size != 0, 
    std::move(*screen_orientation_ptr), 
    std::move(*viewport_ptr));
}

void _ApplicationHostEmulationSetEmitTouchEventsForMouse(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, TouchEventForMouseConfigurationEnum configuration) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetEmitTouchEventsForMouse(
    enabled != 0, 
    static_cast<automation::TouchEventForMouseConfiguration>(configuration));
}

void _ApplicationHostEmulationSetEmulatedMedia(ApplicationHostRef handle, int instance_id, const char* media) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetEmulatedMedia(media);
}

void _ApplicationHostEmulationSetGeolocationOverride(ApplicationHostRef handle, int instance_id, int64_t latitude, int64_t longitude, int64_t accuracy) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetGeolocationOverride(latitude, longitude, accuracy);
}

void _ApplicationHostEmulationSetNavigatorOverrides(ApplicationHostRef handle, int instance_id, const char* platform) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetNavigatorOverrides(platform);
}

void _ApplicationHostEmulationSetPageScaleFactor(ApplicationHostRef handle, int instance_id, float page_scale_factor) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetPageScaleFactor(page_scale_factor);
}

void _ApplicationHostEmulationSetScriptExecutionDisabled(ApplicationHostRef handle, int instance_id, int /* bool */ value) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetScriptExecutionDisabled(value != 0);
}

void _ApplicationHostEmulationSetTouchEmulationEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, int32_t max_touch_points) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetTouchEmulationEnabled(enabled != 0, max_touch_points);
}

void _ApplicationHostEmulationSetVirtualTimePolicy(ApplicationHostRef handle, int instance_id, VirtualTimePolicyEnum policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, int /* bool */ wait_for_navigation, CSetVirtualTimePolicyCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetVirtualTimePolicy(
    static_cast<automation::VirtualTimePolicy>(policy), 
    budget, 
    max_virtual_time_task_starvation_count, 
    wait_for_navigation != 0, 
    base::BindOnce(&SetVirtualTimePolicyCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostEmulationSetVisibleSize(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->emulation()->SetVisibleSize(width, height);
}

// DOMSnapshot
void _ApplicationHostDOMSnapshotGetSnapshot(
    ApplicationHostRef handle,
    int instance_id,
    const char** computed_style_whitelist,
    int computed_style_whitelist_count, 
    int /* bool */ include_event_listeners, 
    int /* bool */ include_paint_order, 
    int /* bool */ include_user_agent_shadow_tree, 
    CGetSnapshotCallback callback, void* state) {
  std::vector<std::string> whitelist;
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  
  for (int i = 0; i < computed_style_whitelist_count; i++) {
    whitelist.push_back(std::string(computed_style_whitelist[i]));
  }
    
  driver->dom_snapshot()->GetSnapshot(
    std::move(whitelist),
    include_event_listeners != 0, 
    include_paint_order != 0, 
    include_user_agent_shadow_tree != 0, 
    base::BindOnce(&GetSnapshotCb, base::Unretained(callback), base::Unretained(state)));
}
// DOM

void _ApplicationHostDOMCollectClassNamesFromSubtree(ApplicationHostRef handle, int instance_id, int32_t node_id, CCollectClassNamesFromSubtreeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->CollectClassNamesFromSubtree(
    node_id,
    base::BindOnce(&CollectClassNamesFromSubtreeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMCopyTo(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, CCopyToCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->CopyTo(
    node_id, 
    target_node_id, 
    anchor_node_id, 
    base::BindOnce(&CopyToCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMDescribeNode(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, int32_t depth, int /* bool */ pierce, CDescribeNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->DescribeNode(
    node_id, 
    backend_node_id, 
    object_id, 
    depth, 
    pierce != 0, 
    base::BindOnce(&DescribeNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->Disable();
}

void _ApplicationHostDOMDiscardSearchResults(ApplicationHostRef handle, int instance_id, const char* search_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->DiscardSearchResults(search_id);
}

void _ApplicationHostDOMEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->Enable();
}

void _ApplicationHostDOMFocus(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->Focus(
    node_id, 
    backend_node_id, 
    object_id);
}

void _ApplicationHostDOMGetAttributes(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetAttributesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetAttributes(node_id, base::BindOnce(&GetAttributesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetBoxModel(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, CGetBoxModelCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetBoxModel(
    node_id, 
    backend_node_id, 
    object_id, 
    base::BindOnce(&GetBoxModelCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetDocument(ApplicationHostRef handle, int instance_id, int32_t depth, int /* bool */ pierce, CGetDocumentCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetDocument(
    depth, 
    pierce != 0, 
    base::BindOnce(&GetDocumentCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetFlattenedDocument(ApplicationHostRef handle, int instance_id, int32_t depth, int /* bool */ pierce, CGetFlattenedDocumentCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetFlattenedDocument(
    depth, 
    pierce != 0, 
    base::BindOnce(&GetFlattenedDocumentCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetNodeForLocation(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int /* bool */ include_user_agent_shadow_dom, CGetNodeForLocationCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetNodeForLocation(
    x, 
    y, 
    include_user_agent_shadow_dom != 0, 
    base::BindOnce(&GetNodeForLocationCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetOuterHTML(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, CGetOuterHTMLCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetOuterHTML(
    node_id, 
    backend_node_id, 
    object_id,
    base::BindOnce(&GetOuterHTMLCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetRelayoutBoundary(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetRelayoutBoundaryCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetRelayoutBoundary(
    node_id,
    base::BindOnce(&GetRelayoutBoundaryCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMGetSearchResults(ApplicationHostRef handle, int instance_id, const char* search_id, int32_t from_index, int32_t to_index, CGetSearchResultsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetSearchResults(
    search_id,
    from_index,
    to_index,    
    base::BindOnce(&GetSearchResultsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMHideHighlight(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->HideHighlight();
}

void _ApplicationHostDOMHighlightNode(ApplicationHostRef handle, int instance_id, HighlightConfigPtrRef highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::HighlightConfigPtr* highlight_ptr = reinterpret_cast<automation::HighlightConfigPtr*>(highlight_config);
  driver->dom()->HighlightNode(
    std::move(*highlight_ptr),
    node_id, 
    backend_node_id, 
    object_id);
}

void _ApplicationHostDOMHighlightRect(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t width, int32_t height, RGBAPtrRef color, RGBAPtrRef outline_color) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::RGBAPtr* color_ptr = reinterpret_cast<automation::RGBAPtr*>(color);
  automation::RGBAPtr* outline_color_ptr = reinterpret_cast<automation::RGBAPtr*>(outline_color);
  driver->dom()->HighlightRect(
    x, 
    y, 
    width, 
    height,
    std::move(*color_ptr),
    std::move(*outline_color_ptr));
}

void _ApplicationHostDOMMarkUndoableState(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->MarkUndoableState();
}

void _ApplicationHostDOMMoveTo(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, CMoveToCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->MoveTo(
    node_id, 
    target_node_id, 
    insert_before_node_id, 
    base::BindOnce(&MoveToCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMPerformSearch(ApplicationHostRef handle, int instance_id, const char* query, int /* bool */ include_user_agent_shadow_dom, CPerformSearchCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->PerformSearch(
    query, 
    include_user_agent_shadow_dom != 0, 
    base::BindOnce(&PerformSearchCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMPushNodeByPathToFrontend(ApplicationHostRef handle, int instance_id, const char* path, CPushNodeByPathToFrontendCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->PushNodeByPathToFrontend(
    path,
    base::BindOnce(&PushNodeByPathToFrontendCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMPushNodesByBackendIdsToFrontend(ApplicationHostRef handle, int instance_id, int32_t* backend_node_ids, int backend_node_ids_count, CPushNodesByBackendIdsToFrontendCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<int32_t> nodes_vec;
  for (int i = 0; i < backend_node_ids_count; ++i) {
    nodes_vec.push_back(backend_node_ids[i]);
  }
  driver->dom()->PushNodesByBackendIdsToFrontend(
    std::move(nodes_vec),
    base::BindOnce(&PushNodesByBackendIdsToFrontendCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMQuerySelector(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* selector, CQuerySelectorCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->QuerySelector(
    node_id, 
    selector,
    base::BindOnce(&QuerySelectorCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMQuerySelectorAll(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* selector, CQuerySelectorAllCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->QuerySelectorAll(
    node_id, 
    selector, 
    base::BindOnce(&QuerySelectorAllCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMRedo(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->Redo();
}

void _ApplicationHostDOMRemoveAttribute(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->RemoveAttribute(node_id, name);
}

void _ApplicationHostDOMRemoveNode(ApplicationHostRef handle, int instance_id, int32_t node_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->RemoveNode(node_id);
}

void _ApplicationHostDOMRequestChildNodes(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t depth, int /* bool */ pierce) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->RequestChildNodes(node_id, depth, pierce != 0);
}

void _ApplicationHostDOMRequestNode(ApplicationHostRef handle, int instance_id, const char* object_id, CRequestNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->RequestNode(
    object_id,
    base::BindOnce(&RequestNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMResolveNode(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* /* optional */ object_group, CResolveNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->ResolveNode(
    node_id, 
    object_group, 
    base::BindOnce(&ResolveNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMSetAttributeValue(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name, const char* value) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetAttributeValue(node_id, name, value);
}

void _ApplicationHostDOMSetAttributesAsText(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* text, const char* /* optional */ name) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetAttributesAsText(
    node_id, 
    text, 
    name);
}

void _ApplicationHostDOMSetFileInputFiles(ApplicationHostRef handle, int instance_id, const char** files, int files_count, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<std::string> files_vec;
  for (int i = 0; i < files_count; ++i) {
    files_vec.push_back(files[i]);
  }
  driver->dom()->SetFileInputFiles(
    std::move(files_vec), 
    node_id, 
    backend_node_id, 
    object_id);
}

void _ApplicationHostDOMSetInspectedNode(ApplicationHostRef handle, int instance_id, int32_t node_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetInspectedNode(node_id);
}

void _ApplicationHostDOMSetNodeName(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name, CSetNodeNameCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetNodeName(node_id, name, base::BindOnce(&SetNodeNameCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostDOMSetNodeValue(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* value) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetNodeValue(node_id, value);
}

void _ApplicationHostDOMSetOuterHTML(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* outer_html) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->SetOuterHTML(node_id, outer_html);
}

void _ApplicationHostDOMUndo(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->Undo();
}

void _ApplicationHostDOMGetFrameOwner(ApplicationHostRef handle, int instance_id, const char* frame_id, CGetFrameOwnerCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->dom()->GetFrameOwner(frame_id, base::BindOnce(&GetFrameOwnerCb, base::Unretained(callback), base::Unretained(state)));
}

// CSS
void _ApplicationHostCSSAddRule(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, const char* rule_text, SourceRangePtrRef location, CAddRuleCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::SourceRangePtr* range_ptr = reinterpret_cast<automation::SourceRangePtr*>(location);
  driver->css()->AddRule(
    style_sheet_id, 
    rule_text, 
    std::move(*range_ptr),
    base::BindOnce(&AddRuleCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSCollectClassNames(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, CCollectClassNamesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->CollectClassNames(
    style_sheet_id,
    base::BindOnce(&CollectClassNamesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSCreateStyleSheet(ApplicationHostRef handle, int instance_id, const char* frame_id, CCreateStyleSheetCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->CreateStyleSheet(
    frame_id,
    base::BindOnce(&CreateStyleSheetCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->Disable();
}

void _ApplicationHostCSSEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->Enable();
}

void _ApplicationHostCSSForcePseudoState(ApplicationHostRef handle, int instance_id, int32_t node_id, const char** forced_pseudo_classes, int forced_pseudo_classes_count) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<std::string> forced_pseudo_classes_vec;
  for (int i = 0; i < forced_pseudo_classes_count; ++i) {
    forced_pseudo_classes_vec.push_back(forced_pseudo_classes[i]);
  }
  driver->css()->ForcePseudoState(
    node_id,
    std::move(forced_pseudo_classes_vec));
}

void _ApplicationHostCSSGetBackgroundColors(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetBackgroundColorsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetBackgroundColors(
    node_id,
    base::BindOnce(&GetBackgroundColorsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetComputedStyleForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetComputedStyleForNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetComputedStyleForNode(
    node_id,
    base::BindOnce(&GetComputedStyleForNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetInlineStylesForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetInlineStylesForNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetInlineStylesForNode(
    node_id, 
    base::BindOnce(&GetInlineStylesForNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetMatchedStylesForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetMatchedStylesForNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetMatchedStylesForNode(
    node_id,
    base::BindOnce(&GetMatchedStylesForNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetMediaQueries(ApplicationHostRef handle, int instance_id, CGetMediaQueriesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetMediaQueries(base::BindOnce(&GetMediaQueriesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetPlatformFontsForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetPlatformFontsForNodeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetPlatformFontsForNode(node_id, base::BindOnce(&GetPlatformFontsForNodeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSGetStyleSheetText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, CGetStyleSheetTextCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->GetStyleSheetText(style_sheet_id, base::BindOnce(&GetStyleSheetTextCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSSetEffectivePropertyValueForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* property_name, const char* value) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->SetEffectivePropertyValueForNode(
    node_id, 
    property_name, 
    value);
}

void _ApplicationHostCSSSetKeyframeKey(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* key_text, CSetKeyframeKeyCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::SourceRangePtr* range_ptr = reinterpret_cast<automation::SourceRangePtr*>(range);
  driver->css()->SetKeyframeKey(
    style_sheet_id,
    std::move(*range_ptr),
    key_text,
    base::BindOnce(&SetKeyframeKeyCb, base::Unretained(callback), base::Unretained(state))
  );
}

void _ApplicationHostCSSSetMediaText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* text, CSetMediaTextCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::SourceRangePtr* range_ptr = reinterpret_cast<automation::SourceRangePtr*>(range);
  driver->css()->SetMediaText(
    style_sheet_id,
    std::move(*range_ptr),
    text,
    base::BindOnce(&SetMediaTextCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSSetRuleSelector(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* selector, CSetRuleSelectorCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  automation::SourceRangePtr* edit_ptr = reinterpret_cast<automation::SourceRangePtr*>(range);
  driver->css()->SetRuleSelector(
    style_sheet_id,
    std::move(*edit_ptr),
    selector,
    base::BindOnce(&SetRuleSelectorCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSSetStyleSheetText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, const char* text, CSetStyleSheetTextCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->SetStyleSheetText(
    style_sheet_id, 
    text, 
    base::BindOnce(&SetStyleSheetTextCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSSetStyleTexts(ApplicationHostRef handle, int instance_id, StyleDeclarationEditPtrRef* edits, int edits_count, CSetStyleTextsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<automation::StyleDeclarationEditPtr> edits_vec;
  for (int i = 0; i < edits_count; i++) {
    automation::StyleDeclarationEditPtr* edit_ptr = reinterpret_cast<automation::StyleDeclarationEditPtr*>(edits[i]);
    edits_vec.push_back(std::move(*edit_ptr));
  }
  driver->css()->SetStyleTexts(
    std::move(edits_vec),
    base::BindOnce(&SetStyleTextsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSStartRuleUsageTracking(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->StartRuleUsageTracking();
}

void _ApplicationHostCSSStopRuleUsageTracking(ApplicationHostRef handle, int instance_id, CStopRuleUsageTrackingCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->StopRuleUsageTracking(
    base::BindOnce(&StopRuleUsageTrackingCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCSSTakeCoverageDelta(ApplicationHostRef handle, int instance_id, CTakeCoverageDeltaCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->css()->TakeCoverageDelta(base::BindOnce(&TakeCoverageDeltaCb, base::Unretained(callback), base::Unretained(state)));
}

// CacheStorage
void _ApplicationHostCacheStorageHasCache(ApplicationHostRef handle, int instance_id, const char* cache_id, CHasCacheCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->HasCache(cache_id, base::BindOnce(&HasCacheCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageOpenCache(ApplicationHostRef handle, int instance_id, const char* cache_id, COpenCacheCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->OpenCache(cache_id, base::BindOnce(&OpenCacheCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageDeleteCache(ApplicationHostRef handle, int instance_id, const char* cache_id, CDeleteCacheCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->DeleteCache(cache_id, base::BindOnce(&DeleteCacheCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStoragePutEntryData(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, const void* data, int size, CPutEntryCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  uint8_t* data_ptr = reinterpret_cast<uint8_t*>(const_cast<void *>(data));
  blink::mojom::blink::BytesProviderPtrInfo bytes_provider_info;
  blink::BlobBytesProvider::CreateAndBind(mojo::MakeRequest(&bytes_provider_info));
  blink::mojom::DataElementBytesPtr bytes_element = 
    blink::mojom::DataElementBytes::New(size, base::nullopt, 
      blink::mojom::BytesProviderPtrInfo(bytes_provider_info.PassHandle(), blink::mojom::BytesProvider::Version_));
  if (data_ptr != nullptr) {
    bytes_element->embedded_data = std::vector<uint8_t>(data_ptr, data_ptr + size);
  }
  blink::mojom::DataElementPtr data_element = blink::mojom::DataElement::NewBytes(std::move(bytes_element));
  //DLOG(INFO) << "_ApplicationHostCacheStoragePutEntryData: '" << std::string(reinterpret_cast<const char*>(&data_vec[0]), data_vec.size()) << "' ";
  driver->cache_storage()->PutEntry(
    cache_id, 
    request,
    std::move(data_element),
    base::BindOnce(&PutEntryCb, base::Unretained(callback), base::Unretained(state)));
  //return result;
}

void _ApplicationHostCacheStoragePutEntryBlob(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, BlobDataRef blob, CPutEntryCallback callback, void* state) {
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  BlobDataState* blob_data = reinterpret_cast<BlobDataState*>(blob);
  std::unique_ptr<blink::BlobData> blob_data_ptr(blob_data->ptr.release());
  uint64_t blob_size = blob_data_ptr->length();
  std::string content_type(blob_data_ptr->ContentType().Utf8().data());
  std::string uuid = base::GenerateGUID();
  scoped_refptr<blink::BlobDataHandle> blob_handle = blink::BlobDataHandle::Create(std::move(blob_data_ptr), blob_size);
  blob_data->handle = blob_handle;
  blink::mojom::SerializedBlobPtr serialized_blob = blink::mojom::SerializedBlob::New(
    uuid,
    content_type, 
    blob_size,
    blink::mojom::BlobPtrInfo(
        blob_data->handle->CloneBlobPtr().PassInterface().PassHandle(),
        blink::mojom::Blob::Version_));

  driver->cache_storage()->PutEntryBlob(
    cache_id, 
    request,
    std::move(serialized_blob),
    base::BindOnce(&PutEntryCb, base::Unretained(callback), base::Unretained(state)));
}

void BlobBytesProviderAppendData(BlobBytesProviderRef handle, const void* data, int size) {
  blink::BlobBytesProvider* provider = reinterpret_cast<blink::BlobBytesProvider*>(handle);
  base::span<const char> data_vec(reinterpret_cast<const char*>(data), size);
  provider->AppendData(std::move(data_vec));
}

void _ApplicationHostCacheStoragePutEntryFile(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, const char* path, uint64_t offset, uint64_t len, CPutEntryCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  blink::mojom::DataElementPtr data_element = blink::mojom::DataElement::NewFile(blink::mojom::DataElementFile::New(base::FilePath(path), offset, len, base::Time()));
  driver->cache_storage()->PutEntry(
    cache_id, 
    request,
    std::move(data_element),
    base::BindOnce(&PutEntryCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageDeleteEntry(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, CDeleteEntryCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->DeleteEntry(
    cache_id, 
    request,
    base::BindOnce(&DeleteEntryCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageRequestCacheNames(ApplicationHostRef handle, int instance_id, const char* securityOrigin, CRequestCacheNamesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->RequestCacheNames(
    securityOrigin,
    base::BindOnce(&RequestCacheNamesCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageRequestCachedResponse(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request_url, int base64_encoded, CRequestCachedResponseCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->RequestCachedResponse(
    cache_id, 
    request_url,
    base64_encoded != 0,
    base::BindOnce(&RequestCachedResponseCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostCacheStorageRequestEntries(ApplicationHostRef handle, int instance_id, const char* cache_id, int32_t skipCount, int32_t pageSize, CRequestEntriesCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->cache_storage()->RequestEntries(cache_id, skipCount, pageSize, 
    base::BindOnce(&RequestEntriesCb, base::Unretained(callback), base::Unretained(state)));
}

// ApplicationCache
void _ApplicationHostApplicationCacheEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->application_cache()->Enable();
}

void _ApplicationHostApplicationCacheGetApplicationCacheForFrame(ApplicationHostRef handle, int instance_id, const char* frameId, CGetApplicationCacheForFrameCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->application_cache()->GetApplicationCacheForFrame(frameId, 
    base::BindOnce(&GetApplicationCacheForFrameCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostApplicationCacheGetFramesWithManifests(ApplicationHostRef handle, int instance_id, CGetFramesWithManifestsCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->application_cache()->GetFramesWithManifests(
    base::BindOnce(&GetFramesWithManifestsCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostApplicationCacheGetManifestForFrame(ApplicationHostRef handle, int instance_id, const char* frame_id, CGetManifestForFrameCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->application_cache()->GetManifestForFrame(
    frame_id,
    base::BindOnce(&GetManifestForFrameCb, base::Unretained(callback), base::Unretained(state)));
}

// Animation
void _ApplicationHostAnimationDisable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->Disable();
}

void _ApplicationHostAnimationEnable(ApplicationHostRef handle, int instance_id) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->Enable();
}

void _ApplicationHostAnimationGetCurrentTime(ApplicationHostRef handle, int instance_id, const char* id, CGetCurrentTimeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->GetCurrentTime(id, base::BindOnce(&GetCurrentTimeCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostAnimationGetPlaybackRate(ApplicationHostRef handle, int instance_id, CGetPlaybackRateCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->GetPlaybackRate(base::BindOnce(&GetPlaybackRateCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostAnimationReleaseAnimations(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<std::string> anim_vec;
  for (int i = 0; i < animations_count; i++) {
    anim_vec.push_back(std::string(animations[i]));
  }
  driver->animation()->ReleaseAnimations(std::move(anim_vec));
}

void _ApplicationHostAnimationResolveAnimation(ApplicationHostRef handle, int instance_id, const char* animation_id, CResolveAnimationCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->ResolveAnimation(animation_id, base::BindOnce(&ResolveAnimationCb, base::Unretained(callback), base::Unretained(state)));
}

void _ApplicationHostAnimationSeekAnimations(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count, int32_t current_time) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<std::string> anim_vec;
  for (int i = 0; i < animations_count; i++) {
    anim_vec.push_back(std::string(animations[i]));
  }
  driver->animation()->SeekAnimations(
    std::move(anim_vec),
    current_time);
}

void _ApplicationHostAnimationSetPaused(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count, int /* bool */ paused) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  std::vector<std::string> anim_vec;
  for (int i = 0; i < animations_count; i++) {
    anim_vec.push_back(std::string(animations[i]));
  }
  driver->animation()->SetPaused(
    std::move(anim_vec),
    paused != 0);
}

void _ApplicationHostAnimationSetPlaybackRate(ApplicationHostRef handle, int instance_id, int32_t playback_rate) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->SetPlaybackRate(playback_rate);
}

void _ApplicationHostAnimationSetTiming(ApplicationHostRef handle, int instance_id, const char* animation_id, int32_t duration, int32_t delay) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->animation()->SetTiming(
    animation_id, 
    duration, 
    delay);
}

// Accessibility
void _ApplicationHostAccessibilityGetPartialAXTree(
    ApplicationHostRef handle, 
    int instance_id,
    const char* /* optional */ node_id, 
    int32_t backend_node_id, 
    const char* /* optional */ object_id, 
    int /* bool */ fetch_relatives, 
    CGetPartialAXTreeCallback callback, void* state) {
  domain::ApplicationDriver* driver = reinterpret_cast<ApplicationState *>(handle)->application()->GetDriver(instance_id);
  driver->accessibility()->GetPartialAXTree(
    node_id, 
    backend_node_id, 
    object_id, 
    fetch_relatives != 0, 
    base::BindOnce(&GetPartialAXTreeCb, base::Unretained(callback), base::Unretained(state)));
}

void _GpuInfoRead(
  GPUInfoPtrRef reference, 
  int* vendor, 
  int* device, 
  const char** vendor_str, 
  const char** device_str, 
  int* device_count,
  const char** aux_str_keys,
  int* aux_str_keys_count,
  const char** aux_str_vals,
  int* aux_str_vals_count,
  const char** feat_str_keys,
  int* feat_str_keys_count,
  const char** feat_str_vals,
  int* feat_str_vals_count,
  const char** workarounds,
  int* workarounds_count) {
  automation::GPUInfo* info = reinterpret_cast<automation::GPUInfo *>(reference);
  *device_count = info->devices.size();
  *aux_str_keys_count = info->aux_attributes.has_value() ? info->aux_attributes.value().size() : 0;
  *aux_str_vals_count = info->aux_attributes.has_value() ? info->aux_attributes.value().size() : 0;
  *workarounds_count = info->driverBugWorkarounds.size();

  vendor = reinterpret_cast<int *>(malloc(sizeof(int) * info->devices.size()));
  device = reinterpret_cast<int *>(malloc(sizeof(int) * info->devices.size()));

  // int32_t vendor_id;
  // int32_t device_id;
  // std::string vendor_string;
  // std::string device_string;

  for (size_t i = 0; i < info->devices.size(); i++) {
    vendor[i] = info->devices[i]->vendor_id;
    device[i] = info->devices[i]->device_id;
    // no problem as GPUInfoPtrRef reference is within scope
    aux_str_keys[i] = info->devices[i]->vendor_string.data();
    aux_str_vals[i] = info->devices[i]->device_string.data();
  }

  if (info->aux_attributes.has_value()) {
    const base::flat_map<std::string, std::string>& map = info->aux_attributes.value();
    for (size_t i = 0; i < map.size(); i++) {
      aux_str_keys[i] = (map.begin() + i)->first.data();
      aux_str_vals[i] = (map.begin() + i)->second.data();
    }
  }

  if (info->feature_status.has_value()) {
    const base::flat_map<std::string, std::string>& map = info->feature_status.value();
    for (size_t i = 0; i < map.size(); i++) {
      info->feature_status.value();
      feat_str_keys[i] = (map.begin() + i)->first.data();
      feat_str_vals[i] = (map.begin() + i)->second.data();
    }
  }

  for (size_t i = 0; i < info->driverBugWorkarounds.size(); i++) {
    // no problem as GPUInfoPtrRef reference is within scope
    workarounds[i] = info->driverBugWorkarounds[i].data();
  }

  //std::vector<GPUDevicePtr> devices;
  //base::Optional<base::flat_map<std::string, std::string>> aux_attributes;
  //base::Optional<base::flat_map<std::string, std::string>> feature_status;
  //std::vector<std::string> driverBugWorkarounds;
  
}

void _GpuInfoClean(
  GPUInfoPtrRef reference, 
  int* vendor, 
  int* device) {
  
  free(vendor);
  free(device);
}

void _HistogramRead(
  HistogramPtrRef reference,
  const char** cname,
  int* sum,
  int* count,
  int** lows,
  int** highs,
  int** counts,
  int* bucket_count) {

  automation::Histogram* histo = reinterpret_cast<automation::Histogram *>(reference);
  *cname = histo->name.data();
  *sum = histo->sum;
  *count = histo->count;
  *bucket_count = histo->buckets.size();
  
  *lows = reinterpret_cast<int*>(malloc(sizeof(int) * histo->buckets.size()));
  *highs = reinterpret_cast<int*>(malloc(sizeof(int) * histo->buckets.size()));
  *counts = reinterpret_cast<int*>(malloc(sizeof(int) * histo->buckets.size()));

  for (size_t i = 0; i < histo->buckets.size(); i++) {
    *lows[i] = histo->buckets[i]->low;
    *highs[i] = histo->buckets[i]->high;
    *counts[i] = histo->buckets[i]->count;
  }
}

void _HistogramClean(
  HistogramPtrRef ref,
  int* lows,
  int* highs,
  int* counts) {

  free(lows);
  free(highs);
  free(counts);
}

void _BoundsRead(
  BoundsPtrRef reference,
  int* left,
  int* top,
  int* width,
  int* height,
  int* state) {
 automation::Bounds* bounds = reinterpret_cast<automation::Bounds *>(reference);
 *left = bounds->left;
 *top = bounds->top;
 *width = bounds->width;
 *height = bounds->height;
 *state = static_cast<int>(bounds->window_state);

}

void _SearchMatchRead(
  SearchMatchPtrRef reference,
  int* line_number,
  const char** line_content) {
  automation::SearchMatch* match = reinterpret_cast<automation::SearchMatch*>(reference);
  *line_number = match->line_number;
  *line_content = match->line_content.data();
}

void _VisualViewportRead(
  VisualViewportPtrRef reference,
  int* offset_x,
  int* offset_y,
  int* page_x,
  int* page_y,
  int* client_width,
  int* client_height,
  float* scale) {
  automation::VisualViewport* viewport = reinterpret_cast<automation::VisualViewport*>(reference);
  *offset_x = viewport->offset_x;
  *offset_y = viewport->offset_y;
  *page_x = viewport->page_x;
  *page_y = viewport->page_y;
  *client_width = viewport->client_width;
  *client_height = viewport->client_height;
  *scale = viewport->scale;
}

void _LayoutViewportRead(
  LayoutViewportPtrRef reference,
  int* page_x,
  int* page_y,
  int* client_width,
  int* client_height) {
  automation::LayoutViewport* layout = reinterpret_cast<automation::LayoutViewport*>(reference);
  *page_x = layout->page_x;
  *page_y = layout->page_y;  
  *client_width = layout->client_width;
  *client_height = layout->client_height;
}

void _CookieRead(
  CookiePtrRef reference,
  const char** name,
  const char** value,
  const char** domain,
  const char** path,
  int64_t* expires,
  int* size,
  int* http_only,
  int* secure,
  int* session,
  int* same_site) {

  automation::Cookie* cookie = reinterpret_cast<automation::Cookie*>(reference);
  *name = cookie->name.data();
  *value = cookie->value.data();
  *domain = cookie->domain.data();
  *path = cookie->path.data();
  *expires = cookie->expires;
  *size = cookie->size;
  *http_only = cookie->http_only ? 1 : 0;
  *secure = cookie->secure ? 1 : 0;
  *session = cookie->session ? 1 : 0;
  *same_site = static_cast<int>(cookie->same_site);

}

void _IndexedDBDataEntryRead(
  IndexedDBDataEntryPtrRef reference,
  const char** key,
  const char** primary_key,
  const char** value) {

  automation::IndexedDBDataEntry* cookie = reinterpret_cast<automation::IndexedDBDataEntry*>(reference);
  *key = cookie->key.data();
  *primary_key = cookie->primary_key.data();
  *value = cookie->value.data();
}

void _DatabaseWithObjectStoresRead(
  DatabaseWithObjectStoresPtrRef reference,
  const char** name,
  int* version,
  const char*** object_names,
  int** object_auto_increments,
  int** object_keypath_types,
  const char*** object_keypath_strs,
  int* object_count,
  const char**** index_names,
  int*** index_uniques,
  int*** index_multientries,
  int*** index_keypath_types,
  const char**** index_keypath_strs,
  int** index_count) {

  automation::DatabaseWithObjectStores* db = reinterpret_cast<automation::DatabaseWithObjectStores*>(reference);
  // 
  // class KeyPath {
  //   var type: KeyPathType = .null
  //   var str: String?
  //   var arr: [String] = []
  // }

  // class ObjectStoreIndex {
  //   var name: String = String()
  //   var keyPath: KeyPath = KeyPath()
  //   var unique: Bool = false
  //   var multiEntry: Bool = false
  // }

  // class ObjectStore {
  //   var name: String = String()
  //   var keyPath: KeyPath = KeyPath()
  //   var autoIncrement: Bool = false
  //   var indexes: [ObjectStoreIndex] = []
  // }

  // class DatabaseWithObjectStores {
  //   var name: String = String()
  //   var version: Int = -1
  //   var objectStores: [ObjectStore] = []
  // }

  *name = db->name.data();
  *version = db->version;

  size_t object_size = db->object_stores.size();

  *object_names = reinterpret_cast<const char**>(malloc(sizeof(char*) * object_size));
  *object_auto_increments = reinterpret_cast<int*>(malloc(sizeof(int) * object_size));
  *object_keypath_types = reinterpret_cast<int*>(malloc(sizeof(int) * object_size));
  *object_keypath_strs = reinterpret_cast<const char**>(malloc(sizeof(char*) * object_size));
  *object_count = object_size;

  *index_names = reinterpret_cast<const char***>(malloc(sizeof(char*) * object_size));
  *index_uniques = reinterpret_cast<int**>(malloc(sizeof(int*) * object_size));
  *index_multientries = reinterpret_cast<int**>(malloc(sizeof(int*) * object_size));
  *index_keypath_types = reinterpret_cast<int**>(malloc(sizeof(int*) * object_size));
  *index_keypath_strs = reinterpret_cast<const char***>(malloc(sizeof(char*) * object_size));
  *index_count = reinterpret_cast<int*>(malloc(sizeof(int) * object_size));

  for (size_t i = 0; i < object_size; i++) {
    const auto& object = db->object_stores[i];
    *object_names[i] = object->name.data();
    *object_auto_increments[i] = object->auto_increment;
    *object_keypath_types[i] = static_cast<int>(object->key_path->type);
    *object_keypath_strs[i] = object->key_path->str.has_value() ? object->key_path->str.value().data() : nullptr;

    size_t index_size = object->indexes.size();
    
    *index_names[i] = reinterpret_cast<const char**>(malloc(sizeof(char*) * index_size));
    *index_uniques[i] = reinterpret_cast<int*>(malloc(sizeof(int) * index_size));
    *index_multientries[i] = reinterpret_cast<int*>(malloc(sizeof(int) * index_size));
    *index_keypath_types[i] =  reinterpret_cast<int*>(malloc(sizeof(int) * index_size));
    *index_keypath_strs[i] = reinterpret_cast<const char**>(malloc(sizeof(char*) * index_size));
    
    *index_count[i] = object->indexes.size();

    for (size_t y = 0; y < object->indexes.size(); y++) {
      const auto& index = object->indexes[i];
      *index_names[i][y] = index->name.data();
      *index_uniques[i][y] = index->unique ? 1 : 0;
      *index_multientries[i][y] = index->multi_entry ? 1 : 0;
      *index_keypath_types[i][y] = static_cast<int>(index->key_path->type);
      *index_keypath_strs[i][y] = index->key_path->str.has_value() ? index->key_path->str.value().data() : nullptr;
    }
  }
}

void _DatabaseWithObjectStoresClean(
  DatabaseWithObjectStoresPtrRef reference,
  const char** object_names,
  int* object_auto_increments,
  int* object_keypath_types,
  const char** object_keypath_strs,
  const char*** index_names,
  int** index_uniques,
  int** index_multientries,
  int** index_keypath_types,
  const char*** index_keypath_strs) {

  automation::DatabaseWithObjectStores* db = reinterpret_cast<automation::DatabaseWithObjectStores*>(reference);  

  free(object_names);
  free(object_auto_increments);
  free(object_keypath_types);
  free(object_keypath_strs);

  size_t object_size = db->object_stores.size();

  for (size_t i = 0; i < object_size; ++i) {
    free(index_names[i]);
    free(index_uniques[i]);
    free(index_multientries[i]);
    free(index_keypath_types[i]);
    free(index_keypath_strs[i]);
  }

  free(index_names);
  free(index_uniques);
  free(index_multientries);
  free(index_keypath_types);
  free(index_keypath_strs);

}

EXPORT void _DOMSnapshotNodeRead(
  DOMSnapshotNodePtrRef reference, 
  int* nodeType,
  const char** nodeName,
  const char** nodeValue,
  const char** textValue,
  const char** inputValue,
  int* inputChecked,
  int* optionSelected,
  int* backendNodeId,
  int** childNodeIndexes,
  int* childNodeIndexesCount,
  const char*** attributesName,
  const char*** attributesValue,
  int* attributesCount,
  int** pseudoElementIndexes,
  int* pseudoElementIndexesCount,
  int* layoutNodeIndex,
  const char** documentUrl,
  const char** baseUrl,
  const char** contentLanguage,
  const char** documentEncoding,
  const char** publicId,
  const char** systemId,
  const char** frameId,
  int* contentDocumentIndex,
  int* importedDocumentIndex,
  int* templateContentIndex,
  int* pseudoType,
  int* shadowRootType,
  int* isClickable,
  const char** currentSourceUrl) {

  automation::DOMSnapshotNode* node = reinterpret_cast<automation::DOMSnapshotNode*>(reference);  
  *nodeType = node->node_type;
  *nodeName = node->node_name.data();
  *textValue = node->text_value.has_value() ? node->text_value.value().data() : nullptr;
  *inputValue = node->input_value.has_value() ? node->input_value.value().data() : nullptr;
  *inputChecked = node->input_checked ? 1 : 0;
  *optionSelected = node->option_selected ? 1 : 0;
  *backendNodeId = node->backend_node_id ? 1 : 0;
  
  *childNodeIndexesCount = 0;

  if (node->child_node_indexes.has_value()) {
    *childNodeIndexesCount = node->child_node_indexes->size();
    *childNodeIndexes = reinterpret_cast<int*>(malloc(sizeof(int) * node->child_node_indexes->size()));
    for (size_t i = 0; i < node->child_node_indexes->size(); i++) {
      *childNodeIndexes[i] = node->child_node_indexes.value()[i];
    }
  }

  if (node->attributes.has_value()) {
    const auto& attr = node->attributes.value();
    *attributesCount = attr.size();
    *attributesName = reinterpret_cast<const char**>(malloc(sizeof(char*) * attr.size()));
    *attributesValue = reinterpret_cast<const char**>(malloc(sizeof(char*) * attr.size()));
    for (size_t i = 0; i < attr.size(); i++) {
      *attributesName[i] = attr[i]->name.data();
      *attributesValue[i] = attr[i]->value.data();
    }
  }

  *pseudoElementIndexesCount = 0;
  if (node->pseudo_element_indexes.has_value()) {
    *pseudoElementIndexesCount = node->pseudo_element_indexes.value().size();
    *pseudoElementIndexes = reinterpret_cast<int*>(malloc(sizeof(int) * node->pseudo_element_indexes.value().size()));
    for (size_t i = 0; i < node->pseudo_element_indexes.value().size(); i++) {
      *pseudoElementIndexes[i] = node->pseudo_element_indexes.value()[i];
    }
  }

  *layoutNodeIndex = node->layout_node_index;

  *documentUrl = node->document_url.has_value() ? node->document_url->data() : nullptr;
  *baseUrl = node->base_url.has_value() ? node->base_url->data() : nullptr;
  *contentLanguage = node->content_language.has_value() ? node->content_language->data() : nullptr;
  *documentEncoding = node->document_encoding.has_value() ? node->document_encoding->data() : nullptr;
  *publicId = node->public_id.has_value() ? node->public_id->data() : nullptr;
  *systemId = node->system_id.has_value() ? node->system_id->data() : nullptr;
  *frameId = node->frame_id.has_value() ? node->frame_id->data() : nullptr;
  *contentDocumentIndex = node->content_document_index;
  *importedDocumentIndex = node->imported_document_index;
  *templateContentIndex = node->template_content_index;
  *pseudoType = static_cast<int>(node->pseudo_type);
  *shadowRootType = static_cast<int>(node->shadow_root_type);
  *isClickable = node->is_clickable;
  *currentSourceUrl = node->current_source_url.has_value() ? node->current_source_url->data() : nullptr;
}
  
EXPORT void _DOMSnapshotNodeCleanup(
  DOMSnapshotNodePtrRef reference, 
  int* childNodeIndexes,
  const char** attributesName,
  const char** attributesValue,
  int* pseudoElementIndexes) {

  free(childNodeIndexes);
  free(attributesName);
  free(attributesValue);
  free(pseudoElementIndexes);
}

void _ComputedStyleRead(
  ComputedStylePtrRef ptr,
  const char*** name_strs,
  const char*** values_strs,
  int* count) {
  
  automation::ComputedStyle* style = reinterpret_cast<automation::ComputedStyle*>(ptr);
  size_t len = style->properties.size();
  if (len > 0) {
    *name_strs = reinterpret_cast<const char**>(malloc(sizeof(char*) * len));
    *values_strs = reinterpret_cast<const char**>(malloc(sizeof(char*) * len));
    for (size_t i = 0; i < len; ++i) {
      *name_strs[i] = style->properties[i]->name.data();
      *values_strs[i] = style->properties[i]->value.data();
    }
  }
}

void _ComputedStyleCleanup(
  ComputedStylePtrRef ptr,
  const char** name_strs,
  const char** values_strs) {
  
  automation::ComputedStyle* style = reinterpret_cast<automation::ComputedStyle*>(ptr);
  size_t len = style->properties.size();
  if (len > 0) {
    free(name_strs);
    free(values_strs);
  }
}

void _LayoutTreeNodeRead(
  LayoutTreeNodePtrRef ptr,
  int* domNodeIndex,
  int* bbx,
  int* bby,
  int* bbw,
  int* bbh,
  const char** layoutText,
  int** itbbx,
  int** itbby,
  int** itbbw,
  int** itbbh,
  int** itsci,
  int** itnc,
  int* itCount,
  int* styleIndex,
  int* paintOrder) {

  automation::LayoutTreeNode* node = reinterpret_cast<automation::LayoutTreeNode*>(ptr);

  *domNodeIndex = node->dom_node_index;
  *bbx = node->bounding_box.x();
  *bby = node->bounding_box.x();
  *bbw = node->bounding_box.width();
  *bbh = node->bounding_box.height();
  *layoutText = node->layout_text.has_value() ? node->layout_text->data() : nullptr;
  if (node->inline_text_nodes.has_value() && (node->inline_text_nodes->size() > 0)) {
    size_t itlen = node->inline_text_nodes->size();
    *itbbx = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itbby = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itbbw = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itbbh = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itsci = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itnc = reinterpret_cast<int *>(malloc(sizeof(int) * itlen));
    *itCount = itlen;
    for (size_t i = 0; i < itlen; ++i) {
      *itbbx[i] = node->inline_text_nodes.value()[i]->bounding_box.x();
      *itbby[i] = node->inline_text_nodes.value()[i]->bounding_box.y();
      *itbbw[i] = node->inline_text_nodes.value()[i]->bounding_box.width();
      *itbbh[i] = node->inline_text_nodes.value()[i]->bounding_box.height();
      *itsci[i] = node->inline_text_nodes.value()[i]->start_character_index;
      *itnc[i] = node->inline_text_nodes.value()[i]->num_characters;
    }
  }
  *styleIndex = node->style_index;
  *paintOrder = node->paint_order;
}
    
void _LayoutTreeNodeCleanup(
  LayoutTreeNodePtrRef ptr,
  int* itbbx,
  int* itbby,
  int* itbbw,
  int* itbbh,
  int* itsci,
  int* itnc) {

  automation::LayoutTreeNode* node = reinterpret_cast<automation::LayoutTreeNode*>(ptr);  
  if (node->inline_text_nodes.has_value() && (node->inline_text_nodes->size() > 0)) {
    free(itbbx);
    free(itbby);
    free(itbbw);
    free(itbbh);
    free(itsci);
    free(itnc);
  }
}

void _DOMNodeRead(
  DOMNodePtrRef ptr,
  int* nodeId,
  int* parentId,
  int* backendNodeId,
  int* nodeType,
  const char** nodeName,
  const char** localName,
  const char** nodeValue,
  int* childNodeCount,
  const char*** attributes,
  int* attributes_count,
  const char** documentUrl,
  const char** baseUrl,
  const char** publicId,
  const char** systemId,
  const char** internalSubset,
  const char** xmlVersion,
  const char** name,
  const char** value,
  int* pseudoType,
  int* shadowRootType,
  const char** frameId,
  int* isSvg,
  int** dnNodeTypes,
  const char*** dnNodeNames,
  int** dnNodeIds,
  int* dnNodesCount) {

  automation::DOMNode* node = reinterpret_cast<automation::DOMNode*>(ptr);
  *nodeId = node->node_id;
  *parentId = node->parent_id;
  *backendNodeId = node->backend_node_id;
  *nodeType = node->node_type;
  *nodeName = node->node_name.data();
  *localName = node->local_name.data();
  *nodeValue = node->node_value.data();
  *childNodeCount = node->child_node_count;
  
  *attributes_count = node->attributes.size();
  *attributes = (const char**)malloc(sizeof(char*) * node->attributes.size()); 
  for (size_t i = 0; i < node->attributes.size(); i++) {
    *attributes[i] = node->attributes[i].data();
  }
  *documentUrl = node->document_url.has_value() ? node->document_url->data() : nullptr;
  *baseUrl = node->base_url.has_value() ? node->base_url->data() : nullptr;
  *publicId = node->public_id.has_value() ? node->public_id->data() : nullptr;
  *systemId = node->system_id.has_value() ? node->system_id->data() : nullptr;
  *xmlVersion = node->xml_version.has_value() ? node->xml_version->data() : nullptr;
  *name = node->name.has_value() ? node->name->data() : nullptr;
  *value = node->value.has_value() ? node->value->data() : nullptr;
  *pseudoType = static_cast<int>(node->pseudo_type);
  *shadowRootType = static_cast<int>(node->shadow_root_type);
  *frameId = node->frame_id.has_value() ? node->frame_id->data() : nullptr;
  *isSvg = node->is_svg ? 1 : 0;

  *dnNodesCount = 0;
  *dnNodeTypes = nullptr;
  *dnNodeNames = nullptr; 
  *dnNodeIds = nullptr;
  
  size_t distributed_nodes_len = node->distributed_nodes.has_value() ? node->distributed_nodes->size() : 0;
  if (distributed_nodes_len > 0) {
    *dnNodesCount = distributed_nodes_len;
    *dnNodeTypes = reinterpret_cast<int*>(malloc(sizeof(int) * distributed_nodes_len));
    *dnNodeNames = reinterpret_cast<const char**>(malloc(sizeof(char*) * distributed_nodes_len));
    *dnNodeIds = reinterpret_cast<int*>(malloc(sizeof(int) * distributed_nodes_len));
    for (size_t i = 0; i < distributed_nodes_len; i++) {
      const auto& dnode = node->distributed_nodes.value()[i];
      *dnNodeTypes[i] = static_cast<int>(dnode->node_type);
      *dnNodeNames[i] = dnode->node_name.data();
      *dnNodeIds[i] = dnode->backend_node_id;
    }
  }

}

void _ScreencastFrameMetadataRead(
  ScreencastFrameMetadataPtrRef ptr,
  int* offsetTop,
  float* pageScaleFactor,
  int* deviceWidth,
  int* deviceHeight,
  int* scrollOffsetX,
  int* scrollOffsetY,
  int* timestamp) {

  automation::ScreencastFrameMetadata* metadata = reinterpret_cast<automation::ScreencastFrameMetadata*>(ptr);
  *offsetTop = metadata->offset_top;
  *pageScaleFactor = metadata->page_scale_factor;
  *deviceWidth = metadata->device_width;
  *deviceHeight = metadata->device_height;
  *scrollOffsetX = metadata->scroll_offset_x;
  *scrollOffsetY = metadata->scroll_offset_y;
  *timestamp = metadata->timestamp;
}

void _ViewportRead(ViewportPtrRef ptr, int* x, int* y, int* width, int* height, float* scale) {
  automation::Viewport* viewport = reinterpret_cast<automation::Viewport*>(ptr);
  *x = viewport->x;
  *y = viewport->y;
  *width = viewport->width;
  *height = viewport->height;
  *scale = viewport->scale;
}

void _ServiceWorkerRegistrationRead(
  ServiceWorkerRegistrationPtrRef ptr, 
  const char** id,
  const char** url,
  int* is_deleted) {

  automation::ServiceWorkerRegistration* registration = reinterpret_cast<automation::ServiceWorkerRegistration*>(ptr);
  *id = registration->registration_id.data();
  *url = registration->scope_url.data();
  *is_deleted = registration->is_deleted ? 1 : 0;
}

void _ServiceWorkerVersionRead(
  ServiceWorkerVersionPtrRef ptr, 
  const char** vid,
  const char** rid,
  const char** url,
  int* runningStatus,
  int* status,
  int* scriptLastModified,
  int64_t* scriptResponseTime,
  int** controlledClients,
  int* controlledClientsCount,
  int* targetId) {
  
  automation::ServiceWorkerVersion* version = reinterpret_cast<automation::ServiceWorkerVersion*>(ptr);
  size_t clients_len = version->controlled_clients.has_value()? version->controlled_clients->size() : 0;

  *vid = version->version_id.data();
  *rid = version->registration_id.data();
  *url = version->script_url.data();
  *runningStatus = static_cast<int>(version->running_status);
  *status = static_cast<int>(version->status);
  *scriptLastModified = version->script_last_modified;
  *controlledClientsCount = clients_len;
  if (clients_len > 0) {
    *controlledClients = reinterpret_cast<int *>(malloc(sizeof(int) * clients_len));
    for (size_t i = 0; i < clients_len; i++) {
      *controlledClients[i] = version->controlled_clients.value()[i];
    }
  }
  *targetId = version->target_id;
}

void _ServiceWorkerVersionCleanup(
  ServiceWorkerVersionPtrRef ptr,
  int* controlledClients) {
  free(controlledClients);
}

void _ServiceWorkerErrorMessageRead(
  ServiceWorkerErrorMessagePtrRef ptr, 
  const char** msg,
  const char** rid,
  const char** surl,
  int* line,
  int* column) {

  // string error_message;
  // string registration_id;
  // string version_id;
  // string source_url;
  // int32 line_number;
  // int32 column_number;
  
  automation::ServiceWorkerErrorMessage* message = reinterpret_cast<automation::ServiceWorkerErrorMessage*>(ptr);
  *msg = message->error_message.data();
  *rid = message->registration_id.data();
  *surl = message->version_id.data();
  *line = message->line_number;
  *column = message->column_number;
}

void _TargetInfoRead(
  TargetInfoPtrRef ref, 
  const char** targetId, 
  const char** type, 
  const char** title, 
  const char** url, 
  int* attached, 
  const char** openerId, 
  const char** browserContextId) {

  automation::TargetInfo* info = reinterpret_cast<automation::TargetInfo*>(ref);
  *targetId = info->target_id.data();
  *type = info->type.data();
  *title = info->title.data();
  *url = info->url.data();
  *attached = info->attached ? 1 : 0;
  *openerId = info->opener_id.has_value() ? info->opener_id.value().data() : nullptr;
  *browserContextId = info->browser_context_id.has_value() ? info->browser_context_id.value().data() : nullptr;
}

void _AuthChallengeRead(
  AuthChallengePtrRef ptr, 
  int* source, 
  const char** origin, 
  const char** scheme, 
  const char** realm) {

  automation::AuthChallenge* challenge = reinterpret_cast<automation::AuthChallenge*>(ptr);
  *source = static_cast<int>(challenge->source);
  *origin = challenge->origin.data();
  *scheme = challenge->scheme.data();
  *realm = challenge->realm.data();
}

void _InitiatorRead(
  InitiatorPtrRef ptr, 
  int* type,
  const char** url,
  int* linenumber) {

  automation::Initiator* initiator = reinterpret_cast<automation::Initiator*>(ptr);
  *type = static_cast<int>(initiator->type);
  *url = initiator->url.has_value() ? initiator->url->data() : nullptr;
  *linenumber = initiator->line_number;
}

void _WebSocketFrameRead(
  WebSocketFramePtrRef ptr, 
  int* opcode,
  int* mask,
  const char** payloadData) {
  
  automation::WebSocketFrame* frame = reinterpret_cast<automation::WebSocketFrame*>(ptr);
  *opcode = frame->opcode;
  *mask = frame->mask;
  *payloadData = frame->payload_data.data();
}

void _WebSocketResponseRead(
  WebSocketResponsePtrRef ptr, 
  int* status,
  const char** statusText,
  const char*** headersKeys,
  const char*** headersValues,
  int* headersCount,
  const char** headersText,
  const char*** requestHeadersKeys,
  const char*** requestHeadersValues,
  int* requestHeadersCount,
  const char** requestHeadersText) {
  
  automation::WebSocketResponse* response = reinterpret_cast<automation::WebSocketResponse*>(ptr);
  *status = static_cast<int>(response->status);
  *statusText = response->status_text.data();
  *headersCount = response->headers.size();
  if (response->headers.size() > 0) {
    *headersKeys = (const char**)malloc(sizeof(char *) * response->headers.size());
    *headersValues = (const char**)malloc(sizeof(char *) * response->headers.size());
    for (size_t i = 0; i < response->headers.size(); i++) {
      auto kv = (response->headers.begin() + i);
      *headersKeys[i] = kv->first.data();
      *headersValues[i] = kv->second.data();
    }
  }
  *headersText = response->headers_text.has_value() ? response->headers_text->data() : nullptr;
  *requestHeadersCount = response->headers.size();
  if (response->request_headers.has_value() && response->request_headers->size() > 0) {
    *requestHeadersKeys = (const char**)malloc(sizeof(char *) * response->request_headers->size());
    *requestHeadersValues = (const char**)malloc(sizeof(char *) * response->request_headers->size());
    for (size_t i = 0; i < response->request_headers->size(); i++) {
      auto kv = (response->request_headers->begin() + i);
      *requestHeadersKeys[i] = kv->first.data();
      *requestHeadersValues[i] = kv->second.data();
    }
  }
  *requestHeadersText = response->request_headers_text.has_value() ? response->request_headers_text->data() : nullptr;
}

void _WebSocketResponseCleanup(
  WebSocketResponsePtrRef ptr,
  const char** headersKeys,
  const char** headersValues,
  const char** requestHeadersKeys,
  const char** requestHeadersValues) {
  
  free(headersKeys);
  free(headersValues);
  free(requestHeadersKeys);
  free(requestHeadersValues);
}

void _WebSocketRequestRead(
  WebSocketRequestPtrRef ptr, 
  const char*** headersKeys,
  const char*** headersValues,
  int* headersCount) {
  
  automation::WebSocketRequest* request = reinterpret_cast<automation::WebSocketRequest*>(ptr);  

  *headersCount = request->headers.size();
  if (request->headers.size() > 0) {
    *headersKeys = (const char**)malloc(sizeof(char *) * request->headers.size());
    *headersValues = (const char**)malloc(sizeof(char *) * request->headers.size());
    for (size_t i = 0; i < request->headers.size(); i++) {
      auto kv = (request->headers.begin() + i);
      *headersKeys[i] = kv->first.data();
      *headersValues[i] = kv->second.data();
    }
  }
}
    
void _WebSocketRequestCleanup(
  WebSocketRequestPtrRef ptr, 
  const char** headersKeys,
  const char** headersValues) {

  free(headersKeys);
  free(headersValues);
}

void _SQLErrorRead(
  ErrorPtrRef ptr, 
  const char** message, 
  int* code) {

  automation::Error* error = reinterpret_cast<automation::Error*>(ptr);
  *message = error->message.data();
  *code = error->code;
}

void _BoxModelRead(
  BoxModelPtrRef ptr,
  double** content,
  int* contentCount,
  double** padding,
  int* paddingCount,
  double** border,
  int* borderCount,
  double** margin,
  int* marginCount,
  int* width,
  int* height,
  double** shapeBounds,
  int* shapeBoundsCount) {

  automation::BoxModel* model = reinterpret_cast<automation::BoxModel*>(ptr);
  size_t content_len = model->content.size();
  size_t padding_len = model->padding.size();
  size_t border_len = model->border.size();
  size_t margin_len = model->margin.size();
  size_t bounds_len = model->shape_outside ? model->shape_outside->bounds.size() : 0;

  *contentCount = content_len;
  *paddingCount = padding_len;
  *borderCount = border_len;
  *marginCount = margin_len;
  *shapeBoundsCount = bounds_len;

  if (content_len) {
    *content = (double *)malloc(sizeof(double) * content_len);
    for (size_t i = 0; i < content_len; i++) {
      *content[i] = model->content[i];
    }
  }
  if (padding_len) {
    *padding = (double *)malloc(sizeof(double) * padding_len);
    for (size_t i = 0; i < padding_len; i++) {
      *padding[i] = model->padding[i];
    }
  }
  if (border_len) {
    *border = (double *)malloc(sizeof(double) * border_len);
    for (size_t i = 0; i < border_len; i++) {
      *border[i] = model->border[i];
    }
  }
  if (margin_len) {
    *margin = (double *)malloc(sizeof(double) * margin_len);
    for (size_t i = 0; i < margin_len; i++) {
      *margin[i] = model->margin[i];
    }
  }
  if (bounds_len) {
    *shapeBounds = (double *)malloc(sizeof(double) * bounds_len);
    for (size_t i = 0; i < bounds_len; i++) {
      *shapeBounds[i] = model->shape_outside->bounds[i];
    }
  }
}
    
void _BoxModelCleanup(
  BoxModelPtrRef ptr,
  double* content,
  int contentCount,
  double* padding,
  int paddingCount,
  double* border,
  int borderCount,
  double* margin,
  int marginCount,
  double* shapeBounds,
  int shapeCount) {
  
  if (contentCount) {
    free(content);
  }
  if (paddingCount) {
    free(padding);
  }
  if (borderCount) {
    free(border);
  }
  if (marginCount) {
    free(margin);
  }
  if (shapeCount) {
    free(shapeBounds);
  }
  
}

void _CSSRuleRead(
  CSSRulePtrRef ptr,
  const char** cstylesheetId,
  const char** cselectorListText,
  int* cselectorListValuesCount,
  const char*** cselectorListValuesTexts,
  int** cselectorListValuesStartLine,
  int** cselectorListValuesStartColumn,
  int** cselectorListValuesEndLine,
  int** cselectorListValuesEndColumn,
  int* corigin,
  int* cssPropertiesCount,
  const char*** cssPropertiesNames,
  const char*** cssPropertiesValues,
  int** cssPropertiesImportants,
  int** cssPropertiesImplicits,
  const char*** cssPropertiesTexts,
  int** cssPropertiesParsedOk,
  int** cssPropertiesDisabled,
  int** cssPropertiesStartLine,
  int** cssPropertiesStartColumn,
  int** cssPropertiesEndLine,
  int** cssPropertiesEndColumn,
  int* shorthandEntriesCount,
  const char*** shorthandEntriesNames,
  const char*** shorthandEntriesValues,
  int** shorthandEntriesImportants,
  const char** styleSheetId,
  const char** styleCssText,
  int* styleStartLine,
  int* styleStartColumn,
  int* styleEndLine,
  int* styleEndColumn,
  CSSMediaPtrRef** cssMedias,
  int* cssMediasCount) {

  automation::CSSRule* rule = reinterpret_cast<automation::CSSRule*>(ptr);

  size_t selector_list_values_len = rule->selector_list->selectors.size();
  *cselectorListValuesCount = selector_list_values_len;

  if (rule->style_sheet_id.has_value()) {
    *cstylesheetId = rule->style_sheet_id->data();
  }

  *corigin = static_cast<int>(rule->origin);
  *cselectorListText = rule->selector_list->text.data();

  if (selector_list_values_len > 0) {
    *cselectorListValuesTexts = reinterpret_cast<const char**>(malloc(sizeof(char*) * selector_list_values_len));
    *cselectorListValuesStartLine = reinterpret_cast<int*>(malloc(sizeof(int) * selector_list_values_len));
    *cselectorListValuesStartColumn = reinterpret_cast<int*>(malloc(sizeof(int) * selector_list_values_len));
    *cselectorListValuesEndLine = reinterpret_cast<int*>(malloc(sizeof(int) * selector_list_values_len));
    *cselectorListValuesEndColumn = reinterpret_cast<int*>(malloc(sizeof(int) * selector_list_values_len));
    for (size_t i = 0; i < selector_list_values_len; i++) {
      *cselectorListValuesTexts[i] = rule->selector_list->selectors[i]->text.data();
      *cselectorListValuesStartLine[i] = rule->selector_list->selectors[i]->range->start_line;
      *cselectorListValuesStartColumn[i] = rule->selector_list->selectors[i]->range->start_column;
      *cselectorListValuesEndLine[i] = rule->selector_list->selectors[i]->range->end_line;
      *cselectorListValuesEndColumn[i] = rule->selector_list->selectors[i]->range->end_column;
    }
  }

  size_t properties_len = rule->style->css_properties.size();
  *cssPropertiesCount = properties_len;

  if (properties_len > 0) {
    *cssPropertiesNames = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesValues = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesImportants = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesImplicits = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesTexts = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesParsedOk = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesDisabled = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesStartLine = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesStartColumn = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesEndLine = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesEndColumn = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cselectorListValuesTexts = reinterpret_cast<const char**>(malloc(sizeof(char*) * selector_list_values_len));

    for (size_t i = 0; i < properties_len; i++) {
      *cssPropertiesNames[i] = rule->style->css_properties[i]->name.data();
      *cssPropertiesValues[i] = rule->style->css_properties[i]->value.data();
      *cssPropertiesImportants[i] = rule->style->css_properties[i]->important ? 1 : 0;
      *cssPropertiesImplicits[i] = rule->style->css_properties[i]->implicit ? 1 : 0;
      *cssPropertiesTexts[i] =  rule->style->css_properties[i]->text.has_value() ? rule->style->css_properties[i]->text->data() : nullptr;
      *cssPropertiesParsedOk[i] = rule->style->css_properties[i]->parsed_ok ? 1 : 0; 
      *cssPropertiesDisabled[i] = rule->style->css_properties[i]->disabled ? 1 : 0;
      if (rule->style->css_properties[i]->range) {
        *cssPropertiesStartLine[i] = rule->style->css_properties[i]->range->start_line;
        *cssPropertiesStartColumn[i] = rule->style->css_properties[i]->range->start_column;
        *cssPropertiesEndLine[i] = rule->style->css_properties[i]->range->end_line;
        *cssPropertiesEndColumn[i] = rule->style->css_properties[i]->range->end_column;
      } else {
        *cssPropertiesStartLine[i] = -1;
        *cssPropertiesStartColumn[i] = -1;
        *cssPropertiesEndLine[i] = -1;
        *cssPropertiesEndColumn[i] = -1;
      }
    }
  }
  
  size_t entries_len = rule->style->css_properties.size();
  *shorthandEntriesCount = entries_len;

  if (entries_len > 0) {
    *shorthandEntriesNames = reinterpret_cast<const char**>(malloc(sizeof(char*) * entries_len));
    *shorthandEntriesValues = reinterpret_cast<const char**>(malloc(sizeof(char*) * entries_len));
    *shorthandEntriesImportants = reinterpret_cast<int*>(malloc(sizeof(char*) * entries_len));

    for (size_t i = 0; i < entries_len; i++) {
      *shorthandEntriesNames[i] = rule->style->shorthand_entries[i]->name.data();
      *shorthandEntriesValues[i] = rule->style->shorthand_entries[i]->value.data();
      *shorthandEntriesImportants[i] = rule->style->shorthand_entries[i]->important ? 1 : 0;
    }

  }

  *styleSheetId = rule->style->style_sheet_id.has_value() ? rule->style->style_sheet_id->data() : nullptr;
  *styleCssText = rule->style->css_text.has_value() ? rule->style->css_text->data() : nullptr;
  if (rule->style->range) {
    *styleStartLine = rule->style->range->start_line;
    *styleStartColumn = rule->style->range->start_column;
    *styleEndLine = rule->style->range->end_line;
    *styleEndColumn = rule->style->range->end_column;
  } else {
    *styleStartLine = -1;
    *styleStartColumn = -1;
    *styleEndLine = -1;
    *styleEndColumn = -1;
  }

  *cssMediasCount = 0;
  if (rule->media.has_value() && rule->media->size() > 0) {
    *cssMediasCount = rule->media->size();
    *cssMedias = (CSSMediaPtrRef *)malloc(sizeof(CSSMediaPtrRef) * rule->media->size());
    for (size_t i = 0; i < rule->media->size(); i++) {
      *cssMedias[i] = rule->media.value()[i].get();
    }
  }
  
}

void _CSSRuleCleanup(
  CSSRulePtrRef ptr,
  int cselectorListValuesCount,
  const char** cselectorListValuesTexts,
  int* cselectorListValuesStartLine,
  int* cselectorListValuesStartColumn,
  int* cselectorListValuesEndLine,
  int* cselectorListValuesEndColumn,
  int cssPropertiesCount,
  const char** cssPropertiesNames,
  const char** cssPropertiesValues,
  int* cssPropertiesImportants,
  int* cssPropertiesImplicits,
  const char** cssPropertiesTexts,
  int* cssPropertiesParsedOk,
  int* cssPropertiesDisabled,
  int* cssPropertiesStartLine,
  int* cssPropertiesStartColumn,
  int* cssPropertiesEndLine,
  int* cssPropertiesEndColumn,
  int shorthandEntriesCount,
  const char** shorthandEntriesNames,
  const char** shorthandEntriesValues,
  int* shorthandEntriesImportants,
  CSSMediaPtrRef* cssMedias,
  int cssMediasCount) {
  
  if (cselectorListValuesCount > 0) {
    free(cselectorListValuesTexts);
    free(cselectorListValuesStartLine);
    free(cselectorListValuesStartColumn);
    free(cselectorListValuesEndLine);
    free(cselectorListValuesEndColumn);
  }

  if (cssPropertiesCount > 0) {
    free(cssPropertiesNames);
    free(cssPropertiesValues);
    free(cssPropertiesImportants);
    free(cssPropertiesImplicits);
    free(cssPropertiesTexts);
    free(cssPropertiesParsedOk);
    free(cssPropertiesDisabled);
    free(cssPropertiesStartLine);
    free(cssPropertiesStartColumn);
    free(cssPropertiesEndLine);
    free(cssPropertiesEndColumn);
    free(cselectorListValuesTexts);
  }
  
  if (shorthandEntriesCount > 0) {
    free(shorthandEntriesNames);
    free(shorthandEntriesValues);
    free(shorthandEntriesImportants);
  }

  if (cssMediasCount > 0) {
    free(cssMedias);
  }
  
}

void _FrameRead(
  FramePtrRef ptr,
  const char** cid,
  const char** pid,
  const char** lid,
  const char** cname,
  const char** curl,
  const char** csecurityOrigin,
  const char** cmimeType,
  const char** cunreachableUrl) {

  automation::Frame* frame = reinterpret_cast<automation::Frame*>(ptr);
  *cid = frame->id.data();
  *pid = frame->parent_id.data();
  *lid = frame->loader_id.data();
  *cname = frame->name.data();
  *curl = frame->url.data();
  *csecurityOrigin = frame->security_origin.data();
  *cmimeType = frame->mime_type.data();
  *cunreachableUrl = frame->unreachable_url.data();

}

void _LayerRead(
  LayerPtrRef ptr,
  const char** clayerId,
  const char** playerId,
  int* cbackendNode,
  int* coffsetx,
  int* coffsety,
  int* cwidth,
  int* cheight,
  double** ctransform,
  int* ctransformCount,
  int* canchorX,
  int* canchorY,
  int* canchorZ,
  int* cpaintCount,
  int* cdrawsContent,
  int* cinvisible,
  int** csx,
  int** csy,
  int** csw,
  int** csh,
  int** cstype,
  int* scrollRectCount,
  int* cspx,
  int* cspy,
  int* cspw,
  int* csph,
  int* cspcx,
  int* cspcy,
  int* cspcw,
  int* cspch,
  const char** cspStickyBox,
  const char** cspContainingBlock) {
  
  automation::Layer* layer = reinterpret_cast<automation::Layer*>(ptr);
  *clayerId = layer->layer_id.data();
  *playerId = layer->parent_layer_id.has_value() ? layer->parent_layer_id->data() : nullptr;
  *cbackendNode = layer->backend_node_id;
  *coffsetx = layer->offset_x;
  *coffsety = layer->offset_y;
  *cwidth = layer->width;
  *cheight = layer->height;

  *ctransformCount = 0;
  if (layer->transform.has_value() && layer->transform->size() > 0) {
    size_t len = layer->transform->size();
    *ctransformCount = len;
    *ctransform = reinterpret_cast<double*>(malloc(sizeof(double) * len));
    for (size_t i = 0; i < len; i++) {
      *ctransform[i] = layer->transform.value()[i]; 
    }
  }

  *scrollRectCount = 0;
  if (layer->scroll_rects.has_value() && layer->scroll_rects->size() > 0) {
    size_t len = layer->scroll_rects->size();
    *scrollRectCount = len;
    *csx = reinterpret_cast<int*>(malloc(sizeof(int) * len));
    *csy = reinterpret_cast<int*>(malloc(sizeof(int) * len));
    *csw = reinterpret_cast<int*>(malloc(sizeof(int) * len));
    *csh = reinterpret_cast<int*>(malloc(sizeof(int) * len));
    *cstype = reinterpret_cast<int*>(malloc(sizeof(int) * len));
    for (size_t i = 0; i < len; i++) {
      if (layer->scroll_rects.value()[i]) {
        *csx[i] = layer->scroll_rects.value()[i]->rect.x();
        *csy[i] = layer->scroll_rects.value()[i]->rect.y();
        *csw[i] = layer->scroll_rects.value()[i]->rect.width();
        *csh[i] = layer->scroll_rects.value()[i]->rect.height();
        *cstype[i] = static_cast<int>(layer->scroll_rects.value()[i]->type);
      }
    }
  }
  *canchorX = layer->anchor_x;
  *canchorY = layer->anchor_y;
  *canchorZ = layer->anchor_z;
  *cpaintCount = layer->paint_count;
  *cdrawsContent = layer->draws_content ? 1 : 0;
  *cinvisible = layer->invisible ? 1 : 0;
  if (layer->sticky_position_constraint) {
    *cspx = layer->sticky_position_constraint->sticky_box_rect.x();
    *cspy = layer->sticky_position_constraint->sticky_box_rect.y();
    *cspw = layer->sticky_position_constraint->sticky_box_rect.width();
    *csph = layer->sticky_position_constraint->sticky_box_rect.height();
    *cspcx = layer->sticky_position_constraint->containing_block_rect.x();
    *cspcy = layer->sticky_position_constraint->containing_block_rect.y();
    *cspcw = layer->sticky_position_constraint->containing_block_rect.width();
    *cspch = layer->sticky_position_constraint->containing_block_rect.height();
    *cspStickyBox = layer->sticky_position_constraint->nearest_layer_shifting_sticky_box.data();
    *cspContainingBlock = layer->sticky_position_constraint->nearest_layer_shifting_containing_block.data();
  }
  
}

void _LayerCleanup(
  LayerPtrRef ptr,
  double* ctransform,
  int ctransformCount,
  int* csx,
  int* csy,
  int* csw,
  int* csh,
  int* cstype,
  int scrollRectCount) {

  if (ctransformCount > 0) {
    free(ctransform);
  }

  if (scrollRectCount > 0) {
    free(csx);
    free(csy);
    free(csw);
    free(csh);
    free(cstype);
  }
}

void _StorageIdRead(
  StorageIdPtrRef ptr,
  const char** securityOrigin,
  int* localStorage) {

  automation::StorageId* storage = reinterpret_cast<automation::StorageId*>(ptr);
  *securityOrigin = storage->security_origin.data();
  *localStorage = storage->is_local_storage ? 1 : 0;
}

void _CSSStyleRead(
  CSSStylePtrRef ptr,
  const char** styleSheetId,
  const char** styleCssText,
  int* styleStartLine,
  int* styleStartColumn,
  int* styleEndLine,
  int* styleEndColumn,
  int* cssPropertiesCount,
  const char*** cssPropertiesNames,
  const char*** cssPropertiesValues,
  int** cssPropertiesImportants,
  int** cssPropertiesImplicits,
  const char*** cssPropertiesTexts,
  int** cssPropertiesParsedOk,
  int** cssPropertiesDisabled,
  int** cssPropertiesStartLine,
  int** cssPropertiesStartColumn,
  int** cssPropertiesEndLine,
  int** cssPropertiesEndColumn,
  int* shorthandEntriesCount,
  const char*** shorthandEntriesNames,
  const char*** shorthandEntriesValues,
  int** shorthandEntriesImportants) {

  automation::CSSStyle* style = reinterpret_cast<automation::CSSStyle*>(ptr);
  *styleSheetId = style->style_sheet_id.has_value() ? style->style_sheet_id->data() : nullptr;
  *styleCssText = style->css_text.has_value() ? style->css_text->data() : nullptr;
  if (style->range) {
    *styleStartLine = style->range->start_line;
    *styleStartColumn = style->range->start_column;
    *styleEndLine = style->range->end_line;
    *styleEndColumn = style->range->end_column;
  } else {
    *styleStartLine = -1;
    *styleStartColumn = -1;
    *styleEndLine = -1;
    *styleEndColumn = -1;
  }

  size_t properties_len = style->css_properties.size();
  *cssPropertiesCount = properties_len;

  if (properties_len > 0) {
    *cssPropertiesNames = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesValues = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesImportants = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesImplicits = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesTexts = reinterpret_cast<const char**>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesParsedOk = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesDisabled = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesStartLine = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesStartColumn = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesEndLine = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
    *cssPropertiesEndColumn = reinterpret_cast<int*>(malloc(sizeof(char*) * properties_len));
  
    for (size_t i = 0; i < properties_len; i++) {
      *cssPropertiesNames[i] = style->css_properties[i]->name.data();
      *cssPropertiesValues[i] = style->css_properties[i]->value.data();
      *cssPropertiesImportants[i] = style->css_properties[i]->important ? 1 : 0;
      *cssPropertiesImplicits[i] = style->css_properties[i]->implicit ? 1 : 0;
      *cssPropertiesTexts[i] =  style->css_properties[i]->text.has_value() ? style->css_properties[i]->text->data() : nullptr;
      *cssPropertiesParsedOk[i] = style->css_properties[i]->parsed_ok ? 1 : 0; 
      *cssPropertiesDisabled[i] = style->css_properties[i]->disabled ? 1 : 0;
      if (style->css_properties[i]->range) {
        *cssPropertiesStartLine[i] = style->css_properties[i]->range->start_line;
        *cssPropertiesStartColumn[i] = style->css_properties[i]->range->start_column;
        *cssPropertiesEndLine[i] = style->css_properties[i]->range->end_line;
        *cssPropertiesEndColumn[i] = style->css_properties[i]->range->end_column;
      } else {
        *cssPropertiesStartLine[i] = -1;
        *cssPropertiesStartColumn[i] = -1;
        *cssPropertiesEndLine[i] = -1;
        *cssPropertiesEndColumn[i] = -1;
      }
    }
  }
  
  size_t entries_len = style->css_properties.size();
  *shorthandEntriesCount = entries_len;
  if (entries_len > 0) {
    *shorthandEntriesNames = reinterpret_cast<const char**>(malloc(sizeof(char*) * entries_len));
    *shorthandEntriesValues = reinterpret_cast<const char**>(malloc(sizeof(char*) * entries_len));
    *shorthandEntriesImportants = reinterpret_cast<int*>(malloc(sizeof(char*) * entries_len));
    for (size_t i = 0; i < entries_len; i++) {
      *shorthandEntriesNames[i] = style->shorthand_entries[i]->name.data();
      *shorthandEntriesValues[i] = style->shorthand_entries[i]->value.data();
      *shorthandEntriesImportants[i] = style->shorthand_entries[i]->important ? 1 : 0;
    }

  }
}

void _BackendNodeRead(
  BackendNodePtrRef ptr, 
  int* nodeType,
  const char** nodeName,
  int* backendNodeId) {

  automation::BackendNode* node = reinterpret_cast<automation::BackendNode*>(ptr);
  *nodeType = node->node_type;
  *nodeName = node->node_name.data();
  *backendNodeId = node->backend_node_id;
}

EXPORT void _CSSValueRead(
  CSSValuePtrRef ptr,
  const char** text,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn) {

  automation::CSSValue* value = reinterpret_cast<automation::CSSValue*>(ptr);  
  *text = value->text.data();
  if (value->range) {
    *startLine = value->range->start_line;
    *startColumn = value->range->start_column;
    *endLine = value->range->end_line;
    *endColumn = value->range->end_column;
  }
}

void _RuleMatchRead(
  RuleMatchPtrRef ptr, 
  CSSRulePtrRef* rule,
  int** sels,
  int* selsCount) {

  automation::RuleMatch* match = reinterpret_cast<automation::RuleMatch*>(ptr);    
  *selsCount = match->matching_selectors.size();
  if (match->matching_selectors.size() > 0) {
    *sels = (int *)malloc(sizeof(int) * match->matching_selectors.size());
    for (size_t i = 0; i < match->matching_selectors.size(); i++) {
      *sels[i] = match->matching_selectors[i];
    }
  }
  *rule = match->rule.get();
}

void _RuleMatchCleanup(
  RuleMatchPtrRef ptr,
  int* sels,
  int selsCount) {

  if (selsCount > 0) {
    free(sels);
  }

}

void _DatabaseRead(
  DatabasePtrRef ptr, 
  const char** id,
  const char** dom,
  const char** name,
  const char** version) {

  automation::Database* db = reinterpret_cast<automation::Database*>(ptr);
  *id = db->id.data();
  *dom = db->domain.data();
  *name = db->name.data();
  *version = db->version.data();
}

void _FontFaceRead(
  FontFacePtrRef ptr,
  const char** fontFamily,
  const char** fontStyle,
  const char** fontVariant,
  const char** fontWeight,
  const char** fontStretch,
  const char** unicodeRange,
  const char** src,
  const char** platformFontFamily) {

  automation::FontFace* font = reinterpret_cast<automation::FontFace*>(ptr);
  *fontFamily = font->font_family.data();
  *fontStyle = font->font_style.data();
  *fontVariant = font->font_variant.data();
  *fontWeight = font->font_weight.data();
  *fontStretch = font->font_stretch.data();
  *unicodeRange = font->unicode_range.data();
  *src = font->src.data();
  *platformFontFamily = font->platform_font_family.data();
}

void _CSSStyleSheetHeaderRead(
  CSSStyleSheetHeaderPtrRef ptr,
  const char** styleStyleSheetId,
  const char** frameId,
  const char** sourceUrl,
  const char** sourceMapUrl,
  int* origin,
  const char** title,
  int* ownerNode,
  int* disabled,
  int* hasSourceUrl,
  int* isInline,
  int* startLine,
  int* startColumn,
  int* length) {

  automation::CSSStyleSheetHeader* header = reinterpret_cast<automation::CSSStyleSheetHeader*>(ptr);
  *styleStyleSheetId = header->style_sheet_id.data();
  *frameId = header->frame_id.data();
  *sourceUrl = header->source_url.data();
  if (header->source_map_url.has_value()) {
    *sourceMapUrl = header->source_map_url->data();
  }
  *origin = static_cast<int>(header->origin);
  *title = header->title.data();
  *ownerNode = header->owner_node;
  *disabled = header->disabled ? 1 : 0;
  *hasSourceUrl = header->has_source_url ? 1 : 0;
  *isInline = header->is_inline ? 1 : 0;
  *startLine = header->start_line;
  *startColumn = header->start_column;
  *length = header->length;
}

void _AnimationRead(
  AnimationPtrRef ptr, 
  const char** id,
  const char** name,
  int* pausedState,
  const char** playState,
  int* playbackRate,
  int64_t* startTime,
  int64_t* currentTime,
  int* type,
  AnimationEffectPtrRef* source,
  const char** cssId) {

  automation::Animation* anim = reinterpret_cast<automation::Animation*>(ptr);
  *id = anim->id.data();
  *name = anim->name.data();
  *pausedState = anim->paused_state;
  *playState = anim->play_state.data();
  *playbackRate = anim->playback_rate;
  *startTime = anim->start_time;
  *currentTime = anim->current_time;
  *type = static_cast<int>(anim->type);
  if (anim->source) {
    *source = anim->source.get();
  }
  if (anim->css_id) {
    *cssId = anim->css_id->data();
  }
}

void _AnimationEffectRead(
  AnimationEffectPtrRef ptr,
  int* delay,
  int* endDelay,
  int* iterationStart,
  int* iterations,
  int* duration,
  const char** direction,
  const char** fill,
  int* backendNodeId,
  CSSKeyframesRulePtrRef* keyframesRule,
  const char** easing) {

  automation::AnimationEffect* effect = reinterpret_cast<automation::AnimationEffect*>(ptr);
  *delay = effect->delay;
  *endDelay = effect->end_delay;
  *iterationStart = effect->iteration_start;
  *iterations = effect->iterations;
  *duration = effect->duration;
  *direction = effect->direction.data();
  *fill = effect->fill.data();
  *backendNodeId = effect->backend_node_id;
  *keyframesRule = effect->keyframes_rule.get();
  *easing = effect->easing.data();
}

void _KeyframesRuleRead(
  CSSKeyframesRulePtrRef ptr,
  const char** name,
  const char*** offsets,
  const char*** easing,
  int* stylesCount) {

  automation::KeyframesRule* rule = reinterpret_cast<automation::KeyframesRule*>(ptr);
  if (rule->name.has_value()) {
    *name = rule->name->data();
  }
  if (rule->keyframes.size() > 0) {
    *offsets = reinterpret_cast<const char**>(malloc(sizeof(char*) * rule->keyframes.size()));
    *easing = reinterpret_cast<const char**>(malloc(sizeof(char*) * rule->keyframes.size()));
    for (size_t i = 0; i < rule->keyframes.size(); i++) {
      *offsets[i] = rule->keyframes[i]->offset.data();
      *easing[i] = rule->keyframes[i]->easing.data();
    }
  }
  *stylesCount = rule->keyframes.size();
}

void _KeyframesRuleCleanup(
  CSSKeyframesRulePtrRef ptr,
  const char** offsets,
  const char** easing,
  int stylesCount) {
  
  if (stylesCount > 0) {
    free(offsets);
    free(easing);
  }

}

void _NavigationEntryRead(
  NavigationEntryPtrRef ptr,
  int* id,
  const char** url,
  const char** userTypedUrl,
  const char** title,
  int* transitionType) {

  automation::NavigationEntry* entry = reinterpret_cast<automation::NavigationEntry*>(ptr);
  *id = entry->id;
  *url = entry->url.data();
  *userTypedUrl = entry->user_typed_url.data();
  *title = entry->title.data();
  *transitionType = static_cast<int>(entry->transition_type);
}

void _CSSComputedStylePropertyRead(
  CSSComputedStylePropertyPtrRef ptr,
  const char** name,
  const char** value) {

  automation::CSSComputedStyleProperty* prop = reinterpret_cast<automation::CSSComputedStyleProperty*>(ptr);
  *name = prop->name.data();
  *value = prop->value.data();
}

void _PseudoElementMatchesRead(
  PseudoElementMatchesPtrRef ptr,
  int* pseudoType,
  RuleMatchPtrRef** matches,
  int* matchesCount) {

  automation::PseudoElementMatches* pmatches = reinterpret_cast<automation::PseudoElementMatches*>(ptr);
  *pseudoType = static_cast<int>(pmatches->pseudo_type);
  *matchesCount = pmatches->matches.size();
  if (pmatches->matches.size() > 0) {
    *matches = (RuleMatchPtrRef*)malloc(sizeof(RuleMatchPtrRef) * pmatches->matches.size());
    for (size_t i = 0; i < pmatches->matches.size(); i++) {
      *matches[i] = pmatches->matches[i].get();
    }
  }
}

void _PseudoElementMatchesCleanup(
  PseudoElementMatchesPtrRef ptr, 
  RuleMatchPtrRef* matches,
  int matchesCount) {
  if (matchesCount > 0) {
    free(matches);
  }
}

void _InheritedStyleEntryRead(
  InheritedStyleEntryPtrRef ptr,
  CSSStylePtrRef* inlineStyle,
  RuleMatchPtrRef** matches,
  int* matchesCount) {

  automation::InheritedStyleEntry* entry = reinterpret_cast<automation::InheritedStyleEntry*>(ptr);
  *matchesCount = entry->matched_css_rules.size();
  if (entry->matched_css_rules.size() > 0) {
    *matches = (RuleMatchPtrRef*)malloc(sizeof(RuleMatchPtrRef) * entry->matched_css_rules.size());
    for (size_t i = 0; i < entry->matched_css_rules.size(); i++) {
      *matches[i] = entry->matched_css_rules[i].get();
    }
  }
}

void _InheritedStyleEntryCleanup(
  InheritedStyleEntryPtrRef ptr, 
  RuleMatchPtrRef* matches,
  int matchesCount) {
  
  if (matchesCount > 0) {
    free(matches);
  }
}

void _CSSKeyframeRuleRead(
  CSSKeyframeRulePtrRef ptr, 
  const char** styleSheetId,
  int* origin, 
  CSSValuePtrRef* keyText, 
  CSSValuePtrRef* style) {
  automation::CSSKeyframeRule* rule = reinterpret_cast<automation::CSSKeyframeRule*>(ptr);
  if (rule->style_sheet_id) {
    *styleSheetId = rule->style_sheet_id->data();
  }
  *origin = static_cast<int>(rule->origin);
  *keyText = rule->key_text.get();
  *style = rule->style.get();
}

void _CSSKeyframesRuleRead(
  CSSKeyframesRulePtrRef ptr, 
  CSSValuePtrRef* animationName, 
  CSSKeyframeRulePtrRef** keyframes, 
  int* keyframesCount) {

  automation::CSSKeyframesRule* rule = reinterpret_cast<automation::CSSKeyframesRule*>(ptr);
  *animationName = rule->animation_name.get();
  *keyframesCount = 0;
  if (rule->keyframes.size() > 0) {
    *keyframes = (CSSKeyframeRulePtrRef*)malloc(sizeof(CSSKeyframeRulePtrRef) * rule->keyframes.size());
    for (size_t i = 0; i < rule->keyframes.size(); i++) {
      *keyframes[i] = rule->keyframes[i].get();
    }   
  }
}

void _CSSKeyframesRuleCleanup(
  CSSKeyframesRulePtrRef ptr, 
  CSSKeyframeRulePtrRef* keyframes, 
  int keyframesCount) {
  
  if (keyframesCount > 0) {
    free(keyframes);
  }
}

void _CSSMediaQueryExpressionRead(
  CSSMediaQueryExpressionPtrRef ptr,
  int* value,
  const char** unit,
  const char** feature,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn,
  int* computedLength) {

  automation::CSSMediaQueryExpression* query = reinterpret_cast<automation::CSSMediaQueryExpression*>(ptr);
  *value = query->value;
  *unit = query->unit.data();
  *feature = query->feature.data();
  if (query->value_range) {
    *startLine =  query->value_range->start_line;
    *startColumn =  query->value_range->start_column;
    *endLine =  query->value_range->end_line;
    *endColumn =  query->value_range->end_column;
  }
  *computedLength = query->computed_length;
}

void _CSSMediaQueryRead(
  CSSMediaQueryPtrRef ptr,
  CSSMediaQueryExpressionPtrRef** expr,
  int* exprCount,
  int* active) {
  
  automation::CSSMediaQuery* query = reinterpret_cast<automation::CSSMediaQuery*>(ptr);
  *active = query->active ? 1 : 0;
  if (query->expressions.size() > 0) {
    *expr = (CSSMediaQueryExpressionPtrRef*)malloc(sizeof(CSSMediaQueryExpressionPtrRef) * query->expressions.size());
    for (size_t i = 0; i < query->expressions.size(); i++) {
      *expr[i] = query->expressions[i].get();
    }
  }
}

void _CSSMediaQueryCleanup(
  CSSMediaQueryPtrRef ptr, 
  CSSMediaQueryExpressionPtrRef* expr,
  int exprCount) {
  
  if (exprCount > 0) {
    free(expr);
  }
}

void _CSSMediaRead(
  CSSMediaPtrRef ptr,
  int* source,
  const char** text,
  const char** sourceUrl,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn,
  const char** styleSheetId,
  CSSMediaQueryPtrRef** mediaList,
  int* mediaListCount) {

  automation::CSSMedia* media = reinterpret_cast<automation::CSSMedia*>(ptr);
  *source = static_cast<int>(media->source);
  *text = media->text.data();
  *sourceUrl = media->source_url.has_value() ? media->source_url->data() : nullptr;
  if (media->range) {
    *startLine = media->range->start_line;
    *startColumn = media->range->start_line;
    *endLine = media->range->end_line;
    *endColumn = media->range->end_column;
  }
  *styleSheetId = media->style_sheet_id.has_value() ? media->style_sheet_id->data() : nullptr;
  *mediaListCount = media->media_list.has_value() ? media->media_list->size() : 0;
  if (media->media_list.has_value() && media->media_list->size() > 0) {
    *mediaList = (CSSMediaQueryPtrRef *)malloc(sizeof(CSSMediaQueryPtrRef) * media->media_list->size());
    for (size_t i = 0; i < media->media_list->size(); i++) {
      *mediaList[i] = media->media_list.value()[i].get();
    }
  }
}

void _CSSMediaCleanup(
  CSSMediaPtrRef ptr,
  CSSMediaQueryPtrRef* mediaList,
  int mediaListCount) {

  if (mediaListCount > 0) {
    free(mediaList);
  }

}

void _CSSRuleUsageRead(
  CSSRuleUsagePtrRef ptr,
  const char** styleSheetId,
  int* startOffset,
  int* endOffset,
  int* used) {

  automation::CSSRuleUsage* usage = reinterpret_cast<automation::CSSRuleUsage*>(ptr); 
  *styleSheetId = usage->style_sheet_id.data();
  *startOffset = usage->start_offset;
  *endOffset = usage->end_offset;
  *used = usage->used ? 1 : 0;
}

void _CacheRead(
  CachePtrRef ptr,
  const char** cacheId,
  const char** securityOrigin,
  const char** cacheName) {

  automation::Cache* cache = reinterpret_cast<automation::Cache*>(ptr);
  *cacheId = cache->cache_id.data();
  *securityOrigin = cache->security_origin.data();
  *cacheName = cache->cache_name.data();
}

void _FrameWithManifestRead(
  FrameWithManifestPtrRef ptr,
  const char** frameId,
  const char** manifestUrl,
  int* status) {

  automation::FrameWithManifest* frame = reinterpret_cast<automation::FrameWithManifest*>(ptr);
  *frameId = frame->frame_id.data();
  *manifestUrl = frame->manifest_url.data();
  *status = frame->status;
}

void _SelectorListRead(
  SelectorListPtrRef ptr, 
  CSSValuePtrRef** sel,
  int* selCount,
  const char** text) {

  automation::SelectorList* list = reinterpret_cast<automation::SelectorList*>(ptr);
  *text = list->text.data();
  *selCount = 0;
  if (list->selectors.size() > 0) {
    *selCount = list->selectors.size();
    *sel = (CSSValuePtrRef *)malloc(sizeof(CSSValuePtrRef) * list->selectors.size());
    for (size_t i = 0; i < list->selectors.size(); i++) {
      *sel[i] = list->selectors[i].get();
    }
  }
}

void _SelectorListCleanup(
  SelectorListPtrRef ptr, 
  CSSValuePtrRef* sel,
  int selCount) {

  if (selCount > 0) {
    free(sel);
  }
}

void _ApplicationCacheRead(
  ApplicationCachePtrRef ptr, 
  const char** manifestUrl,
  int64_t* size,
  int64_t* creationTime,
  int64_t* updateTime,
  const char*** resourceUrls,
  int** resourceSizes,
  const char*** resourceTypes,
  int* resourceCount) {
  
  automation::ApplicationCache* cache = reinterpret_cast<automation::ApplicationCache*>(ptr);
  *manifestUrl = cache->manifest_url.data();
  *size = cache->size;
  *creationTime = cache->creation_time;
  *updateTime = cache->update_time;
  if (cache->resources.size() > 0) {
    *resourceUrls = (const char**)malloc(sizeof(char*) * cache->resources.size());
    *resourceSizes = (int*)malloc(sizeof(int) * cache->resources.size());
    *resourceTypes = (const char**)malloc(sizeof(char*) * cache->resources.size());
    for (size_t i = 0; i < cache->resources.size(); i++) {
      *resourceUrls[i] = cache->resources[i]->url.data();
      *resourceSizes[i] = cache->resources[i]->size;
      *resourceTypes[i] = cache->resources[i]->type.data();
    }
  }
}

void _ApplicationCacheCleanup(
  ApplicationCachePtrRef ptr, 
  const char** resourceUrls,
  int* resourceSizes,
  const char** resourceTypes,
  int resourceCount) {

  if (resourceCount > 0) {
    free(resourceUrls);
    free(resourceSizes);
    free(resourceTypes);
  }
}

void _PlatformFontUsage(
  PlatformFontUsagePtrRef ptr,
  const char** familyName,
  int* isCustomFont,
  int* glyphCount) {

  automation::PlatformFontUsage* usage = reinterpret_cast<automation::PlatformFontUsage*>(ptr);
  *familyName = usage->family_name.data();
  *isCustomFont = usage->is_custom_font ? 1 : 0;
  *glyphCount = usage->glyph_count;
}

void _DataEntryRead(
  DataEntryPtrRef ptr,
  const char** requestUrl,
  const char** requestMethod,
  const char*** requestHeadersNames,
  const char*** requestHeadersValues,
  int* requestHeadersCount,
  int64_t* responseTime,
  int* responseStatus,
  const char** responseStatusText, 
  const char*** responseHeadersNames,
  const char*** responseHeadersValues,
  int* responseHeadersCount) {

  automation::DataEntry* entry = reinterpret_cast<automation::DataEntry*>(ptr);
  *requestUrl = entry->request_url.data();
  *requestMethod = entry->request_method.data();
  
  *requestHeadersCount = 0;

  if (entry->request_headers.size() > 0) {
    *requestHeadersNames = (const char**) malloc(sizeof(char*) * entry->request_headers.size());
    *requestHeadersValues =(const char**) malloc(sizeof(char*) * entry->request_headers.size());
    for (size_t i = 0; i < entry->request_headers.size(); i++) {
      *requestHeadersNames[i] = entry->request_headers.begin()[i]->name.data();
      *requestHeadersValues[i] = entry->request_headers.begin()[i]->value.data();
    }
    *requestHeadersCount = entry->request_headers.size();
  }
  
  *responseTime = entry->response_time;
  *responseStatus = entry->response_status;
  *responseStatusText =  entry->response_status_text.data();
  
  *responseHeadersCount = 0;

  if (entry->response_headers.size() > 0) {
    *responseHeadersNames = (const char**) malloc(sizeof(char*) * entry->response_headers.size());
    *responseHeadersValues =(const char**) malloc(sizeof(char*) * entry->response_headers.size());
    for (size_t i = 0; i < entry->response_headers.size(); i++) {
      *responseHeadersNames[i] = entry->response_headers.begin()[i]->name.data();
      *responseHeadersValues[i] = entry->response_headers.begin()[i]->value.data();
    }
    *responseHeadersCount = entry->response_headers.size();
  }
}

void _DataEntryCleanup(
  DataEntryPtrRef ptr,
  const char** requestHeadersNames,
  const char** requestHeadersValues,
  int requestHeadersCount,
  const char** responseHeadersNames,
  const char** responseHeadersValues,
  int responseHeadersCount) {

  if (requestHeadersCount > 0) {
    free(requestHeadersNames);
    free(requestHeadersValues);
  }

  if (responseHeadersCount > 0) {
    free(responseHeadersNames);
    free(responseHeadersValues);
  }
}

void _FrameResourceRead(
  FrameResourcePtrRef ptr,
  const char** url,
  int* type,
  const char** mimetype,
  int* lastModified,
  int* contentSize,
  int* failed,
  int* canceled) {
  
  automation::FrameResource* resource = reinterpret_cast<automation::FrameResource*>(ptr);
  *url = resource->url.data();
  *type = static_cast<int>(resource->type);
  *mimetype = resource->mime_type.data();
  *lastModified = resource->last_modified;
  *failed = resource->failed ? 1 : 0;
  *canceled = resource->canceled ? 1 : 0;
}

void _FrameTreeRead(
  FrameTreePtrRef ptr,
  FramePtrRef* frame,
  FrameTreePtrRef** childFrames,
  int* childFramesCount) {

  automation::FrameTree* frame_tree = reinterpret_cast<automation::FrameTree*>(ptr);
  *frame = frame_tree->frame.get();
  *childFramesCount = 0;
  if (frame_tree->child_frames.size()) {
    *childFramesCount = frame_tree->child_frames.size();
    *childFrames = (FrameTreePtrRef *)malloc(sizeof(FrameTreePtrRef) * frame_tree->child_frames.size());
    for (size_t i = 0; i < frame_tree->child_frames.size(); i++) {
      *childFrames[i] = frame_tree->child_frames[i].get();
    }
  }

}

void _FrameTreeCleanup(
  FrameTreePtrRef ptr,
  FrameTreePtrRef* childFrames,
  int childFramesCount) {
  
  if (childFramesCount > 0) {
    free(childFrames);
  }
}

void _FrameResourceTreeRead(
  FrameResourceTreePtrRef ptr,
  FramePtrRef* frame,
  FrameTreePtrRef** childFrames,
  int* childFramesCount,
  FrameResourcePtrRef** resources,
  int* resourcesCount) {

  automation::FrameResourceTree* frame_tree = reinterpret_cast<automation::FrameResourceTree*>(ptr);
  *frame = frame_tree->frame.get();
  *childFramesCount = 0;
  if (frame_tree->child_frames.size()) {
    *childFramesCount = frame_tree->child_frames.size();
    *childFrames = (FrameTreePtrRef *)malloc(sizeof(FrameTreePtrRef) * frame_tree->child_frames.size());
    for (size_t i = 0; i < frame_tree->child_frames.size(); i++) {
      *childFrames[i] = frame_tree->child_frames[i].get();
    }
  }

  *resourcesCount = 0;
  if (frame_tree->resources.size()) {
    *resourcesCount = frame_tree->resources.size();
    *resources = (FrameResourcePtrRef *)malloc(sizeof(FrameResourcePtrRef) * frame_tree->resources.size());
    for (size_t i = 0; i < frame_tree->resources.size(); i++) {
      *resources[i] = frame_tree->resources[i].get();
    }
  }

}
    
void _FrameResourceTreeCleanup(
  FrameResourceTreePtrRef ptr,
  FrameTreePtrRef* childFrames,
  int childFramesCount,
  FrameResourcePtrRef* resources,
  int resourcesCount) {
  
  if (childFramesCount > 0) {
    free(childFrames);
  }
  
  if (resourcesCount > 0) {
    free(resources);
  }
  
}

BlobDataRef BlobDataCreate() {
  BlobDataState* state = new BlobDataState();
  state->ptr = blink::BlobData::Create();
  return state;
}

BlobDataRef BlobDataCreateForFile(const char* path) {
  BlobDataState* state = new BlobDataState();
  state->ptr = blink::BlobData::CreateForFileWithUnknownSize(String::FromUTF8(path));
  return state;
}

BlobDataRef BlobDataCreateForFilesystemUrl(const char* url) {
  BlobDataState* state = new BlobDataState();
  state->ptr = blink::BlobData::CreateForFileSystemURLWithUnknownSize(blink::KURL(url), -1);
  return state;
}

void BlobDataDestroy(BlobDataRef reference) {
  delete reinterpret_cast<BlobDataState*>(reference);
}

char* BlobDataGetContentType(BlobDataRef reference, int* len) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  // when used in CacheStoragePutEntry, the BlobData is transfered to the BlobHandle
  // so if someone calls this after this event, it will be null
  if (!state->ptr) {
    return nullptr;
  }
  String str = state->ptr->ContentType();
  *len = str.length();
  if (str.length() > 0) {
    char* result = reinterpret_cast<char *>(malloc(str.length()));
    memcpy(result, str.Utf8().data(), str.length());
    return result;
  }
  return nullptr;
}

void BlobDataSetContentType(BlobDataRef reference, const char* content_type) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  // when used in CacheStoragePutEntry, the BlobData is transfered to the BlobHandle
  // so if someone calls this after this event, it will be null
  if (!state->ptr) {
    return;
  }
  state->ptr->SetContentType(String::FromUTF8(content_type));
}

uint64_t BlobDataGetLength(BlobDataRef reference) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  if (!state->ptr) {
    return 0;
  }
  return state->ptr->length();
}

void BlobDataAppendBytes(BlobDataRef reference, const void* data, size_t length) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  if (!state->ptr) {
    return;
  }
  state->ptr->AppendBytes(data, length);
}

void BlobDataAppendFile(BlobDataRef reference, 
                        const char* path,
                        long long offset,
                        long long length,
                        double expected_modification_time) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  if (!state->ptr) {
    return;
  }
  state->ptr->AppendFile(String::FromUTF8(path), offset, length, expected_modification_time);
}

void BlobDataAppendFileSystemURL(BlobDataRef reference, 
                                 const char* url,
                                 long long offset,
                                 long long length,
                                 double expected_modification_time) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  if (!state->ptr) {
    return;
  }
  state->ptr->AppendFileSystemURL(
    blink::KURL(String::FromUTF8(url)), 
    offset,
    length,
    expected_modification_time);
}

void BlobDataAppendText(BlobDataRef reference, const char* text, int normalize_line_endings_to_native) {
  BlobDataState* state = reinterpret_cast<BlobDataState*>(reference);
  if (!state->ptr) {
    return;
  }
  state->ptr->AppendText(String::FromUTF8(text), normalize_line_endings_to_native != 0);
}