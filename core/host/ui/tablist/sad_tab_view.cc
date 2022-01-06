// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/sad_tab_view.h"

#include <string>

#include "base/metrics/histogram_macros.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "mumba/app/vector_icons/vector_icons.h"
#include "core/host/ui/dock_finder.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/layout/bulleted_label_list_view.h"
#include "core/host/ui/layout/dock_layout_provider.h"
#include "core/host/ui/layout/dock_typography.h"
#include "core/host/ui/application_view.h"
#include "core/host/ui/tablist/tablist.h"
//#include "core/host/ui/views_mode_controller.h"
#include "core/host/application/application_contents.h"
#include "ui/accessibility/ax_enums.mojom.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/gfx/color_palette.h"
#include "ui/gfx/paint_vector_icon.h"
#include "ui/native_theme/common_theme.h"
#include "ui/native_theme/native_theme.h"
#include "ui/views/accessibility/view_accessibility.h"
#include "ui/views/background.h"
#include "ui/views/controls/button/md_text_button.h"
#include "ui/views/controls/image_view.h"
#include "ui/views/controls/label.h"
#include "ui/views/controls/link.h"
//#include "ui/views/controls/webview/webview.h"
#include "ui/views/layout/grid_layout.h"
#include "ui/views/widget/widget.h"

namespace host {

namespace {

constexpr int kMaxContentWidth = 600;
constexpr int kMinColumnWidth = 120;
constexpr int kTitleBottomSpacing = 13;

views::Label* CreateFormattedLabel(const base::string16& message) {
  views::Label* label =
      new views::Label(message, views::style::CONTEXT_LABEL, STYLE_SECONDARY);

  label->SetMultiLine(true);
  label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  label->SetLineHeight(DockLayoutProvider::Get()->GetDistanceMetric(
      views::DISTANCE_UNRELATED_CONTROL_VERTICAL));
  return label;
}

}  // namespace

// static
const char SadTabView::kViewClassName[] = "SadTabView";

SadTabView::SadTabView(ApplicationContents* app_contents, SadTabKind kind)
    : SadTab(app_contents, kind) {
  // This view gets inserted as a child of a WebView, but we don't want the
  // WebView to delete us if the WebView gets deleted before the SadTabHelper
  // does.
  set_owned_by_client();

  SetBackground(views::CreateThemedSolidBackground(
      this, ui::NativeTheme::kColorId_DialogBackground));

  views::GridLayout* layout =
      SetLayoutManager(std::make_unique<views::GridLayout>(this));

  const int column_set_id = 0;
  views::ColumnSet* columns = layout->AddColumnSet(column_set_id);

  // TODO(ananta)
  // This view should probably be styled as web UI.
  DockLayoutProvider* provider = DockLayoutProvider::Get();
  const int unrelated_horizontal_spacing = provider->GetDistanceMetric(
          DISTANCE_UNRELATED_CONTROL_HORIZONTAL);
  columns->AddPaddingColumn(1, unrelated_horizontal_spacing);
  columns->AddColumn(views::GridLayout::LEADING, views::GridLayout::LEADING, 0,
                     views::GridLayout::USE_PREF, 0, kMinColumnWidth);
  columns->AddColumn(views::GridLayout::TRAILING, views::GridLayout::LEADING, 0,
                     views::GridLayout::USE_PREF, 0, kMinColumnWidth);
  columns->AddPaddingColumn(1, unrelated_horizontal_spacing);

  views::ImageView* image = new views::ImageView();

  image->SetImage(
      gfx::CreateVectorIcon(kCrashedTabIcon, 48, gfx::kChromeIconGrey));

  const int unrelated_vertical_spacing_large = provider->GetDistanceMetric(
      DISTANCE_UNRELATED_CONTROL_VERTICAL_LARGE);
  layout->AddPaddingRow(1, unrelated_vertical_spacing_large);
  layout->StartRow(0, column_set_id);
  layout->AddView(image, 2, 1);

  title_ = new views::Label(l10n_util::GetStringUTF16(GetTitle()));
  ui::ResourceBundle& rb = ui::ResourceBundle::GetSharedInstance();
  title_->SetFontList(rb.GetFontList(ui::ResourceBundle::LargeFont));
  title_->SetMultiLine(true);
  title_->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  layout->StartRowWithPadding(0, column_set_id, 0,
      unrelated_vertical_spacing_large);
  layout->AddView(title_, 2, 1);

  message_ = CreateFormattedLabel(l10n_util::GetStringUTF16(GetMessage()));
  layout->StartRowWithPadding(0, column_set_id, 0, kTitleBottomSpacing);
  layout->AddView(message_, 2, 1, views::GridLayout::LEADING,
                  views::GridLayout::LEADING);

  std::vector<int> bullet_string_ids = GetSubMessages();
  if (!bullet_string_ids.empty()) {
    auto list_view = std::make_unique<BulletedLabelListView>();
    for (const auto& id : bullet_string_ids)
      list_view->AddLabel(l10n_util::GetStringUTF16(id));

    layout->StartRow(0, column_set_id);
    layout->AddView(list_view.release(), 2, 1);
  }

  action_button_ = views::MdTextButton::CreateSecondaryUiBlueButton(
      this, l10n_util::GetStringUTF16(GetButtonTitle()));
  help_link_ = new views::Link(l10n_util::GetStringUTF16(GetHelpLinkTitle()));
  help_link_->set_listener(this);
  layout->StartRowWithPadding(0, column_set_id, 0,
      unrelated_vertical_spacing_large);
  layout->AddView(help_link_, 1, 1, views::GridLayout::LEADING,
                  views::GridLayout::CENTER);
  layout->AddView(action_button_, 1, 1, views::GridLayout::TRAILING,
                  views::GridLayout::LEADING);

  layout->AddPaddingRow(2, provider->GetDistanceMetric(
                               views::DISTANCE_UNRELATED_CONTROL_VERTICAL));

  // Needed to ensure this View is drawn even if a sibling (such as dev tools)
  // has a z-order.
  SetPaintToLayer();

  AttachToApplicationView();

  // Make the accessibility role of this view an alert dialog, and
  // put focus on the action button. This causes screen readers to
  // immediately announce the text of this view.
  GetViewAccessibility().OverrideRole(ax::mojom::Role::kDialog);
  action_button_->RequestFocus();
}

SadTabView::~SadTabView() {
  if (owner_)
    owner_->SetCrashedOverlayView(nullptr);
}

void SadTabView::ReinstallInApplicationView() {
  if (owner_) {
    owner_->SetCrashedOverlayView(nullptr);
    owner_ = nullptr;
  }
  AttachToApplicationView();
}

void SadTabView::AttachToApplicationView() {
  Dock* dock = host::FindDockWithApplicationContents(application_contents());
  // This can be null during prefetch.
  if (!dock)
    return;

  // In unit tests, browser->window() might not be a real BrowserView.
  if (!dock->window()->GetNativeWindow())
    return;

  DockWindow* dock_view = DockWindow::GetDockWindowForDock(dock);
  DCHECK(dock_view);

  ApplicationView* app_view = dock_view->application_view();
  if (app_view->GetApplicationContents() == application_contents()) {
    owner_ = app_view;
    owner_->SetCrashedOverlayView(this);
    // this is not the proper place for that (controller?)
    // but we need to make the tab view aware of the crash too
    // FIXME: find a proper place as this is not 'SadTabView' related
    int tab_index = dock->tablist_model()->GetIndexOfApplicationContents(application_contents());
    dock_view->tablist()->SetTabIsCrashed(tab_index);
  }
}

void SadTabView::LinkClicked(views::Link* source, int event_flags) {
  PerformAction(Action::HELP_LINK);
}

void SadTabView::ButtonPressed(views::Button* sender,
                               const ui::Event& event) {
  DCHECK_EQ(action_button_, sender);
  PerformAction(Action::BUTTON);
}

void SadTabView::Layout() {
  // Specify the maximum message width explicitly.
  const int max_width =
      std::min(width() - DockLayoutProvider::Get()->GetDistanceMetric(
          DISTANCE_UNRELATED_CONTROL_HORIZONTAL) * 2, kMaxContentWidth);

  message_->SizeToFit(max_width);
  title_->SizeToFit(max_width);

  View::Layout();
}

const char* SadTabView::GetClassName() const {
  return kViewClassName;
}

void SadTabView::OnPaint(gfx::Canvas* canvas) {
  if (!painted_) {
    RecordFirstPaint();
    painted_ = true;
  }
  View::OnPaint(canvas);
}

void SadTabView::RemovedFromWidget() {
  owner_ = nullptr;
}

SadTab* SadTab::Create(ApplicationContents* app_contents,
                       SadTabKind kind) {
#if defined(OS_MACOSX)
  if (views_mode_controller::IsViewsBrowserCocoa())
    return CreateCocoa(app_contents, kind);
#endif
  return new SadTabView(app_contents, kind);
}

}