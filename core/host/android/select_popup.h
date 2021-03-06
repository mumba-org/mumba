// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_SELECT_POPUP_H_
#define CONTENT_BROWSER_ANDROID_SELECT_POPUP_H_

#include <jni.h>

#include "base/android/jni_weak_ref.h"
#include "base/android/scoped_java_ref.h"
#include "ui/android/view_android.h"

namespace gfx {
class Rect;
}

namespace host {

class RenderFrameHost;
class WebContentsImpl;
struct MenuItem;

class SelectPopup {
 public:
  SelectPopup(JNIEnv* env,
              const base::android::JavaParamRef<jobject>& obj,
              WebContentsImpl* web_contents);
  base::android::ScopedJavaLocalRef<jobject> GetWindowAndroid(
      JNIEnv* env,
      const base::android::JavaParamRef<jobject>& obj);
  ~SelectPopup();

  // Creates a popup menu with |items|.
  // |multiple| defines if it should support multi-select.
  // If not |multiple|, |selected_item| sets the initially selected item.
  // Otherwise, item's "checked" flag selects it.
  void ShowMenu(RenderFrameHost* frame,
                const gfx::Rect& bounds,
                const std::vector<MenuItem>& items,
                int selected_item,
                bool multiple,
                bool right_aligned);
  // Hides a visible popup menu.
  void HideMenu();

  // Notifies that items were selected in the currently showing select popup.
  void SelectMenuItems(JNIEnv* env,
                       const base::android::JavaParamRef<jobject>& obj,
                       jlong selectPopupSourceFrame,
                       const base::android::JavaParamRef<jintArray>& indices);

 private:
  WebContentsImpl* web_contents_;
  JavaObjectWeakGlobalRef java_obj_;

  // Select popup view
  ui::ViewAndroid::ScopedAnchorView popup_view_;
};

}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_SELECT_POPUP_H_
