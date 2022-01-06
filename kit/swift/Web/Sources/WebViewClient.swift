// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
//import Base
import Base

public protocol WebViewClient : WebWidgetClient {
  
  var acceptLanguages: String { get }
  var acceptsLoadDrops: Bool { get }
  var historyBackListCount: Int { get }
  var historyForwardListCount: Int { get }
  var canHandleGestureEvent: Bool { get }
  var canUpdateLayout: Bool { get }
  var sessionStorageNamespaceId: String { get }
  var rootWindowRect: IntRect { get }

  func makeView(creator: WebFrame?,
                request: WebURLRequest,
                features: WebWindowFeatures,
                name: String,
                policy: WebNavigationPolicy,
                suppressOpener: Bool) -> WebView?
 
  func makePopup(creator: WebFrame?, type: WebPopupType) -> WebView?
 
  func printPage(frame: WebFrame)
  func enumerateChosenDirectory(path: String, completion: WebFileChooserCompletion?) -> Bool
  func openDateTimeChooser(params: WebDateTimeChooserParams, completion: WebDateTimeChooserCompletion?) -> Bool 
  func pageImportanceSignalsChanged()
  func setMouseOverURL(url: String)
  func setKeyboardFocusURL(url: String)
  func focusNext()
  func focusPrevious()
  func focusedNodeChanged(from: WebNode?, to: WebNode?)
  func didUpdateLayout() 
  func didAutoResize(size: IntSize)
  func didFocus(callingFrame: WebFrame)
  func didTapMultipleTargets(visualViewportOffset: IntSize, touchRect: IntRect, targetRects: [IntRect]) -> Bool
  func navigateBackForwardSoon(offset: Int)
  func didUpdateInspectorSettings()
  func didUpdateInspectorSetting(key: String, value: String)
  func zoomLimitsChanged(minimumLevel: Double, maximumLevel: Double)
  func pageScaleFactorChanged()
  func convertViewportToWindow(_: inout IntRect)
  func convertWindowToViewport(_: inout FloatRect)
}

extension WebViewClient {
  
  public func makeView(creator: WebFrame?,
                       request: WebURLRequest,
                       features: WebWindowFeatures,
                       name: String,
                       policy: WebNavigationPolicy,
                       suppressOpener: Bool) -> WebView? {
   // TODO: pass parameters 
   //let handle = _WebViewCreate()
   //return WebView(reference: handle!)
   return nil
  }

}