// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Web
import Javascript

public protocol UIWebFrameObserver : class {
  func didMeaningfulLayout(frame: UIWebFrame, layout: WebMeaningfulLayout)
  func didStartNavigation(frame: UIWebFrame)
  func didStartLoading(frame: UIWebFrame, toDifferentDocument: Bool)
  func didStopLoading(frame: UIWebFrame)
  func didFailProvisionalLoad(frame: UIWebFrame)
  func didChangeScrollOffset(frame: UIWebFrame)
  func onStop(frame: UIWebFrame)
  func frameDetached(frame: UIWebFrame)
  func frameFocused(frame: UIWebFrame)
  func didStartNavigation(frame: UIWebFrame, url: String, type: WebNavigationType?)
  func didReceiveResponse(frame: UIWebFrame, response: WebURLResponse)
  func didCreateNewDocument(frame: UIWebFrame)
  func didCreateDocumentElement(frame: UIWebFrame)
  func didClearWindowObject(frame: UIWebFrame)
  func didFinishDocumentLoad(frame: UIWebFrame)
  func didFinishLoad(frame: UIWebFrame)
  func didFailLoad(frame: UIWebFrame, error: WebURLError)
  func didHandleOnloadEvents(frame: UIWebFrame)
  func didCreateScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int)
  func willReleaseScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int)
  func willSendRequest(frame: UIWebFrame, request: WebURLRequest)
  func readyToCommitNavigation(frame: UIWebFrame, loader: WebDocumentLoader)
  func willCommitProvisionalLoad(frame: UIWebFrame)
  func onWasShown(frame: UIWebFrame)
  func onWasHidden(frame: UIWebFrame)
  func didInvalidateRect(frame: UIWebFrame, rect: IntRect)
  func didChangeName(frame: UIWebFrame, name: String)
  func didChangeLoadProgress(frame: UIWebFrame, loadProgress: Double)
  func didChangeContents(frame: UIWebFrame)
  func runScriptsAtDocumentElementAvailable(frame: UIWebFrame)
  func runScriptsAtDocumentReady(frame: UIWebFrame)
  func runScriptsAtDocumentIdle(frame: UIWebFrame)
  func focusedNodeChanged(frame: UIWebFrame, node: WebNode?)
}

extension UIWebFrameObserver {
  public func didMeaningfulLayout(frame: UIWebFrame, layout: WebMeaningfulLayout) {}
  public func didStartNavigation(frame: UIWebFrame) {}
  public func didStartLoading(frame: UIWebFrame, toDifferentDocument: Bool) {}
  public func didStopLoading(frame: UIWebFrame) {}
  public func didReceiveResponse(frame: UIWebFrame, response: WebURLResponse) {}
  public func didFailProvisionalLoad(frame: UIWebFrame) {}
  public func didChangeScrollOffset(frame: UIWebFrame) {}
  public func onStop(frame: UIWebFrame) {}
  public func frameDetached(frame: UIWebFrame) {}
  public func frameFocused(frame: UIWebFrame) {}
  public func didStartNavigation(frame: UIWebFrame, url: String, type: WebNavigationType?) {}
  public func didCreateNewDocument(frame: UIWebFrame) {}
  public func didCreateDocumentElement(frame: UIWebFrame) {}
  public func didClearWindowObject(frame: UIWebFrame) {}
  public func didFinishDocumentLoad(frame: UIWebFrame) {}
  public func didFinishLoad(frame: UIWebFrame) {}
  public func didFailLoad(frame: UIWebFrame, error: WebURLError) {}
  public func didHandleOnloadEvents(frame: UIWebFrame) {}
  public func didCreateScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
  public func willReleaseScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
  public func readyToCommitNavigation(frame: UIWebFrame, loader: WebDocumentLoader) {}
  public func willCommitProvisionalLoad(frame: UIWebFrame) {}
  public func willSendRequest(frame: UIWebFrame, request: WebURLRequest) {}
  public func onWasShown(frame: UIWebFrame) {}
  public func onWasHidden(frame: UIWebFrame) {}
  public func didInvalidateRect(frame: UIWebFrame, rect: IntRect) {}
  public func didChangeName(frame: UIWebFrame, name: String) {}
  public func didChangeLoadProgress(frame: UIWebFrame, loadProgress: Double) {}
  public func didChangeContents(frame: UIWebFrame) {}
  public func runScriptsAtDocumentElementAvailable(frame: UIWebFrame) {}
  public func runScriptsAtDocumentReady(frame: UIWebFrame) {}
  public func runScriptsAtDocumentIdle(frame: UIWebFrame) {}
  public func focusedNodeChanged(frame: UIWebFrame, node: WebNode?) {}
}