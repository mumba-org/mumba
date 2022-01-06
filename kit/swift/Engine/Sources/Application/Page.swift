// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

/*
 * Note: This is what we should use to fill 
 *       the rpc method call with the contents
 *       of a instantiated (somehow) page
 *
 *       The page can be used as intermediate state
 *       between the data model (persistent storage and/or heap)
 *       and the state being commited to the application/renderer
 *
 * TODO: see how can we have page events between
 *       the application process and this process
 *       using the webkit inspector protocol as inspiration
 *
 *       Example: is it being viewed by the user (visible) or hidden ?
 *
 *       Also this should serve as a 'sink' to page content
 */

public struct PageContent {
  // the real data (in memory)
  // TODO: we should consider also wrapping SharedMemory and mmaped
  //       buffers.. so in the future we should consider to create
  //       more than one implementation of this
  public var data: ByteBuffer?
  // signal if this content is considered to be dirty
  // considering the content being showed in the application process
  public var dirty: Bool = false
}

public enum PageVisibility {
  case None
  case Visible
  case Hidden
}

public class Page: ApplicationEntry {

  public var contentAsString: String {
    return readContentToString()
  }

  public var isVisible: Bool {
    return visibility == PageVisibility.Visible
  }

  public var isHidden: Bool {
    return visibility == PageVisibility.Hidden
  }
  
  public private(set) var content: PageContent
  public private(set) var visibility: PageVisibility
  public private(set) var bounds: IntRect

  public init(instance: ApplicationInstance?, uuid: String) {
    content = PageContent()
    visibility = PageVisibility.None
    bounds = IntRect()
    
    super.init(instance: instance, uuid: uuid, kind: .Page)
  }

  public init(instance: ApplicationInstance?, uuid: String, withString: String) {
    content = PageContent()
    visibility = PageVisibility.None
    bounds = IntRect()
    
    super.init(instance: instance, uuid: uuid, kind: .Page)
  }

  public init(instance: ApplicationInstance?, uuid: String, withBytes: [UInt8]) {
    content = PageContent()
    visibility = PageVisibility.None
    bounds = IntRect()
    
    super.init(instance: instance, uuid: uuid, kind: .Page)  
  }

  public init(instance: ApplicationInstance?, uuid: String, withBuffer: ByteBuffer) {
    content = PageContent()
    visibility = PageVisibility.None
    bounds = IntRect()
    
    super.init(instance: instance, uuid: uuid, kind: .Page)
  }

  public func read() -> ByteBuffer? {
    return nil
  }

  public func read(at: Int64) -> ByteBuffer? {
    return nil
  }

  public func read(at: Int64, size: Int64) -> ByteBuffer? {
    return nil
  }

  public func readBytes(_ bytes: inout [UInt8]) -> Int64 {
    return 0
  }

  public func readBytes(at: Int64, _ bytes: inout [UInt8]) -> Int64 {
    return 0
  }

  public func readBytes(at: Int64, size: Int64, _ bytes: inout [UInt8]) -> Int64 {
    return 0
  }

  public func writeBytes(_ bytes: [UInt8]) -> Int64 {
    return 0
  }

  public func writeBytes(at: Int64, _ bytes: [UInt8]) -> Int64 {
    return 0
  }

  public func writeBytes(at: Int64, size: Int64, _ bytes: [UInt8]) -> Int64 {
    return 0
  }
 
  // commit page content that are out-of-sync (dirty)
  // with the application process 
  public func commit() {

  }

  public func refresh() {

  }

  private func readContentToString() -> String {
    return String()
  }

  public func onApplicationStateChanged(oldState: ApplicationState, newState: ApplicationState) {

  }

  public func onBoundsChanged(bounds: IntRect) {

  }

  public func onVisible() {
    
  }
  
  public func onHidden() {

  }

}