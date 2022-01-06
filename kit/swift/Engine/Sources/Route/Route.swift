// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Route

public typealias RouteHandlerFactoryFn = () -> RouteHandler


public struct Route {

  public var entry: RouteEntry {
    get {
      return handler.entry
    } 
    set {
      handler.entry = newValue
    }
  }  

  public var type: RouteEntryType {
    return handler.type
  }

  public var url: String {
    return handler.url
  }
  
  public var path: String {
    return handler.path
  }

  public var transportType: RouteTransportType {
    return handler.transportType
  }

  public var rpcTransportMode: RouteRpcTransportMode {
    return handler.rpcTransportMode
  }
  
  public var name: String {
    return handler.name
  }

  public var scheme: String {
    return handler.scheme
  }
  
  public var title: String {
    return handler.title 
  }

  public var contentType: String {
    return handler.contentType
  }

  public var iconData: Data {
    return handler.iconData
  }

  public var handler: RouteHandler

  public init(_ handlerFactory: RouteHandlerFactoryFn) {
    self.handler = handlerFactory()
  }

  public init(_ path: String, _ handlerFactory: RouteHandlerFactoryFn) {
    self.handler = handlerFactory()
    self.handler.path = path
  }

  public init(_ handler: RouteHandler) {
    self.handler = handler
  }

  public init(_ path: String, _ handler: RouteHandler) {
    self.handler = handler
    self.handler.path = path
  }

}

extension Route : Hashable {

  public static func == (lhs: Route, rhs: Route) -> Bool {
    return lhs.type == rhs.type && 
           lhs.transportType == rhs.transportType && 
           lhs.scheme == rhs.scheme && 
           lhs.name == rhs.name && 
           lhs.rpcTransportMode == rhs.rpcTransportMode &&
           lhs.path == rhs.path && 
           lhs.title == rhs.title && 
           lhs.url == rhs.url && 
           lhs.contentType == rhs.contentType && 
           lhs.iconData == rhs.iconData
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(type)
    hasher.combine(transportType)
    hasher.combine(rpcTransportMode)
    hasher.combine(scheme)
    hasher.combine(name)
    hasher.combine(path)
    hasher.combine(url)
    hasher.combine(title)
    hasher.combine(contentType)
    hasher.combine(iconData)
  }
}