// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Route

public class RouteManager {

  public private(set) var routes: [String: Route]

  public var count: Int {
    return routes.count
  }

  private var routeRegistry: RouteRegistry

  public init(routeRegistry: RouteRegistry) {
    self.routeRegistry = routeRegistry
    routes = [:]
  }

  public subscript(_ name: String) -> Route? {
    return routes[name]
  }
  
  public func route(at path: String) -> Route? {
    return routes[path]
  }

  public func handler(at path: String) -> RouteHandler? {
    return routes[path]?.handler
  }

  public func bind(_ path: String, _ route: Route) {
    var localRoute = route
    localRoute.entry.path = path
    routes[path] = localRoute
    routeRegistry.addRoute(localRoute.entry)
  }

  public func bind(_ path: String, _ handler: RouteHandler) {
    var route = Route(handler)
    route.entry.path = path
    routes[path] = route
    routeRegistry.addRoute(route.entry)
  }

  public func bind(_ route: Route) {
    routes[route.path] = route
    routeRegistry.addRoute(route.entry)
  }

  public func bind(_ routes: [Route]) {
    for route in routes {
      bind(route)
    }
  }

}
