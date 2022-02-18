// Copyright (c) 2019 World. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import WorldApi
import Foundation
import Base
import Net
import Engine
import Collection
import Channel
import Data
import SwiftGlibc
import Route
import Graphics
import Web
import Python
import PDF

internal class WorldProviderImpl : world_WorldProvider {

  public var routes: RouteManager {
    return context!.routes
  }

  private weak var context: WorldContext?
  //private var serviceWorkerClient: ServiceWorkerClient
  private var wasActivate: Bool = false

  init(context: WorldContext) {
    self.context = context
    
    let routeMap = makeRoutes {
      Route("/main", { return MainHandler(context: context) })
      Route("/new", { return NewHandler(context: context) })
      Route("/devtools", { return DevToolsHandler(context: context) })
    }

    //serviceWorkerClient = ServiceWorkerClient(context: context)
    //context.serviceWorkerContextClient = ServiceWorkerContextClientImpl(delegate: serviceWorkerClient)
    routes.bind(routeMap)
  }

  public func routeHandler(for route: String) -> RouteHandler? {
    return routes[route]?.handler
  }

  func version(callId: Int, request: World.VersionInfo, session: world_WorldVersionSession) throws -> ServerStatus? {
    print("WorldProvider.version")
    return .ok
  }

}