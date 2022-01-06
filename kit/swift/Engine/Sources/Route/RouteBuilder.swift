// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

@_functionBuilder
public struct RouteBuilder {
  public static func buildBlock(_ components: Route...) -> [Route] { components }
}

public func makeRoutes(@RouteBuilder _ content: () -> [Route]) -> [Route] {
  content()
}