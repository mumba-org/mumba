// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base
import Javascript
import Graphics

public enum WebFrameDetachType : Int { 
    case Remove = 0
    case Swap
}

public enum WebFrameSuddenTerminationDisablerType : Int {
    case BeforeUnloadHandler = 0
    case UnloadHandler
}
    
public struct WebFrameNavigationPolicyInfo {

    var extraData: WebDataSourceExtraData?
    var urlRequest: WebURLRequest
    var navigationType: WebNavigationType
    var defaultPolicy: WebNavigationPolicy
    var replacesCurrentHistoryItem: Bool

    public init(urlRequest: WebURLRequest) {
        self.urlRequest = urlRequest
        navigationType = WebNavigationType.Other
        defaultPolicy = WebNavigationPolicy.Ignore
        replacesCurrentHistoryItem = false
    }
}


public protocol WebFrameClient : class {
    func frameDetached(type: WebFrameDetachType)
    func didChangeOpener(opener: WebFrame?)
    func frameFocused()
}
