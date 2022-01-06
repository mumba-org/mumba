// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct WebURLError {
    public var domain: String
    public var reason: Int32
    public var staleCopyInCache: Bool
    public var isCancellation: Bool
    public var wasIgnoredByHandler: Bool
    public var unreachableURL: String?
    public var localizedDescription: String

    public init() {
    	domain = String()
    	reason = 0
    	staleCopyInCache = false
    	isCancellation = false
    	wasIgnoredByHandler = false
    	localizedDescription = String()
    }

     public init(
     	domain: String, 
     	reason: Int32, 
     	staleCopyInCache: Bool, 
     	isCancellation: Bool, 
     	wasIgnoredByHandler: Bool, 
     	unreachableURL: String, 
     	localizedDescription: String) {
    	
    	self.domain = domain
    	self.reason = reason
    	self.staleCopyInCache = staleCopyInCache
    	self.isCancellation = isCancellation
    	self.wasIgnoredByHandler = wasIgnoredByHandler
        self.unreachableURL = unreachableURL
    	self.localizedDescription = localizedDescription
    }
}