// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public typealias WebSharedWorkerConnector = Int

public protocol WebSharedWorkerRepositoryClient {
    typealias DocumentID = UInt64

    func createSharedWorkerConnector(url: String, 
      name: String, 
      id: DocumentID, 
      contentSecurityPolicy: String, 
      type: WebContentSecurityPolicyType) -> WebSharedWorkerConnector?
    
    func documentDetached(id: DocumentID)
}