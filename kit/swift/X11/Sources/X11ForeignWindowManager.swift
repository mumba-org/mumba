// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class X11ForeignWindowManager {
  
  public static let instance: X11ForeignWindowManager = X11ForeignWindowManager()
  
  public class Request {
    var requestId: Int
    var eventMask: Int
    
    public init(requestId: Int, eventMask: Int) {
      self.requestId = requestId
      self.eventMask = eventMask
    }
  }
  
  typealias RequestArray = [Request]
  var requestMap: [XID: RequestArray]
  // The id of the next request.
  var nextRequestId: Int
  
  public init() {
    requestMap = [XID: RequestArray]()
    nextRequestId = 0
  }  
  
  public func requestEvents(xid: XID, eventMask: Int) -> Int {
    if requestMap[xid] == nil {
      requestMap[xid] = RequestArray()
    }
    requestMap[xid]!.append(Request(requestId: nextRequestId, eventMask: eventMask))
    nextRequestId = nextRequestId + 1
    updateSelectedEvents(xid: xid)
    return nextRequestId
  }

  public func cancelRequest(requestId: Int) {
    for (xid, var requestArr) in requestMap {
      for (index, req) in requestArr.enumerated() {
       if requestId == req.requestId {
          requestArr.remove(at: index)
          updateSelectedEvents(xid: xid)
          if requestArr.isEmpty {
            requestMap.removeValue(forKey: xid)
          }
          return
        } 
      }
    }
  }

  public func onWindowDestroyed(xid: XID) {
    requestMap.removeAll()
  }
  
  func updateSelectedEvents(xid: XID) {
    var eventMask = NoEventMask
    var found = false
    
    for (rid, requestArr) in requestMap {
      if rid == xid {
        found = true
        for req in requestArr {
          eventMask |= req.eventMask
        }
        break
      } 
    }
    
    if found {
      XSelectInput(X11Environment.XDisplay, xid, eventMask)
    }
    
  }


}