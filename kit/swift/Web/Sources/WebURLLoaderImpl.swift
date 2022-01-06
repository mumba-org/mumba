// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebURLLoaderImpl : WebURLLoader {
	
	public var unmanagedSelf: UnsafeMutableRawPointer? {
	  return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
	}

	private let request: WebURLRequest

	public init(request: WebURLRequest) {
	  self.request = request
	}

	public func loadSynchronously(
	  request: WebURLRequest,
	  response: WebURLResponse,
	  error: WebURLError?,
	  data: WebData,
	  encodedDataLength: Int64,
	  encodedBodyLength: Int64,
	  downloadedFileLength: Int64?,
	  downloadedBlob: WebBlobInfo) {
      //print("WebURLLoaderImpl.loadSynchronously")
	}

	public func loadAsynchronously(
		request: WebURLRequest,
	    client: WebURLLoaderClient) {
      //print("WebURLLoaderImpl.loadAsynchronously")
	}

	public func cancel() {
	  print("WebURLLoaderImpl.cancel")
	}

	public func setDefersLoading(_ defers: Bool) {
      //print("WebURLLoaderImpl.setDefersLoading: \(defers)")
	}

	public func didChangePriority(newPriority: WebURLRequest.Priority,
	                              intraPriorityValue: Int) {
      //print("WebURLLoaderImpl.didChangePriority")
	}

	public func createCallbacks() -> CBlinkPlatformCallbacks {
	  var callbacks = CBlinkPlatformCallbacks()
	  memset(&callbacks, 0, MemoryLayout<CBlinkPlatformCallbacks>.stride)

	  //void (*URLLoaderLoadAsynchronously)(void* state)
	  callbacks.URLLoaderLoadAsynchronously = { (handle: UnsafeMutableRawPointer?) in
	  	//let loader = unsafeBitCast(handle, to: WebURLLoaderImpl.self)
	  	//loader.loadAsynchronously()
	  }
  	  
  	  //void (*URLLoaderLoadSynchronously)(void* state)
  	callbacks.URLLoaderLoadSynchronously = { (handle: UnsafeMutableRawPointer?) in
	  	//let loader = unsafeBitCast(handle, to: WebURLLoaderImpl.self)
	  	//loader.loadSynchronously()
	  }
  	  
  	  //void (*URLLoaderCancel)(void* state)
  	callbacks.URLLoaderCancel = { (handle: UnsafeMutableRawPointer?) in
	  	//let loader = unsafeBitCast(handle, to: WebURLLoaderImpl.self)
	  	//loader.cancel()
	  }
  	  
  	  //void (*URLLoaderSetDefersLoading)(void* state, int defers)
  	callbacks.URLLoaderSetDefersLoading = { (handle: UnsafeMutableRawPointer?, defers: CInt) in
	  	//let loader = unsafeBitCast(handle, to: WebURLLoaderImpl.self)
	  	//loader.setDefersLoading(defers != 0)
	  }
  	  
  	  //void (*URLLoaderDidChangePriority)(void* state)
  	callbacks.URLLoaderDidChangePriority = { (handle: UnsafeMutableRawPointer?) in
	  	//let loader = unsafeBitCast(handle, to: WebURLLoaderImpl.self)
	  	//loader.didChangePriority()
	  }

	  return callbacks
	}
}