// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class LayerTreeFrameSink {
  
  public var reference: LayerTreeFrameSinkRef?
  
  public init(reference: LayerTreeFrameSinkRef) {
   self.reference = reference
  }

  deinit {
  	if let ref = reference {
  	  _LayerTreeFrameSinkDestroy(ref)
  	}
  }

}

public class DirectLayerTreeFrameSink : LayerTreeFrameSink {

  public init(frameSinkId: FrameSinkId,
  		        hostFrameSinkManager: HostFrameSinkManager,
        	    frameSinkManager: FrameSinkManagerImpl, 
        	    display: CompositorDisplay,
        	    contextProvider: ContextProvider) {
    let ref = _LayerTreeFrameSinkCreateDirect(
      frameSinkId.clientId, 
      frameSinkId.sinkId, 
      hostFrameSinkManager.reference,
      frameSinkManager.reference,
      display.reference,
      contextProvider.reference)
  	super.init(reference: ref!)
  }

}