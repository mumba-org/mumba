// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public enum LatencyComponentType : Int, RawRepresentable {
	case InputEventLatencyBeginRWHComponent = 0
	case LatencyBeginScrollListenerUpdateMainComponent
	case LatencyBeginFrameRendererMainComponent
  case LatencyBeginFrameRendererInvalidateComponent
  case LatencyBeginFrameRendererCompositorComponent
  case LatencyBeginFrameUIMainComponent
  case LatencyBeginFrameUICompositorComponent
  case LatencyBeginFrameDisplayCompositorComponent
  case InputEventLatencyScrollUpdateOriginalComponent
  case InputEventLatencyFirstScrollUpdateOriginalComponent
  case InputEventLatencyOriginalComponent
  case InputEventLatencyUIComponent
  case InputEventLatencyRendererMainComponent
	case InputEventLatencyRenderingScheduledMainComponent
	case InputEventLatencyRenderingScheduledImplComponent
	case InputEventLatencyForwardScrollUpdateToMainComponent
  case InputEventLatencyAckRWHComponent
  case WindowSnapshotFrameNumberComponent
  case TabShowComponent
  case InputEventLatencyRendererSwapComponent
  case DisplayCompositorReceivedFrameComponent
  case InputEventGpuSwapBufferComponent
  case InputEventLatencyGenerateScrollUpdateFromMouseWhell
  case InputEventLatencyTerminatedNoSwapComponent
  case InputEventLatencyTerminatedFrameSwapComponent
  case InputEventLatencyTerminatedCommitFailedComponent
  case InputEventLatencyTerminatedCommitNoUpdateComponent
  case InputEventLatencyTerminatedSwapFailedComponent
}

public enum SourceEventType : Int {
  case Unknown
  case Wheel
  case Mouse
  case Touch
  case KeyPress
  case Frame
  case Other
}

// public struct LatencyComponent {
//     public var sequenceNumber: Int64 = 0
//     public var eventTime: TimeTicks = TimeTicks()
//     public var eventCount: UInt32 = 0
//     public var firstEventTime: TimeTicks = TimeTicks()
//     public var lastEventTime: TimeTicks = TimeTicks()
//     public init() {}
// }

// public struct LatencyKey : Hashable {

//   public var hashValue: Int {
//     return Int((UInt64(id) << 32) | UInt64(type.rawValue))
//   }

//   public var id: Int64
//   public var type: LatencyComponentType

//   public init(id: Int64, type: LatencyComponentType) {
//     self.id = id
//     self.type = type
//   }
// }

//public typealias LatencyMap = [LatencyComponentType: LatencyComponent]

public struct LatencyInfo {
	
	public var components: [LatencyComponentType: TimeTicks] = [:]
	public var traceId: Int64 = 0
	public var traceName: String = String()
  public var ukmSourcedId: Int64 = 0
  public var coalesced: Bool = false
  public var began: Bool = false
  public var terminated: Bool = false
  public var sourceEventType: SourceEventType = SourceEventType.Unknown
  public var scrollUpdateDelta: Float = 0.0
  public var predictedScrollUpdateDelta: Float = 0.0
  
	public init() {}

	public func findLatency(type: LatencyComponentType, id: Int64, output: TimeTicks?) -> Bool {
		return false
	}

	public func addLatencyNumber(component: LatencyComponentType) {

	}

	public func addLatencyNumber(component: LatencyComponentType, name: String) {

	}

	public func copyLatencyFrom(other: LatencyInfo, type: LatencyComponentType) {
		
	}

}
