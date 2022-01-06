/*
 * Copyright 2016, gRPC Authors All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import MumbaShims

extension RpcChannel {
  /// The connectivity state of a given gRPC channel.
  public enum ConnectivityState {
    /// RpcChannel has just been initialized
    case initialized
    /// RpcChannel is idle
    case idle
    /// RpcChannel is connecting
    case connecting
    /// RpcChannel is ready for work
    case ready
    /// RpcChannel has seen a failure but expects to recover
    case transientFailure
    /// RpcChannel has seen a failure that it cannot recover from
    case shutdown
    /// RpcChannel connectivity state is unknown
    case unknown

    init(_ underlyingState: grpc_connectivity_state) {
      switch underlyingState {
      case GRPC_CHANNEL_INIT:
        self = .initialized
      case GRPC_CHANNEL_IDLE:
        self = .idle
      case GRPC_CHANNEL_CONNECTING:
        self = .connecting
      case GRPC_CHANNEL_READY:
        self = .ready
      case GRPC_CHANNEL_TRANSIENT_FAILURE:
        self =  .transientFailure
      case GRPC_CHANNEL_SHUTDOWN:
        self = .shutdown
      default:
        self = .unknown
      }
    }

    var underlyingState: grpc_connectivity_state? {
      switch self {
      case .initialized:
        return GRPC_CHANNEL_INIT
      case .idle:
        return GRPC_CHANNEL_IDLE
      case .connecting:
        return GRPC_CHANNEL_CONNECTING
      case .ready:
        return GRPC_CHANNEL_READY
      case .transientFailure:
        return GRPC_CHANNEL_TRANSIENT_FAILURE
      case .shutdown:
        return GRPC_CHANNEL_SHUTDOWN
      default:
        return nil
      }
    }
  }
}
