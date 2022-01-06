// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

open class ServiceServer {
  public let port: Int
  public private(set) var server: RpcServer

  public var shouldLogRequests = true
  
  fileprivate var servicesByName: [String: ServiceProvider]
    /// Create a server that accepts insecure connections.
  public init(port: Int, serviceProviders: [ServiceProvider]) throws {
    self.port = port
    servicesByName = Dictionary(uniqueKeysWithValues: serviceProviders.map { ($0.serviceName, $0) })
    // hack to allow for the 'plugin' fetch methods that are declared in its own service
    for item in serviceProviders {
      let names = item.serviceName.components(separatedBy: ".")
      // the same handler should already have the methods implemented
      servicesByName[names[0] + ".FetchService"] = item
    }
    server = try RpcServer(serviceName: serviceProviders[0].serviceName, port: port)
  }

  /// Start the server.
  public func start() {
    server.run { [weak self] handler, callId in
      guard let strongSelf = self else {
        print("ERROR: ServiceServer has been asked to handle a request even though it has already been deallocated")
        return
      }

      //if strongSelf.shouldLogRequests == true {
      //  print("Server received request to " + handler.host
      //    + " calling " + handler.method
      //    + " from " + handler.caller
      //    + " with metadata " + handler.requestMetadata.dictionaryRepresentation.description)
     // }
      
      // do {
      //   do {
      //     let methodComponents = handler.method.components(separatedBy: "/")
      //     guard methodComponents.count >= 3 && methodComponents[0].isEmpty,
      //       let providerForServiceName = strongSelf.servicesByName[methodComponents[1]] else {
      //       throw HandleMethodError.unknownMethod
      //     }
          
      //     print("service named '\(methodComponents[1])' resolved ok to '\(providerForServiceName.serviceName)'")
      //     //if let responseStatus = try providerForServiceName.handleMethod(handler.method, callId: handler.callId, handler: handler) {
      //       // The handler wants us to send the status for them; do that.
      //       // But first, ensure that all outgoing messages have been enqueued, to avoid ending the stream prematurely:
      //       //handler.call.messageQueueEmpty.wait()
      //       //if handler.shouldSendStatus {
      //       //  handler.sendStatus(responseStatus)
      //       //}
      //     //}
      //     print("calling providerForServiceName.handleMethod()")
      //     if let responseStatus = try providerForServiceName.handleMethod(handler.method, callId: handler.callId, handler: handler) {
      //       print("providerForServiceName.handleMethod() returned ok")
      //       if responseStatus.code != .ok {
      //         print("error while handling method: \(responseStatus.message)")
      //       }
      //     }
      //   } catch _ as HandleMethodError {
      //     print("ServiceServer call to unknown method '\(handler.method)'")
      //     // The method is not implemented by the service - send a status saying so.
      //     // try handler.call.perform(RpcOperationGroup(
      //     //   call: handler.call,
      //     //   operations: [
      //     //     .sendInitialMetadata(RpcMetadata()),
      //     //     .receiveCloseOnServer,
      //     //     .sendStatusFromServer(.unimplemented, "unknown method " + handler.method, RpcMetadata())
      //     // ]) { _ in
      //     //   handler.shutdown()
      //     // })
      //   }
      // } catch {
      //   // The individual sessions' `run` methods (which are called by `self.handleMethod`) only throw errors if
      //   // they encountered an error that has not also been "seen" by the actual request handler implementation.
      //   // Therefore, this error is "really unexpected" and  should be logged here - there's nowhere else to log it otherwise.
      //   print("ServiceServer unexpected error handling method '\(handler.method)': \(error)")
      //   //do {
      //   handler.sendStatus((error as? ServerStatus) ?? .processingError)
      //   //} catch {
      //   //  print("ServiceServer unexpected error handling method '\(handler.method)'; sending status failed as well: \(error)")
      //   //  handler.shutdown()
      //  // }
      // }
      do {
        let methodComponents = handler.method.components(separatedBy: "/")
        guard methodComponents.count >= 3 && methodComponents[0].isEmpty,
          let providerForServiceName = strongSelf.servicesByName[methodComponents[1]] else {
          print("error: throwing HandleMethodError.unknownMethod")
          throw HandleMethodError.unknownMethod
        }
        
        //if let responseStatus = try providerForServiceName.handleMethod(handler.method, callId: handler.callId, handler: handler) {
          // The handler wants us to send the status for them; do that.
          // But first, ensure that all outgoing messages have been enqueued, to avoid ending the stream prematurely:
          //handler.call.messageQueueEmpty.wait()
          //if handler.shouldSendStatus {
          //  handler.sendStatus(responseStatus)
          //}
        //}
        if let responseStatus = try providerForServiceName.handleMethod(handler.method, callId: callId, handler: handler) {
          if responseStatus.code != .ok {
            print("error while handling method \(handler.method): \(responseStatus.message)")
            //sendMessage(callId: Int, data: Data, method: RpcMethodType, now: true)
            handler.sendStatus(callId: callId, responseStatus)
          }
        }
      } catch { 
        handler.sendStatus(callId: callId, (error as? ServerStatus) ?? .processingError)
      }
    }
  }
}
