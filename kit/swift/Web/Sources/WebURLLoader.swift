// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct WebURLLoaderOptions {

    public enum CrossOriginRequestPolicy : Int {
        case Deny = 0
        case UseAccessControl
        case Allow
    }

    public enum PreflightPolicy : Int {
        case ConsiderPreflight = 0
        case ForcePreflight
        case PreventPreflight
    }

    public var untrustedHTTP: Bool
    public var allowCredentials: Bool
    public var exposeAllResponseHeaders: Bool
    public var preflightPolicy: PreflightPolicy
    public var crossOriginRequestPolicy: CrossOriginRequestPolicy
}

public protocol WebURLLoaderClient {
  // Called when following a redirect. |new_.*| arguments contain the
  // information about the received redirect. When |report_raw_headers| is
  // updated it'll be used for filtering data of the next redirect or response.
  //
  // Implementations should return true to instruct the loader to follow the
  // redirect, or false otherwise.
  func willFollowRedirect(
    url: String,
    siteForCookies: String,
    referrer: String,
    referrerPolicy: WebReferrerPolicy,
    method: String,
    passedRedirectResponse: WebURLResponse,
    reportRawHeaders: inout Bool) -> Bool

  // Called to report upload progress. The bytes reported correspond to
  // the HTTP message body.
  func didSendData(bytesSent: UInt64,
                   totalBytesToBeSent: UInt64)

  // Called when response headers are received.
  func didReceiveResponse(response: WebURLResponse)

  // Called when response headers are received.
  func didReceiveResponse(
    response: WebURLResponse,
    handle: WebDataConsumerHandle)

  // Called when the response body becomes available. This method is only called
  // if the request's PassResponsePipeToClient flag was set to true.

  // TODO: see what ScopedDataPipeConsumerHandle gives us
  func didStartLoadingResponseBody(/* body: mojo::ScopedDataPipeConsumerHandle */ )

  // Called when a chunk of response data is downloaded. This is only called
  // if WebURLRequest's DownloadToFile flag was set to true.
  func didDownloadData(dataLength: Int, encodedDataLength: Int)

  // Called when a chunk of response data is received. |data_length| is the
  // number of bytes pointed to by |data|. |encoded_data_length| is the number
  // of bytes actually received from network to serve this chunk, including
  // HTTP headers and framing if relevant. It is 0 if the response was served
  // from cache, and -1 if this information is unavailable.
  func didReceiveData(data: UnsafePointer<Int8>?, dataLength: Int)

  // Called when the number of bytes actually received from network including
  // HTTP headers is updated. |transfer_size_diff| is positive.
  func didReceiveTransferSizeUpdate(transferSizeDiff: Int)

  // Called when a chunk of renderer-generated metadata is received from the
  // cache.
  func didReceiveCachedMetadata(data: UnsafePointer<Int8>?, dataLength: Int)

  // Called when the load completes successfully.
  // |total_encoded_data_length| may be equal to kUnknownEncodedDataLength.
  // |blocked_cross_site_document| is used to report that cross-site document
  // request response was blocked from entering renderer. Corresponding message
  // will be generated in devtools console if this flag is set to true.
  // TODO(crbug.com/798625): use different callback for subresources
  // with responses blocked due to document protection.
  func didFinishLoading(finishTime: Double,
                        totalEncodedDataLength: Int64,
                        totalEncodedBodyLength: Int64,
                        totalDecodedBodyLength: Int64,
                        blockedCrossSiteDocument: Bool)

  // Called when the load completes with an error.
  // |total_encoded_data_length| may be equal to kUnknownEncodedDataLength.
  func didFail(error: WebURLError,
               totalEncodedDataLength: Int64,
               totalEncodedBodyLength: Int64,
               totalDecodedBodyLength: Int64)

}

extension WebURLLoaderClient {

  //public static let UnknownEncodedDataLength: Int64 = -1

  public func willFollowRedirect(
    url: String,
    siteForCookies: String,
    referrer: String,
    referrerPolicy: WebReferrerPolicy,
    method: String,
    passedRedirectResponse: WebURLResponse,
    reportRawHeaders: inout Bool) -> Bool {
    return true
  }

  public func didSendData(bytesSent: UInt64, totalBytesToBeSent: UInt64) {}

  public func didReceiveResponse(response: WebURLResponse) {}

  public func didReceiveResponse(
    response: WebURLResponse,
    handle: WebDataConsumerHandle) {
    didReceiveResponse(response: response)
  }

  public func didStartLoadingResponseBody() {}

  public func didDownloadData(dataLength: Int, encodedDataLength: Int) {}

  public func didReceiveData(data: UnsafePointer<Int8>?, dataLength: Int) {}

  public func didReceiveTransferSizeUpdate(transferSizeDiff: Int) {}

  public func didReceiveCachedMetadata(data: UnsafePointer<Int8>?, dataLength: Int) {}

  public func didFinishLoading(finishTime: Double,
                               totalEncodedDataLength: Int64,
                               totalEncodedBodyLength: Int64,
                               totalDecodedBodyLength: Int64,
                               blockedCrossSiteDocument: Bool) {}
  public func didFail(
    error: WebURLError,
    totalEncodedDataLength: Int64,
    totalEncodedBodyLength: Int64,
    totalDecodedBodyLength: Int64) {}
}

public protocol WebURLLoader : class {

  var unmanagedSelf: UnsafeMutableRawPointer? { get }

  // Load the request synchronously, returning results directly to the
  // caller upon completion.  There is no mechanism to interrupt a
  // synchronous load!!
  // If the request's PassResponsePipeToClient flag is set to true, the response
  // will instead be redirected to a blob, which is passed out in
  // |downloaded_blob|.
  func loadSynchronously(
      request: WebURLRequest,
      response: WebURLResponse,
      error: WebURLError?,
      data: WebData,
      encodedDataLength: Int64,
      encodedBodyLength: Int64,
      downloadedFileLength: Int64?,
      downloadedBlob: WebBlobInfo)

  // Load the request asynchronously, sending notifications to the given
  // client.  The client will receive no further notifications if the
  // loader is disposed before it completes its work.
  func loadAsynchronously(request: WebURLRequest,
                          client: WebURLLoaderClient)

  // Cancels an asynchronous load.  This will appear as a load error to
  // the client.
  func cancel()

  // Suspends/resumes an asynchronous load.
  func setDefersLoading(_: Bool)

  // Notifies the loader that the priority of a WebURLRequest has changed from
  // its previous value. For example, a preload request starts with low
  // priority, but may increase when the resource is needed for rendering.
  func didChangePriority(newPriority: WebURLRequest.Priority,
                         intraPriorityValue: Int)

  func createCallbacks() -> CBlinkPlatformCallbacks
}

// public class WebURLLoaderImpl : WebURLLoader {

//   var reference: WebURLLoaderRef

//   init(reference: WebURLLoaderRef) {
//     self.reference = reference
//   }

// }