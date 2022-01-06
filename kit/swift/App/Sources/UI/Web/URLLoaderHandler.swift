// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Web

public class URLLoaderHandler : WebURLLoaderClient {

  public func willFollowRedirect(
    url: String,
    siteForCookies: String,
    referrer: String,
    referrerPolicy: WebReferrerPolicy,
    method: String,
    passedRedirectResponse: WebURLResponse,
    reportRawHeaders: inout Bool) -> Bool {
    
  }

  public func didSendData(bytesSent: UInt64,
                          totalBytesToBeSent: UInt64) {
    
  }

  public func didReceiveResponse(response: WebURLResponse) {
    
  }

  public func didReceiveResponse(
    response: WebURLResponse,
    handle: WebDataConsumerHandle) {
    
  }

  public func didStartLoadingResponseBody(/* body: mojo::ScopedDataPipeConsumerHandle */ ) {
    
  }

  public func didDownloadData(dataLength: Int, encodedDataLength: Int) {
    
  }

  public func didReceiveData(data: UnsafePointer<Int8>?, dataLength: Int) {

  }

  public func didReceiveTransferSizeUpdate(transferSizeDiff: Int) {
    
  }

  public func didReceiveCachedMetadata(data: UnsafePointer<Int8>?, dataLength: Int) {
    
  }

  public func didFinishLoading(finishTime: Double,
                        totalEncodedDataLength: Int64,
                        totalEncodedBodyLength: Int64,
                        totalDecodedBodyLength: Int64,
                        blockedCrossSiteDocument: Bool) {
    
  }

  public func didFail(error: WebURLError,
               totalEncodedDataLength: Int64,
               totalEncodedBodyLength: Int64,
               totalDecodedBodyLength: Int64) {
    
  }
}