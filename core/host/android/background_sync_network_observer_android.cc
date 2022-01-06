// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/android/background_sync_network_observer_android.h"

#include "jni/BackgroundSyncNetworkObserver_jni.h"

using base::android::JavaParamRef;

namespace host {

// static
scoped_refptr<BackgroundSyncNetworkObserverAndroid::Observer>
BackgroundSyncNetworkObserverAndroid::Observer::Create(
    base::Callback<void(net::NetworkChangeNotifier::ConnectionType)> callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  scoped_refptr<BackgroundSyncNetworkObserverAndroid::Observer> observer(
      new BackgroundSyncNetworkObserverAndroid::Observer(callback));
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::Bind(&BackgroundSyncNetworkObserverAndroid::Observer::Init,
                 observer));
  return observer;
}

void BackgroundSyncNetworkObserverAndroid::Observer::Init() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // Attach a Java BackgroundSyncNetworkObserver object. Its lifetime will be
  // scoped to the lifetime of this object.
  JNIEnv* env = base::android::AttachCurrentThread();
  base::android::ScopedJavaGlobalRef<jobject> obj(
      Java_BackgroundSyncNetworkObserver_createObserver(
          env, reinterpret_cast<jlong>(this)));
  j_observer_.Reset(obj);
}

BackgroundSyncNetworkObserverAndroid::Observer::~Observer() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_BackgroundSyncNetworkObserver_removeObserver(
      env, j_observer_, reinterpret_cast<jlong>(this));
  DCHECK_CURRENTLY_ON(HostThread::UI);
  j_observer_.Release();
}

void BackgroundSyncNetworkObserverAndroid::Observer::
    NotifyConnectionTypeChanged(JNIEnv* env,
                                const JavaParamRef<jobject>& jcaller,
                                jint new_connection_type) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::Bind(callback_,
                 static_cast<net::NetworkChangeNotifier::ConnectionType>(
                     new_connection_type)));
}

BackgroundSyncNetworkObserverAndroid::Observer::Observer(
    base::Callback<void(net::NetworkChangeNotifier::ConnectionType)> callback)
    : callback_(callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
}

BackgroundSyncNetworkObserverAndroid::BackgroundSyncNetworkObserverAndroid(
    const base::Closure& network_changed_callback)
    : BackgroundSyncNetworkObserver(network_changed_callback),
      weak_ptr_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  // Remove the observer attached by the NetworkObserver constructor
  net::NetworkChangeNotifier::RemoveNetworkChangeObserver(this);

  observer_ = Observer::Create(
      base::Bind(&BackgroundSyncNetworkObserverAndroid::OnNetworkChanged,
                 weak_ptr_factory_.GetWeakPtr()));
}

BackgroundSyncNetworkObserverAndroid::~BackgroundSyncNetworkObserverAndroid() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
}
}  // namespace host
