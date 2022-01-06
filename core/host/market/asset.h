// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_COIN_H_
#define MUMBA_HOST_MARKET_COIN_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {

enum class AssetType : int {
  NATIVE = 0,
  CREDIT_ALPHANUM4 = 1,
  CREDIT_ALPHANUM12 = 2,
  POOL_SHARE = 3
};

class Asset {
public:
  Asset(AssetType type, const std::string& asset_code);
  Asset(AssetType type, const std::string& asset_code, double unity);
  virtual ~Asset();

  AssetType type() const {
    return type_;
  }

  const std::string& asset_code() const {
    return asset_code_;
  }

  double unity() const {
    return unity_;
  }

  virtual bool is_lumen() const {
    return type_ == AssetType::NATIVE;
  }

  virtual bool is_klu() const {
    return type_ == AssetType::CREDIT_ALPHANUM4 && asset_code_ == "KLU";
  }

  virtual bool is_application() const {
    return false;
  }

  virtual bool is_attention() const {
    return false;
  }

  virtual bool is_transfer() const {
    return false;
  }

  virtual bool is_service() const {
    return false;
  }

  virtual bool is_storage() const {
    return false;
  }

  virtual bool is_certificate() const {
    return false;
  }

  virtual bool is_custom() const {
    return false;
  }

  template <class S>
  S* As() const {
    return S::Cast(this);
  }  

private:
  
  AssetType type_;
  std::string asset_code_;
  double unity_;
  
  DISALLOW_COPY_AND_ASSIGN(Asset);
};

class Lumen : public Asset {
public:

  static Lumen* Cast(Asset* self) {
    return static_cast<Lumen*>(self);
  }

  Lumen();
  Lumen(double unity);
  ~Lumen() override;

};

class Klu : public Asset {
public:

  static Klu* Cast(Asset* self) {
    return static_cast<Klu*>(self);
  }

  Klu();
  Klu(double unity);
  ~Klu() override;

  bool is_klu() const override {
    return true;
  }

};

/* 
 * 
 */

class AppKlu: public Klu {
public:

  static AppKlu* Cast(Asset* self) {
    return static_cast<AppKlu*>(self);
  }

  AppKlu();
  AppKlu(double unity);
  ~AppKlu() override;

  bool is_application() const override {
    return true;
  }

};

class AttentionKlu : public Klu {
public:

  static AttentionKlu* Cast(Asset* self) {
    return static_cast<AttentionKlu*>(self);
  }

  AttentionKlu();
  AttentionKlu(double unity);
  ~AttentionKlu() override;

  bool is_attention() const override {
    return true;
  }
};

class TransferKlu : public Klu {
public:

  static TransferKlu* Cast(Asset* self) {
    DCHECK(self->is_transfer());
    return static_cast<TransferKlu*>(self);
  }

  TransferKlu();
  TransferKlu(double unity);
  ~TransferKlu() override;

  bool is_transfer() const override {
    return true;
  }

};

class ServiceKlu : public Klu {
public:

  static ServiceKlu* Cast(Asset* self) {
    DCHECK(self->is_service());
    return static_cast<ServiceKlu*>(self);
  }

  ServiceKlu();
  ServiceKlu(double unity);
  ~ServiceKlu() override;

  bool is_service() const override {
    return true;
  }
};

class StorageKlu : public Klu {
public:

  static StorageKlu* Cast(Asset* self) {
    DCHECK(self->is_storage());
    return static_cast<StorageKlu*>(self);
  }

  StorageKlu();
  StorageKlu(double unity);
  ~StorageKlu() override;

  bool is_storage() const override {
    return true;
  }
};

class CertificateKlu : public Klu {
public:

  static CertificateKlu* Cast(Asset* self) {
    DCHECK(self->is_certificate());
    return static_cast<CertificateKlu*>(self);
  }

  CertificateKlu();
  CertificateKlu(double unity);
  ~CertificateKlu() override;

  bool is_certificate() const override {
    return true;
  }
};

class CustomKlu : public Klu {
public:

  static CustomKlu* Cast(Asset* self) {
    DCHECK(self->is_custom());
    return static_cast<CustomKlu*>(self);
  }

  CustomKlu();
  CustomKlu(double unity);
  ~CustomKlu() override;

  bool is_custom() const override {
    return true;
  }
};

}

#endif