// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/asset.h"

namespace host {

Asset::Asset(AssetType type, const std::string& asset_code): type_(type), asset_code_(asset_code) {

}

Asset::Asset(AssetType type, const std::string& asset_code, double unity): type_(type), asset_code_(asset_code), unity_(unity) {

}

Asset::~Asset() {

}   

Lumen::Lumen(): Asset(AssetType::NATIVE, "XLM") {

}

Lumen::Lumen(double unity): Asset(AssetType::NATIVE, "XLM", unity) {

}

Lumen::~Lumen() {

}

Klu::Klu(): Asset(AssetType::CREDIT_ALPHANUM4, "KLU") {

}

Klu::Klu(double unity): Asset(AssetType::CREDIT_ALPHANUM4, "KLU", unity) {

}

Klu::~Klu() {

}

AppKlu::AppKlu() {

}

AppKlu::AppKlu(double unity): Klu(unity) {

}

AppKlu::~AppKlu() {

}

AttentionKlu::AttentionKlu() {

}

AttentionKlu::AttentionKlu(double unity): Klu(unity) {

}

AttentionKlu::~AttentionKlu() {

}

TransferKlu::TransferKlu() {

}

TransferKlu::TransferKlu(double unity): Klu(unity) {

}

TransferKlu::~TransferKlu() {

}

ServiceKlu::ServiceKlu() {

}

ServiceKlu::ServiceKlu(double unity): Klu(unity) {

}

ServiceKlu::~ServiceKlu() {

}

StorageKlu::StorageKlu() {

}

StorageKlu::StorageKlu(double unity): Klu(unity) {

}

StorageKlu::~StorageKlu() {

}

CertificateKlu::CertificateKlu(){

}

CertificateKlu::CertificateKlu(double unity): Klu(unity) {

}

CertificateKlu::~CertificateKlu() {

}

CustomKlu::CustomKlu() {

}

CustomKlu::CustomKlu(double unity): Klu(unity) {

}

CustomKlu::~CustomKlu() {

}

}