// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_BLOCK_H_
#define MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_BLOCK_H_

#include "base/macros.h"
#include "core/shared/domain/storage/block.h"

namespace domain {

// this block points to a given file contents 
class Ext4Block : public Block {
public:
  Ext4Block();
  ~Ext4Block() override;

  void* data() const override;
  size_t size() const override;

private:

  DISALLOW_COPY_AND_ASSIGN(Ext4Block);
};

}

#endif