// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_MANAGER_H_
#define MUMBA_HOST_BUNDLE_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "base/files/file_path.h"
#include "core/host/bundle/bundle_manager_observer.h"
#include "core/host/database_policy.h"

namespace host {
class Workspace;
class BundleModel;
class ShareDatabase;

class BundleManager {
public:
  BundleManager(Workspace* workspace);
  ~BundleManager();

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);

  //bool IsBundleInstalled(const base::FilePath& path) const;
  bool IsBundleInstalled(const std::string& name) const;

  bool HaveBundle(const base::UUID& id);
  bool HaveBundle(const std::string& name);
  Bundle* GetBundle(const base::UUID& id);
  Bundle* GetBundle(const std::string& name);

  void UnpackBundle(const std::string& name, const base::FilePath& src, base::OnceCallback<void(bool)> callback);
  void UnpackBundleFromContents(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback);

  void UnpackBundleSync(const std::string& name, const base::FilePath& src, base::OnceCallback<void(bool)> callback);
  void UnpackBundleFromContentsSync(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback);

  void AddObserver(BundleManagerObserver* observer);
  void RemoveObserver(BundleManagerObserver* observer);

private:
  friend class Workspace;
  
  bool ValidateBundleBeforeUnpack(const base::FilePath& src);

  void UnpackBundleImpl(const std::string& name, const base::FilePath& src, const base::FilePath& dest, base::OnceCallback<void(bool)> callback);
  void UnpackBundleFromContentsImpl(const std::string& name, base::StringPiece contents, const base::FilePath& dest, base::OnceCallback<void(bool)> callback);
  bool BeforeBundleUnpack(const base::FilePath& dest) const;
  bool AfterBundleUnpack(const std::string& name, const base::FilePath& dest) const;
  base::FilePath GetOutputPath() const;

  void OnLoad(int r, int count);

  void NotifyBundleAdded(Bundle* bundle);
  void NotifyBundleRemoved(Bundle* bundle);
  void NotifyBundlesLoad(int r, int count);

  Workspace* workspace_;

  std::unique_ptr<BundleModel> model_;
  std::vector<BundleManagerObserver*> observers_;

  DISALLOW_COPY_AND_ASSIGN(BundleManager);
};

}

#endif