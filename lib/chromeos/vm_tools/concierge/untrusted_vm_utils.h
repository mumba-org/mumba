// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_UNTRUSTED_VM_UTILS_H_
#define VM_TOOLS_CONCIERGE_UNTRUSTED_VM_UTILS_H_

#include <utility>

#include <base/files/file_path.h>
#include <dbus/object_proxy.h>

namespace vm_tools {
namespace concierge {

// Used to check for, and if needed enable, the conditions required for
// untrusted VMs.
class UntrustedVMUtils {
 public:
  // |l1tf_status_path| - Path to read L1TF vulnerability status from.
  // |mds_status_path| - Path to read MDS vulnerability status from.
  UntrustedVMUtils(const base::FilePath& l1tf_status_path,
                   const base::FilePath& mds_status_path);
  UntrustedVMUtils(const UntrustedVMUtils&) = delete;
  UntrustedVMUtils& operator=(const UntrustedVMUtils&) = delete;

  // Mitigation status for L1TF and MDS vulnerabilities.
  enum class MitigationStatus {
    // The host is not vulnerable.
    NOT_VULNERABLE,

    // The host is vulnerable.
    VULNERABLE,

    // The host is vulnerable but can be secure if SMT is disabled on the host.
    VULNERABLE_DUE_TO_SMT_ENABLED,
  };

  // Returns the mitigation status for untrusted VMs based on the following
  // checks
  // - Check if kernel version >= |min_needed_version_|.
  // - Check if L1TF is mitigated.
  // - Check if MDS is mitigated.
  MitigationStatus CheckUntrustedVMMitigationStatus();

 private:
  // Path to read L1TF vulnerability status from.
  base::FilePath l1tf_status_path_;

  // Path to read MDS vulnerability status from.
  base::FilePath mds_status_path_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_UNTRUSTED_VM_UTILS_H_
