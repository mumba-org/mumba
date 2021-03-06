// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CRL_SET_H_
#define NET_CERT_CRL_SET_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/cert/x509_cert_types.h"

namespace net {

// A CRLSet is a structure that lists the serial numbers of revoked
// certificates from a number of issuers where issuers are identified by the
// SHA256 of their SubjectPublicKeyInfo.
// CRLSetStorage is responsible for creating CRLSet instances.
class NET_EXPORT CRLSet : public base::RefCountedThreadSafe<CRLSet> {
 public:
  enum class Result {
    REVOKED,  // the certificate should be rejected.
    UNKNOWN,  // the CRL for the certificate is not included in the set.
    GOOD,     // the certificate is not listed.
  };

  // Parses the bytes in |data| and, on success, puts a new CRLSet in
  // |out_crl_set| and returns true.
  static bool Parse(base::StringPiece data, scoped_refptr<CRLSet>* out_crl_set);

  // CheckSPKI checks whether the given SPKI has been listed as blocked.
  //   spki_hash: the SHA256 of the SubjectPublicKeyInfo of the certificate.
  Result CheckSPKI(const base::StringPiece& spki_hash) const;

  // CheckSerial returns the information contained in the set for a given
  // certificate:
  //   serial_number: the serial number of the certificate
  //   issuer_spki_hash: the SHA256 of the SubjectPublicKeyInfo of the CRL
  //       signer
  Result CheckSerial(
      const base::StringPiece& serial_number,
      const base::StringPiece& issuer_spki_hash) const;

  // CheckSubject returns the information contained in the set for a given,
  // encoded subject name and SPKI hash. The subject name is encoded as a DER
  // X.501 Name (see https://tools.ietf.org/html/rfc5280#section-4.1.2.4).
  Result CheckSubject(const base::StringPiece& asn1_subject,
                      const base::StringPiece& spki_hash) const;

  // IsExpired returns true iff the current time is past the NotAfter time
  // specified in the CRLSet.
  bool IsExpired() const;

  // sequence returns the sequence number of this CRL set. CRL sets generated
  // by the same source are given strictly monotonically increasing sequence
  // numbers.
  uint32_t sequence() const;

  // CRLList contains a list of (issuer SPKI hash, revoked serial numbers)
  // pairs.
  typedef std::vector< std::pair<std::string, std::vector<std::string> > >
      CRLList;

  // crls returns the internal state of this CRLSet. It should only be used in
  // testing.
  const CRLList& crls() const;

  // EmptyCRLSetForTesting returns a valid, but empty, CRLSet for unit tests.
  static scoped_refptr<CRLSet> EmptyCRLSetForTesting();

  // ExpiredCRLSetForTesting returns a expired, empty CRLSet for unit tests.
  static scoped_refptr<CRLSet> ExpiredCRLSetForTesting();

  // ForTesting returns a CRLSet for testing. If |is_expired| is true, calling
  // IsExpired on the result will return true. If |issuer_spki| is not NULL,
  // the CRLSet will cover certificates issued by that SPKI. If |serial_number|
  // is not empty, then that big-endian serial number will be considered to
  // have been revoked by |issuer_spki|. If |common_name| is not empty then the
  // CRLSet will consider certificates with a subject consisting only of that
  // common name to be revoked unless they match an SPKI hash from
  // |acceptable_spki_hashes_for_cn|.
  static scoped_refptr<CRLSet> ForTesting(
      bool is_expired,
      const SHA256HashValue* issuer_spki,
      const std::string& serial_number,
      const std::string common_name,
      const std::vector<std::string> acceptable_spki_hashes_for_cn);

 private:
  CRLSet();
  ~CRLSet();

  friend class base::RefCountedThreadSafe<CRLSet>;

  uint32_t sequence_;
  CRLList crls_;
  // not_after_ contains the time, in UNIX epoch seconds, after which the
  // CRLSet should be considered stale, or 0 if no such time was given.
  uint64_t not_after_;
  // crls_index_by_issuer_ maps from issuer SPKI hashes to the index in |crls_|
  // where the information for that issuer can be found. We have both |crls_|
  // and |crls_index_by_issuer_| because, when applying a delta update, we need
  // to identify a CRL by index.
  std::unordered_map<std::string, size_t> crls_index_by_issuer_;
  // blocked_spkis_ contains the SHA256 hashes of SPKIs which are to be blocked
  // no matter where in a certificate chain they might appear.
  std::vector<std::string> blocked_spkis_;
  // limited_subjects_ is a map from the SHA256 hash of an X.501 subject name
  // to a list of allowed SPKI hashes for certificates with that subject name.
  std::unordered_map<std::string, std::vector<std::string>> limited_subjects_;
  // limited_subjects_ordered_ contains the keys of |limited_subjects_|,
  // ordered in the same order as they were found when parsing. This allows
  // exact reserialisation.
  std::vector<std::string> limited_subjects_ordered_;
};

}  // namespace net

#endif  // NET_CERT_CRL_SET_H_
