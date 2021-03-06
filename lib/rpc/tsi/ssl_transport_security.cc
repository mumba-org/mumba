/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "rpc/tsi/ssl_transport_security.h"

#include <rpc/support/port_platform.h>

#include <limits.h>
#include <string.h>

/* TODO(jboeuf): refactor inet_ntop into a portability header. */
/* Note: for whomever reads this and tries to refactor this, this
   can't be in grpc, it has to be in gpr. */
#ifdef GPR_WINDOWS
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/sync.h>
#include <rpc/support/thd.h>
#include <rpc/support/useful.h>

extern "C" {
#include <openssl/bio.h>
#include <openssl/crypto.h> /* For OPENSSL_free */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
}

#include "rpc/tsi/ssl_types.h"
#include "rpc/tsi/transport_security.h"

/* --- Constants. ---*/

#define TSI_SSL_MAX_PROTECTED_FRAME_SIZE_UPPER_BOUND 16384
#define TSI_SSL_MAX_PROTECTED_FRAME_SIZE_LOWER_BOUND 1024

/* Putting a macro like this and littering the source file with #if is really
   bad practice.
   TODO(jboeuf): refactor all the #if / #endif in a separate module. */
#ifndef TSI_OPENSSL_ALPN_SUPPORT
#define TSI_OPENSSL_ALPN_SUPPORT 1
#endif

/* TODO(jboeuf): I have not found a way to get this number dynamically from the
   SSL structure. This is what we would ultimately want though... */
#define TSI_SSL_MAX_PROTECTION_OVERHEAD 100

/* --- Structure definitions. ---*/

struct tsi_ssl_handshaker_factory {
  const tsi_ssl_handshaker_factory_vtable* vtable;
  gpr_refcount refcount;
};

struct tsi_ssl_client_handshaker_factory {
  tsi_ssl_handshaker_factory base;
  SSL_CTX* ssl_context;
  unsigned char* alpn_protocol_list;
  size_t alpn_protocol_list_length;
};

struct tsi_ssl_server_handshaker_factory {
  /* Several contexts to support SNI.
     The tsi_peer array contains the subject names of the server certificates
     associated with the contexts at the same index.  */
  tsi_ssl_handshaker_factory base;
  SSL_CTX** ssl_contexts;
  tsi_peer* ssl_context_x509_subject_names;
  size_t ssl_context_count;
  unsigned char* alpn_protocol_list;
  size_t alpn_protocol_list_length;
};

typedef struct {
  tsi_handshaker base;
  SSL* ssl;
  BIO* into_ssl;
  BIO* from_ssl;
  tsi_result result;
  tsi_ssl_handshaker_factory* factory_ref;
} tsi_ssl_handshaker;

typedef struct {
  tsi_frame_protector base;
  SSL* ssl;
  BIO* into_ssl;
  BIO* from_ssl;
  unsigned char* buffer;
  size_t buffer_size;
  size_t buffer_offset;
} tsi_ssl_frame_protector;

/* --- Library Initialization. ---*/

static gpr_once init_openssl_once = GPR_ONCE_INIT;
static gpr_mu* openssl_mutexes = nullptr;

static void openssl_locking_cb(int mode, int type, const char* file, int line) {
  if (mode & CRYPTO_LOCK) {
    gpr_mu_lock(&openssl_mutexes[type]);
  } else {
    gpr_mu_unlock(&openssl_mutexes[type]);
  }
}

static unsigned long openssl_thread_id_cb(void) {
  return (unsigned long)gpr_thd_currentid();
}

static void init_openssl(void) {
  int i;
  int num_locks;
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  num_locks = CRYPTO_num_locks();
  GPR_ASSERT(num_locks > 0);
  openssl_mutexes = (gpr_mu*)gpr_malloc((size_t)num_locks * sizeof(gpr_mu));
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    gpr_mu_init(&openssl_mutexes[i]);
  }
  CRYPTO_set_locking_callback(openssl_locking_cb);
  CRYPTO_set_id_callback(openssl_thread_id_cb);
}

/* --- Ssl utils. ---*/

static const char* ssl_error_string(int error) {
  switch (error) {
    case SSL_ERROR_NONE:
      return "SSL_ERROR_NONE";
    case SSL_ERROR_ZERO_RETURN:
      return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_READ:
      return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE:
      return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_CONNECT:
      return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
      return "SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
      return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_SSL:
      return "SSL_ERROR_SSL";
    default:
      return "Unknown error";
  }
}

/* TODO(jboeuf): Remove when we are past the debugging phase with this code. */
static void ssl_log_where_info(const SSL* ssl, int where, int flag,
                               const char* msg) {
  if ((where & flag) && tsi_tracing_enabled.enabled()) {
    gpr_log(GPR_INFO, "%20.20s - %30.30s  - %5.10s", msg,
            SSL_state_string_long(ssl), SSL_state_string(ssl));
  }
}

/* Used for debugging. TODO(jboeuf): Remove when code is mature enough. */
static void ssl_info_callback(const SSL* ssl, int where, int ret) {
  if (ret == 0) {
    gpr_log(GPR_ERROR, "ssl_info_callback: error occured.\n");
    return;
  }

  ssl_log_where_info(ssl, where, SSL_CB_LOOP, "LOOP");
  ssl_log_where_info(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
  ssl_log_where_info(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

/* Returns 1 if name looks like an IP address, 0 otherwise.
   This is a very rough heuristic, and only handles IPv6 in hexadecimal form. */
static int looks_like_ip_address(const char* name) {
  size_t i;
  size_t dot_count = 0;
  size_t num_size = 0;
  for (i = 0; i < strlen(name); i++) {
    if (name[i] == ':') {
      /* IPv6 Address in hexadecimal form, : is not allowed in DNS names. */
      return 1;
    }
    if (name[i] >= '0' && name[i] <= '9') {
      if (num_size > 3) return 0;
      num_size++;
    } else if (name[i] == '.') {
      if (dot_count > 3 || num_size == 0) return 0;
      dot_count++;
      num_size = 0;
    } else {
      return 0;
    }
  }
  if (dot_count < 3 || num_size == 0) return 0;
  return 1;
}

/* Gets the subject CN from an X509 cert. */
static tsi_result ssl_get_x509_common_name(X509* cert, unsigned char** utf8,
                                           size_t* utf8_size) {
  int common_name_index = -1;
  X509_NAME_ENTRY* common_name_entry = nullptr;
  ASN1_STRING* common_name_asn1 = nullptr;
  X509_NAME* subject_name = X509_get_subject_name(cert);
  int utf8_returned_size = 0;
  if (subject_name == nullptr) {
    gpr_log(GPR_ERROR, "Could not get subject name from certificate.");
    return TSI_NOT_FOUND;
  }
  common_name_index =
      X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
  if (common_name_index == -1) {
    gpr_log(GPR_ERROR,
            "Could not get common name of subject from certificate.");
    return TSI_NOT_FOUND;
  }
  common_name_entry = X509_NAME_get_entry(subject_name, common_name_index);
  if (common_name_entry == nullptr) {
    gpr_log(GPR_ERROR, "Could not get common name entry from certificate.");
    return TSI_INTERNAL_ERROR;
  }
  common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
  if (common_name_asn1 == nullptr) {
    gpr_log(GPR_ERROR,
            "Could not get common name entry asn1 from certificate.");
    return TSI_INTERNAL_ERROR;
  }
  utf8_returned_size = ASN1_STRING_to_UTF8(utf8, common_name_asn1);
  if (utf8_returned_size < 0) {
    gpr_log(GPR_ERROR, "Could not extract utf8 from asn1 string.");
    return TSI_OUT_OF_RESOURCES;
  }
  *utf8_size = (size_t)utf8_returned_size;
  return TSI_OK;
}

/* Gets the subject CN of an X509 cert as a tsi_peer_property. */
static tsi_result peer_property_from_x509_common_name(
    X509* cert, tsi_peer_property* property) {
  unsigned char* common_name;
  size_t common_name_size;
  tsi_result result =
      ssl_get_x509_common_name(cert, &common_name, &common_name_size);
  if (result != TSI_OK) {
    if (result == TSI_NOT_FOUND) {
      common_name = nullptr;
      common_name_size = 0;
    } else {
      return result;
    }
  }
  result = tsi_construct_string_peer_property(
      TSI_X509_SUBJECT_COMMON_NAME_PEER_PROPERTY,
      common_name == nullptr ? "" : (const char*)common_name, common_name_size,
      property);
  OPENSSL_free(common_name);
  return result;
}

/* Gets the X509 cert in PEM format as a tsi_peer_property. */
static tsi_result add_pem_certificate(X509* cert, tsi_peer_property* property) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_X509(bio, cert)) {
    BIO_free(bio);
    return TSI_INTERNAL_ERROR;
  }
  char* contents;
  long len = BIO_get_mem_data(bio, &contents);
  if (len <= 0) {
    BIO_free(bio);
    return TSI_INTERNAL_ERROR;
  }
  tsi_result result = tsi_construct_string_peer_property(
      TSI_X509_PEM_CERT_PROPERTY, (const char*)contents, (size_t)len, property);
  BIO_free(bio);
  return result;
}

/* Gets the subject SANs from an X509 cert as a tsi_peer_property. */
static tsi_result add_subject_alt_names_properties_to_peer(
    tsi_peer* peer, GENERAL_NAMES* subject_alt_names,
    size_t subject_alt_name_count) {
  size_t i;
  tsi_result result = TSI_OK;

  /* Reset for DNS entries filtering. */
  peer->property_count -= subject_alt_name_count;

  for (i = 0; i < subject_alt_name_count; i++) {
    GENERAL_NAME* subject_alt_name =
        sk_GENERAL_NAME_value(subject_alt_names, TSI_SIZE_AS_SIZE(i));
    /* Filter out the non-dns entries names. */
    if (subject_alt_name->type == GEN_DNS) {
      unsigned char* name = nullptr;
      int name_size;
      name_size = ASN1_STRING_to_UTF8(&name, subject_alt_name->d.dNSName);
      if (name_size < 0) {
        gpr_log(GPR_ERROR, "Could not get utf8 from asn1 string.");
        result = TSI_INTERNAL_ERROR;
        break;
      }
      result = tsi_construct_string_peer_property(
          TSI_X509_SUBJECT_ALTERNATIVE_NAME_PEER_PROPERTY, (const char*)name,
          (size_t)name_size, &peer->properties[peer->property_count++]);
      OPENSSL_free(name);
    } else if (subject_alt_name->type == GEN_IPADD) {
      char ntop_buf[INET6_ADDRSTRLEN];
      int af;

      if (subject_alt_name->d.iPAddress->length == 4) {
        af = AF_INET;
      } else if (subject_alt_name->d.iPAddress->length == 16) {
        af = AF_INET6;
      } else {
        gpr_log(GPR_ERROR, "SAN IP Address contained invalid IP");
        result = TSI_INTERNAL_ERROR;
        break;
      }
      const char* name = inet_ntop(af, subject_alt_name->d.iPAddress->data,
                                   ntop_buf, INET6_ADDRSTRLEN);
      if (name == nullptr) {
        gpr_log(GPR_ERROR, "Could not get IP string from asn1 octet.");
        result = TSI_INTERNAL_ERROR;
        break;
      }

      result = tsi_construct_string_peer_property_from_cstring(
          TSI_X509_SUBJECT_ALTERNATIVE_NAME_PEER_PROPERTY, name,
          &peer->properties[peer->property_count++]);
    }
    if (result != TSI_OK) break;
  }
  return result;
}

/* Gets information about the peer's X509 cert as a tsi_peer object. */
static tsi_result peer_from_x509(X509* cert, int include_certificate_type,
                                 tsi_peer* peer) {
  /* TODO(jboeuf): Maybe add more properties. */
  GENERAL_NAMES* subject_alt_names = (GENERAL_NAMES*)X509_get_ext_d2i(
      cert, NID_subject_alt_name, nullptr, nullptr);
  int subject_alt_name_count = (subject_alt_names != nullptr)
                                   ? (int)sk_GENERAL_NAME_num(subject_alt_names)
                                   : 0;
  size_t property_count;
  tsi_result result;
  GPR_ASSERT(subject_alt_name_count >= 0);
  property_count = (include_certificate_type ? (size_t)1 : 0) +
                   2 /* common name, certificate */ +
                   (size_t)subject_alt_name_count;
  result = tsi_construct_peer(property_count, peer);
  if (result != TSI_OK) return result;
  do {
    if (include_certificate_type) {
      result = tsi_construct_string_peer_property_from_cstring(
          TSI_CERTIFICATE_TYPE_PEER_PROPERTY, TSI_X509_CERTIFICATE_TYPE,
          &peer->properties[0]);
      if (result != TSI_OK) break;
    }
    result = peer_property_from_x509_common_name(
        cert, &peer->properties[include_certificate_type ? 1 : 0]);
    if (result != TSI_OK) break;

    result = add_pem_certificate(
        cert, &peer->properties[include_certificate_type ? 2 : 1]);
    if (result != TSI_OK) break;

    if (subject_alt_name_count != 0) {
      result = add_subject_alt_names_properties_to_peer(
          peer, subject_alt_names, (size_t)subject_alt_name_count);
      if (result != TSI_OK) break;
    }
  } while (0);

  if (subject_alt_names != nullptr) {
    sk_GENERAL_NAME_pop_free(subject_alt_names, GENERAL_NAME_free);
  }
  if (result != TSI_OK) tsi_peer_destruct(peer);
  return result;
}

/* Logs the SSL error stack. */
static void log_ssl_error_stack(void) {
  unsigned long err;
  while ((err = ERR_get_error()) != 0) {
    char details[256];
    ERR_error_string_n((uint32_t)err, details, sizeof(details));
    gpr_log(GPR_ERROR, "%s", details);
  }
}

/* Performs an SSL_read and handle errors. */
static tsi_result do_ssl_read(SSL* ssl, unsigned char* unprotected_bytes,
                              size_t* unprotected_bytes_size) {
  int read_from_ssl;
  GPR_ASSERT(*unprotected_bytes_size <= INT_MAX);
  read_from_ssl =
      SSL_read(ssl, unprotected_bytes, (int)*unprotected_bytes_size);
  if (read_from_ssl <= 0) {
    read_from_ssl = SSL_get_error(ssl, read_from_ssl);
    switch (read_from_ssl) {
      case SSL_ERROR_ZERO_RETURN: /* Received a close_notify alert. */
      case SSL_ERROR_WANT_READ:   /* We need more data to finish the frame. */
        *unprotected_bytes_size = 0;
        return TSI_OK;
      case SSL_ERROR_WANT_WRITE:
        gpr_log(
            GPR_ERROR,
            "Peer tried to renegotiate SSL connection. This is unsupported.");
        return TSI_UNIMPLEMENTED;
      case SSL_ERROR_SSL:
        gpr_log(GPR_ERROR, "Corruption detected.");
        log_ssl_error_stack();
        return TSI_DATA_CORRUPTED;
      default:
        gpr_log(GPR_ERROR, "SSL_read failed with error %s.",
                ssl_error_string(read_from_ssl));
        return TSI_PROTOCOL_FAILURE;
    }
  }
  *unprotected_bytes_size = (size_t)read_from_ssl;
  return TSI_OK;
}

/* Performs an SSL_write and handle errors. */
static tsi_result do_ssl_write(SSL* ssl, unsigned char* unprotected_bytes,
                               size_t unprotected_bytes_size) {
  int ssl_write_result;
  GPR_ASSERT(unprotected_bytes_size <= INT_MAX);
  ssl_write_result =
      SSL_write(ssl, unprotected_bytes, (int)unprotected_bytes_size);
  if (ssl_write_result < 0) {
    ssl_write_result = SSL_get_error(ssl, ssl_write_result);
    if (ssl_write_result == SSL_ERROR_WANT_READ) {
      gpr_log(GPR_ERROR,
              "Peer tried to renegotiate SSL connection. This is unsupported.");
      return TSI_UNIMPLEMENTED;
    } else {
      gpr_log(GPR_ERROR, "SSL_write failed with error %s.",
              ssl_error_string(ssl_write_result));
      return TSI_INTERNAL_ERROR;
    }
  }
  return TSI_OK;
}

/* Loads an in-memory PEM certificate chain into the SSL context. */
static tsi_result ssl_ctx_use_certificate_chain(SSL_CTX* context,
                                                const char* pem_cert_chain,
                                                size_t pem_cert_chain_size) {
  tsi_result result = TSI_OK;
  X509* certificate = nullptr;
  BIO* pem;
  GPR_ASSERT(pem_cert_chain_size <= INT_MAX);
  pem = BIO_new_mem_buf((void*)pem_cert_chain, (int)pem_cert_chain_size);
  if (pem == nullptr) return TSI_OUT_OF_RESOURCES;

  do {
    certificate = PEM_read_bio_X509_AUX(pem, nullptr, nullptr, (void*)"");
    if (certificate == nullptr) {
      result = TSI_INVALID_ARGUMENT;
      break;
    }
    if (!SSL_CTX_use_certificate(context, certificate)) {
      result = TSI_INVALID_ARGUMENT;
      break;
    }
    while (1) {
      X509* certificate_authority =
          PEM_read_bio_X509(pem, nullptr, nullptr, (void*)"");
      if (certificate_authority == nullptr) {
        ERR_clear_error();
        break; /* Done reading. */
      }
      if (!SSL_CTX_add_extra_chain_cert(context, certificate_authority)) {
        X509_free(certificate_authority);
        result = TSI_INVALID_ARGUMENT;
        break;
      }
      /* We don't need to free certificate_authority as its ownership has been
         transfered to the context. That is not the case for certificate though.
       */
    }
  } while (0);

  if (certificate != nullptr) X509_free(certificate);
  BIO_free(pem);
  return result;
}

/* Loads an in-memory PEM private key into the SSL context. */
static tsi_result ssl_ctx_use_private_key(SSL_CTX* context, const char* pem_key,
                                          size_t pem_key_size) {
  tsi_result result = TSI_OK;
  EVP_PKEY* private_key = nullptr;
  BIO* pem;
  GPR_ASSERT(pem_key_size <= INT_MAX);
  pem = BIO_new_mem_buf((void*)pem_key, (int)pem_key_size);
  if (pem == nullptr) return TSI_OUT_OF_RESOURCES;
  do {
    private_key = PEM_read_bio_PrivateKey(pem, nullptr, nullptr, (void*)"");
    if (private_key == nullptr) {
      result = TSI_INVALID_ARGUMENT;
      break;
    }
    if (!SSL_CTX_use_PrivateKey(context, private_key)) {
      result = TSI_INVALID_ARGUMENT;
      break;
    }
  } while (0);
  if (private_key != nullptr) EVP_PKEY_free(private_key);
  BIO_free(pem);
  return result;
}

/* Loads in-memory PEM verification certs into the SSL context and optionally
   returns the verification cert names (root_names can be NULL). */
static tsi_result ssl_ctx_load_verification_certs(SSL_CTX* context,
                                                  const char* pem_roots,
                                                  size_t pem_roots_size,
                                                  STACK_OF(X509_NAME) *
                                                      *root_names) {
  tsi_result result = TSI_OK;
  size_t num_roots = 0;
  X509* root = nullptr;
  X509_NAME* root_name = nullptr;
  BIO* pem;
  X509_STORE* root_store;
  GPR_ASSERT(pem_roots_size <= INT_MAX);
  pem = BIO_new_mem_buf((void*)pem_roots, (int)pem_roots_size);
  root_store = SSL_CTX_get_cert_store(context);
  if (root_store == nullptr) return TSI_INVALID_ARGUMENT;
  if (pem == nullptr) return TSI_OUT_OF_RESOURCES;
  if (root_names != nullptr) {
    *root_names = sk_X509_NAME_new_null();
    if (*root_names == nullptr) return TSI_OUT_OF_RESOURCES;
  }

  while (1) {
    root = PEM_read_bio_X509_AUX(pem, nullptr, nullptr, (void*)"");
    if (root == nullptr) {
      ERR_clear_error();
      break; /* We're at the end of stream. */
    }
    if (root_names != nullptr) {
      root_name = X509_get_subject_name(root);
      if (root_name == nullptr) {
        gpr_log(GPR_ERROR, "Could not get name from root certificate.");
        result = TSI_INVALID_ARGUMENT;
        break;
      }
      root_name = X509_NAME_dup(root_name);
      if (root_name == nullptr) {
        result = TSI_OUT_OF_RESOURCES;
        break;
      }
      sk_X509_NAME_push(*root_names, root_name);
      root_name = nullptr;
    }
    if (!X509_STORE_add_cert(root_store, root)) {
      gpr_log(GPR_ERROR, "Could not add root certificate to ssl context.");
      result = TSI_INTERNAL_ERROR;
      break;
    }
    X509_free(root);
    num_roots++;
  }

  if (num_roots == 0) {
    gpr_log(GPR_ERROR, "Could not load any root certificate.");
    result = TSI_INVALID_ARGUMENT;
  }

  if (result != TSI_OK) {
    if (root != nullptr) X509_free(root);
    if (root_names != nullptr) {
      sk_X509_NAME_pop_free(*root_names, X509_NAME_free);
      *root_names = nullptr;
      if (root_name != nullptr) X509_NAME_free(root_name);
    }
  }
  BIO_free(pem);
  return result;
}

/* Populates the SSL context with a private key and a cert chain, and sets the
   cipher list and the ephemeral ECDH key. */
static tsi_result populate_ssl_context(
    SSL_CTX* context, const tsi_ssl_pem_key_cert_pair* key_cert_pair,
    const char* cipher_list) {
  tsi_result result = TSI_OK;
  if (key_cert_pair != nullptr) {
    if (key_cert_pair->cert_chain != nullptr) {
      result = ssl_ctx_use_certificate_chain(context, key_cert_pair->cert_chain,
                                             strlen(key_cert_pair->cert_chain));
      if (result != TSI_OK) {
        gpr_log(GPR_ERROR, "Invalid cert chain file.");
        return result;
      }
    }
    if (key_cert_pair->private_key != nullptr) {
      result = ssl_ctx_use_private_key(context, key_cert_pair->private_key,
                                       strlen(key_cert_pair->private_key));
      if (result != TSI_OK || !SSL_CTX_check_private_key(context)) {
        gpr_log(GPR_ERROR, "Invalid private key.");
        return result != TSI_OK ? result : TSI_INVALID_ARGUMENT;
      }
    }
  }
  if ((cipher_list != nullptr) &&
      !SSL_CTX_set_cipher_list(context, cipher_list)) {
    gpr_log(GPR_ERROR, "Invalid cipher list: %s.", cipher_list);
    return TSI_INVALID_ARGUMENT;
  }
  {
    EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!SSL_CTX_set_tmp_ecdh(context, ecdh)) {
      gpr_log(GPR_ERROR, "Could not set ephemeral ECDH key.");
      EC_KEY_free(ecdh);
      return TSI_INTERNAL_ERROR;
    }
    SSL_CTX_set_options(context, SSL_OP_SINGLE_ECDH_USE);
    EC_KEY_free(ecdh);
  }
  return TSI_OK;
}

/* Extracts the CN and the SANs from an X509 cert as a peer object. */
static tsi_result extract_x509_subject_names_from_pem_cert(const char* pem_cert,
                                                           tsi_peer* peer) {
  tsi_result result = TSI_OK;
  X509* cert = nullptr;
  BIO* pem;
  pem = BIO_new_mem_buf((void*)pem_cert, (int)strlen(pem_cert));
  if (pem == nullptr) return TSI_OUT_OF_RESOURCES;

  cert = PEM_read_bio_X509(pem, nullptr, nullptr, (void*)"");
  if (cert == nullptr) {
    gpr_log(GPR_ERROR, "Invalid certificate");
    result = TSI_INVALID_ARGUMENT;
  } else {
    result = peer_from_x509(cert, 0, peer);
  }
  if (cert != nullptr) X509_free(cert);
  BIO_free(pem);
  return result;
}

/* Builds the alpn protocol name list according to rfc 7301. */
static tsi_result build_alpn_protocol_name_list(
    const char** alpn_protocols, uint16_t num_alpn_protocols,
    unsigned char** protocol_name_list, size_t* protocol_name_list_length) {
  uint16_t i;
  unsigned char* current;
  *protocol_name_list = nullptr;
  *protocol_name_list_length = 0;
  if (num_alpn_protocols == 0) return TSI_INVALID_ARGUMENT;
  for (i = 0; i < num_alpn_protocols; i++) {
    size_t length =
        alpn_protocols[i] == nullptr ? 0 : strlen(alpn_protocols[i]);
    if (length == 0 || length > 255) {
      gpr_log(GPR_ERROR, "Invalid protocol name length: %d.", (int)length);
      return TSI_INVALID_ARGUMENT;
    }
    *protocol_name_list_length += length + 1;
  }
  *protocol_name_list = (unsigned char*)gpr_malloc(*protocol_name_list_length);
  if (*protocol_name_list == nullptr) return TSI_OUT_OF_RESOURCES;
  current = *protocol_name_list;
  for (i = 0; i < num_alpn_protocols; i++) {
    size_t length = strlen(alpn_protocols[i]);
    *(current++) = (uint8_t)length; /* max checked above. */
    memcpy(current, alpn_protocols[i], length);
    current += length;
  }
  /* Safety check. */
  if ((current < *protocol_name_list) ||
      ((uintptr_t)(current - *protocol_name_list) !=
       *protocol_name_list_length)) {
    return TSI_INTERNAL_ERROR;
  }
  return TSI_OK;
}

// The verification callback is used for clients that don't really care about
// the server's certificate, but we need to pull it anyway, in case a higher
// layer wants to look at it. In this case the verification may fail, but
// we don't really care.
static int NullVerifyCallback(int preverify_ok, X509_STORE_CTX* ctx) {
  return 1;
}

/* --- tsi_frame_protector methods implementation. ---*/

static tsi_result ssl_protector_protect(tsi_frame_protector* self,
                                        const unsigned char* unprotected_bytes,
                                        size_t* unprotected_bytes_size,
                                        unsigned char* protected_output_frames,
                                        size_t* protected_output_frames_size) {
  tsi_ssl_frame_protector* impl = (tsi_ssl_frame_protector*)self;
  int read_from_ssl;
  size_t available;
  tsi_result result = TSI_OK;

  /* First see if we have some pending data in the SSL BIO. */
  int pending_in_ssl = (int)BIO_pending(impl->from_ssl);
  if (pending_in_ssl > 0) {
    *unprotected_bytes_size = 0;
    GPR_ASSERT(*protected_output_frames_size <= INT_MAX);
    read_from_ssl = BIO_read(impl->from_ssl, protected_output_frames,
                             (int)*protected_output_frames_size);
    if (read_from_ssl < 0) {
      gpr_log(GPR_ERROR,
              "Could not read from BIO even though some data is pending");
      return TSI_INTERNAL_ERROR;
    }
    *protected_output_frames_size = (size_t)read_from_ssl;
    return TSI_OK;
  }

  /* Now see if we can send a complete frame. */
  available = impl->buffer_size - impl->buffer_offset;
  if (available > *unprotected_bytes_size) {
    /* If we cannot, just copy the data in our internal buffer. */
    memcpy(impl->buffer + impl->buffer_offset, unprotected_bytes,
           *unprotected_bytes_size);
    impl->buffer_offset += *unprotected_bytes_size;
    *protected_output_frames_size = 0;
    return TSI_OK;
  }

  /* If we can, prepare the buffer, send it to SSL_write and read. */
  memcpy(impl->buffer + impl->buffer_offset, unprotected_bytes, available);
  result = do_ssl_write(impl->ssl, impl->buffer, impl->buffer_size);
  if (result != TSI_OK) return result;

  GPR_ASSERT(*protected_output_frames_size <= INT_MAX);
  read_from_ssl = BIO_read(impl->from_ssl, protected_output_frames,
                           (int)*protected_output_frames_size);
  if (read_from_ssl < 0) {
    gpr_log(GPR_ERROR, "Could not read from BIO after SSL_write.");
    return TSI_INTERNAL_ERROR;
  }
  *protected_output_frames_size = (size_t)read_from_ssl;
  *unprotected_bytes_size = available;
  impl->buffer_offset = 0;
  return TSI_OK;
}

static tsi_result ssl_protector_protect_flush(
    tsi_frame_protector* self, unsigned char* protected_output_frames,
    size_t* protected_output_frames_size, size_t* still_pending_size) {
  tsi_result result = TSI_OK;
  tsi_ssl_frame_protector* impl = (tsi_ssl_frame_protector*)self;
  int read_from_ssl = 0;
  int pending;

  if (impl->buffer_offset != 0) {
    result = do_ssl_write(impl->ssl, impl->buffer, impl->buffer_offset);
    if (result != TSI_OK) return result;
    impl->buffer_offset = 0;
  }

  pending = (int)BIO_pending(impl->from_ssl);
  GPR_ASSERT(pending >= 0);
  *still_pending_size = (size_t)pending;
  if (*still_pending_size == 0) return TSI_OK;

  GPR_ASSERT(*protected_output_frames_size <= INT_MAX);
  read_from_ssl = BIO_read(impl->from_ssl, protected_output_frames,
                           (int)*protected_output_frames_size);
  if (read_from_ssl <= 0) {
    gpr_log(GPR_ERROR, "Could not read from BIO after SSL_write.");
    return TSI_INTERNAL_ERROR;
  }
  *protected_output_frames_size = (size_t)read_from_ssl;
  pending = (int)BIO_pending(impl->from_ssl);
  GPR_ASSERT(pending >= 0);
  *still_pending_size = (size_t)pending;
  return TSI_OK;
}

static tsi_result ssl_protector_unprotect(
    tsi_frame_protector* self, const unsigned char* protected_frames_bytes,
    size_t* protected_frames_bytes_size, unsigned char* unprotected_bytes,
    size_t* unprotected_bytes_size) {
  tsi_result result = TSI_OK;
  int written_into_ssl = 0;
  size_t output_bytes_size = *unprotected_bytes_size;
  size_t output_bytes_offset = 0;
  tsi_ssl_frame_protector* impl = (tsi_ssl_frame_protector*)self;

  /* First, try to read remaining data from ssl. */
  result = do_ssl_read(impl->ssl, unprotected_bytes, unprotected_bytes_size);
  if (result != TSI_OK) return result;
  if (*unprotected_bytes_size == output_bytes_size) {
    /* We have read everything we could and cannot process any more input. */
    *protected_frames_bytes_size = 0;
    return TSI_OK;
  }
  output_bytes_offset = *unprotected_bytes_size;
  unprotected_bytes += output_bytes_offset;
  *unprotected_bytes_size = output_bytes_size - output_bytes_offset;

  /* Then, try to write some data to ssl. */
  GPR_ASSERT(*protected_frames_bytes_size <= INT_MAX);
  written_into_ssl = BIO_write(impl->into_ssl, protected_frames_bytes,
                               (int)*protected_frames_bytes_size);
  if (written_into_ssl < 0) {
    gpr_log(GPR_ERROR, "Sending protected frame to ssl failed with %d",
            written_into_ssl);
    return TSI_INTERNAL_ERROR;
  }
  *protected_frames_bytes_size = (size_t)written_into_ssl;

  /* Now try to read some data again. */
  result = do_ssl_read(impl->ssl, unprotected_bytes, unprotected_bytes_size);
  if (result == TSI_OK) {
    /* Don't forget to output the total number of bytes read. */
    *unprotected_bytes_size += output_bytes_offset;
  }
  return result;
}

static void ssl_protector_destroy(tsi_frame_protector* self) {
  tsi_ssl_frame_protector* impl = (tsi_ssl_frame_protector*)self;
  if (impl->buffer != nullptr) gpr_free(impl->buffer);
  if (impl->ssl != nullptr) SSL_free(impl->ssl);
  gpr_free(self);
}

static const tsi_frame_protector_vtable frame_protector_vtable = {
    ssl_protector_protect,
    ssl_protector_protect_flush,
    ssl_protector_unprotect,
    ssl_protector_destroy,
};

/* --- tsi_server_handshaker_factory methods implementation. --- */

static void tsi_ssl_handshaker_factory_destroy(
    tsi_ssl_handshaker_factory* self) {
  if (self == nullptr) return;

  if (self->vtable != nullptr && self->vtable->destroy != nullptr) {
    self->vtable->destroy(self);
  }
  /* Note, we don't free(self) here because this object is always directly
   * embedded in another object. If tsi_ssl_handshaker_factory_init allocates
   * any memory, it should be free'd here. */
}

static tsi_ssl_handshaker_factory* tsi_ssl_handshaker_factory_ref(
    tsi_ssl_handshaker_factory* self) {
  if (self == nullptr) return nullptr;
  gpr_refn(&self->refcount, 1);
  return self;
}

static void tsi_ssl_handshaker_factory_unref(tsi_ssl_handshaker_factory* self) {
  if (self == nullptr) return;

  if (gpr_unref(&self->refcount)) {
    tsi_ssl_handshaker_factory_destroy(self);
  }
}

static tsi_ssl_handshaker_factory_vtable handshaker_factory_vtable = {nullptr};

/* Initializes a tsi_ssl_handshaker_factory object. Caller is responsible for
 * allocating memory for the factory. */
static void tsi_ssl_handshaker_factory_init(
    tsi_ssl_handshaker_factory* factory) {
  GPR_ASSERT(factory != nullptr);

  factory->vtable = &handshaker_factory_vtable;
  gpr_ref_init(&factory->refcount, 1);
}

/* --- tsi_handshaker methods implementation. ---*/

static tsi_result ssl_handshaker_get_bytes_to_send_to_peer(tsi_handshaker* self,
                                                           unsigned char* bytes,
                                                           size_t* bytes_size) {
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  int bytes_read_from_ssl = 0;
  if (bytes == nullptr || bytes_size == nullptr || *bytes_size == 0 ||
      *bytes_size > INT_MAX) {
    return TSI_INVALID_ARGUMENT;
  }
  GPR_ASSERT(*bytes_size <= INT_MAX);
  bytes_read_from_ssl = BIO_read(impl->from_ssl, bytes, (int)*bytes_size);
  if (bytes_read_from_ssl < 0) {
    *bytes_size = 0;
    if (!BIO_should_retry(impl->from_ssl)) {
      impl->result = TSI_INTERNAL_ERROR;
      return impl->result;
    } else {
      return TSI_OK;
    }
  }
  *bytes_size = (size_t)bytes_read_from_ssl;
  return BIO_pending(impl->from_ssl) == 0 ? TSI_OK : TSI_INCOMPLETE_DATA;
}

static tsi_result ssl_handshaker_get_result(tsi_handshaker* self) {
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  if ((impl->result == TSI_HANDSHAKE_IN_PROGRESS) &&
      SSL_is_init_finished(impl->ssl)) {
    impl->result = TSI_OK;
  }
  return impl->result;
}

static tsi_result ssl_handshaker_process_bytes_from_peer(
    tsi_handshaker* self, const unsigned char* bytes, size_t* bytes_size) {
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  int bytes_written_into_ssl_size = 0;
  if (bytes == nullptr || bytes_size == nullptr || *bytes_size > INT_MAX) {
    return TSI_INVALID_ARGUMENT;
  }
  GPR_ASSERT(*bytes_size <= INT_MAX);
  bytes_written_into_ssl_size =
      BIO_write(impl->into_ssl, bytes, (int)*bytes_size);
  if (bytes_written_into_ssl_size < 0) {
    gpr_log(GPR_ERROR, "Could not write to memory BIO.");
    impl->result = TSI_INTERNAL_ERROR;
    return impl->result;
  }
  *bytes_size = (size_t)bytes_written_into_ssl_size;

  if (!tsi_handshaker_is_in_progress(self)) {
    impl->result = TSI_OK;
    return impl->result;
  } else {
    /* Get ready to get some bytes from SSL. */
    int ssl_result = SSL_do_handshake(impl->ssl);
    ssl_result = SSL_get_error(impl->ssl, ssl_result);
    switch (ssl_result) {
      case SSL_ERROR_WANT_READ:
        if (BIO_pending(impl->from_ssl) == 0) {
          /* We need more data. */
          return TSI_INCOMPLETE_DATA;
        } else {
          return TSI_OK;
        }
      case SSL_ERROR_NONE:
        return TSI_OK;
      default: {
        char err_str[256];
        ERR_error_string_n(ERR_get_error(), err_str, sizeof(err_str));
        gpr_log(GPR_ERROR, "Handshake failed with fatal error %s: %s.",
                ssl_error_string(ssl_result), err_str);
        impl->result = TSI_PROTOCOL_FAILURE;
        return impl->result;
      }
    }
  }
}

static tsi_result ssl_handshaker_extract_peer(tsi_handshaker* self,
                                              tsi_peer* peer) {
  tsi_result result = TSI_OK;
  const unsigned char* alpn_selected = nullptr;
  unsigned int alpn_selected_len;
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  X509* peer_cert = SSL_get_peer_certificate(impl->ssl);
  if (peer_cert != nullptr) {
    result = peer_from_x509(peer_cert, 1, peer);
    X509_free(peer_cert);
    if (result != TSI_OK) return result;
  }
#if TSI_OPENSSL_ALPN_SUPPORT
  SSL_get0_alpn_selected(impl->ssl, &alpn_selected, &alpn_selected_len);
#endif /* TSI_OPENSSL_ALPN_SUPPORT */
  if (alpn_selected == nullptr) {
    /* Try npn. */
    SSL_get0_next_proto_negotiated(impl->ssl, &alpn_selected,
                                   &alpn_selected_len);
  }
  if (alpn_selected != nullptr) {
    size_t i;
    tsi_peer_property* new_properties = (tsi_peer_property*)gpr_zalloc(
        sizeof(*new_properties) * (peer->property_count + 1));
    for (i = 0; i < peer->property_count; i++) {
      new_properties[i] = peer->properties[i];
    }
    result = tsi_construct_string_peer_property(
        TSI_SSL_ALPN_SELECTED_PROTOCOL, (const char*)alpn_selected,
        alpn_selected_len, &new_properties[peer->property_count]);
    if (result != TSI_OK) {
      gpr_free(new_properties);
      return result;
    }
    if (peer->properties != nullptr) gpr_free(peer->properties);
    peer->property_count++;
    peer->properties = new_properties;
  }
  return result;
}

static tsi_result ssl_handshaker_create_frame_protector(
    tsi_handshaker* self, size_t* max_output_protected_frame_size,
    tsi_frame_protector** protector) {
  size_t actual_max_output_protected_frame_size =
      TSI_SSL_MAX_PROTECTED_FRAME_SIZE_UPPER_BOUND;
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  tsi_ssl_frame_protector* protector_impl =
      (tsi_ssl_frame_protector*)gpr_zalloc(sizeof(*protector_impl));

  if (max_output_protected_frame_size != nullptr) {
    if (*max_output_protected_frame_size >
        TSI_SSL_MAX_PROTECTED_FRAME_SIZE_UPPER_BOUND) {
      *max_output_protected_frame_size =
          TSI_SSL_MAX_PROTECTED_FRAME_SIZE_UPPER_BOUND;
    } else if (*max_output_protected_frame_size <
               TSI_SSL_MAX_PROTECTED_FRAME_SIZE_LOWER_BOUND) {
      *max_output_protected_frame_size =
          TSI_SSL_MAX_PROTECTED_FRAME_SIZE_LOWER_BOUND;
    }
    actual_max_output_protected_frame_size = *max_output_protected_frame_size;
  }
  protector_impl->buffer_size =
      actual_max_output_protected_frame_size - TSI_SSL_MAX_PROTECTION_OVERHEAD;
  protector_impl->buffer =
      (unsigned char*)gpr_malloc(protector_impl->buffer_size);
  if (protector_impl->buffer == nullptr) {
    gpr_log(GPR_ERROR,
            "Could not allocated buffer for tsi_ssl_frame_protector.");
    gpr_free(protector_impl);
    return TSI_INTERNAL_ERROR;
  }

  /* Transfer ownership of ssl to the frame protector. It is OK as the caller
   * cannot call anything else but destroy on the handshaker after this call. */
  protector_impl->ssl = impl->ssl;
  impl->ssl = nullptr;
  protector_impl->into_ssl = impl->into_ssl;
  protector_impl->from_ssl = impl->from_ssl;

  protector_impl->base.vtable = &frame_protector_vtable;
  *protector = &protector_impl->base;
  return TSI_OK;
}

static void ssl_handshaker_destroy(tsi_handshaker* self) {
  tsi_ssl_handshaker* impl = (tsi_ssl_handshaker*)self;
  SSL_free(impl->ssl); /* The BIO objects are owned by ssl */
  tsi_ssl_handshaker_factory_unref(impl->factory_ref);
  gpr_free(impl);
}

static const tsi_handshaker_vtable handshaker_vtable = {
    ssl_handshaker_get_bytes_to_send_to_peer,
    ssl_handshaker_process_bytes_from_peer,
    ssl_handshaker_get_result,
    ssl_handshaker_extract_peer,
    ssl_handshaker_create_frame_protector,
    ssl_handshaker_destroy,
    nullptr,
};

/* --- tsi_ssl_handshaker_factory common methods. --- */

static tsi_result create_tsi_ssl_handshaker(SSL_CTX* ctx, int is_client,
                                            const char* server_name_indication,
                                            tsi_ssl_handshaker_factory* factory,
                                            tsi_handshaker** handshaker) {
  SSL* ssl = SSL_new(ctx);
  BIO* into_ssl = nullptr;
  BIO* from_ssl = nullptr;
  tsi_ssl_handshaker* impl = nullptr;
  *handshaker = nullptr;
  if (ctx == nullptr) {
    gpr_log(GPR_ERROR, "SSL Context is null. Should never happen.");
    return TSI_INTERNAL_ERROR;
  }
  if (ssl == nullptr) {
    return TSI_OUT_OF_RESOURCES;
  }
  SSL_set_info_callback(ssl, ssl_info_callback);

  into_ssl = BIO_new(BIO_s_mem());
  from_ssl = BIO_new(BIO_s_mem());
  if (into_ssl == nullptr || from_ssl == nullptr) {
    gpr_log(GPR_ERROR, "BIO_new failed.");
    SSL_free(ssl);
    if (into_ssl != nullptr) BIO_free(into_ssl);
    if (from_ssl != nullptr) BIO_free(into_ssl);
    return TSI_OUT_OF_RESOURCES;
  }
  SSL_set_bio(ssl, into_ssl, from_ssl);
  if (is_client) {
    int ssl_result;
    SSL_set_connect_state(ssl);
    if (server_name_indication != nullptr) {
      if (!SSL_set_tlsext_host_name(ssl, server_name_indication)) {
        gpr_log(GPR_ERROR, "Invalid server name indication %s.",
                server_name_indication);
        SSL_free(ssl);
        return TSI_INTERNAL_ERROR;
      }
    }
    ssl_result = SSL_do_handshake(ssl);
    ssl_result = SSL_get_error(ssl, ssl_result);
    if (ssl_result != SSL_ERROR_WANT_READ) {
      gpr_log(GPR_ERROR,
              "Unexpected error received from first SSL_do_handshake call: %s",
              ssl_error_string(ssl_result));
      SSL_free(ssl);
      return TSI_INTERNAL_ERROR;
    }
  } else {
    SSL_set_accept_state(ssl);
  }

  impl = (tsi_ssl_handshaker*)gpr_zalloc(sizeof(*impl));
  impl->ssl = ssl;
  impl->into_ssl = into_ssl;
  impl->from_ssl = from_ssl;
  impl->result = TSI_HANDSHAKE_IN_PROGRESS;
  impl->base.vtable = &handshaker_vtable;
  impl->factory_ref = tsi_ssl_handshaker_factory_ref(factory);

  *handshaker = &impl->base;
  return TSI_OK;
}

static int select_protocol_list(const unsigned char** out,
                                unsigned char* outlen,
                                const unsigned char* client_list,
                                size_t client_list_len,
                                const unsigned char* server_list,
                                size_t server_list_len) {
  const unsigned char* client_current = client_list;
  while ((unsigned int)(client_current - client_list) < client_list_len) {
    unsigned char client_current_len = *(client_current++);
    const unsigned char* server_current = server_list;
    while ((server_current >= server_list) &&
           (uintptr_t)(server_current - server_list) < server_list_len) {
      unsigned char server_current_len = *(server_current++);
      if ((client_current_len == server_current_len) &&
          !memcmp(client_current, server_current, server_current_len)) {
        *out = server_current;
        *outlen = server_current_len;
        return SSL_TLSEXT_ERR_OK;
      }
      server_current += server_current_len;
    }
    client_current += client_current_len;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

/* --- tsi_ssl_client_handshaker_factory methods implementation. --- */

tsi_result tsi_ssl_client_handshaker_factory_create_handshaker(
    tsi_ssl_client_handshaker_factory* self, const char* server_name_indication,
    tsi_handshaker** handshaker) {
  return create_tsi_ssl_handshaker(self->ssl_context, 1, server_name_indication,
                                   &self->base, handshaker);
}

void tsi_ssl_client_handshaker_factory_unref(
    tsi_ssl_client_handshaker_factory* self) {
  if (self == nullptr) return;
  tsi_ssl_handshaker_factory_unref(&self->base);
}

static void tsi_ssl_client_handshaker_factory_destroy(
    tsi_ssl_handshaker_factory* factory) {
  if (factory == nullptr) return;
  tsi_ssl_client_handshaker_factory* self =
      (tsi_ssl_client_handshaker_factory*)factory;
  if (self->ssl_context != nullptr) SSL_CTX_free(self->ssl_context);
  if (self->alpn_protocol_list != nullptr) gpr_free(self->alpn_protocol_list);
  gpr_free(self);
}

static int client_handshaker_factory_npn_callback(SSL* ssl, unsigned char** out,
                                                  unsigned char* outlen,
                                                  const unsigned char* in,
                                                  unsigned int inlen,
                                                  void* arg) {
  tsi_ssl_client_handshaker_factory* factory =
      (tsi_ssl_client_handshaker_factory*)arg;
  return select_protocol_list((const unsigned char**)out, outlen,
                              factory->alpn_protocol_list,
                              factory->alpn_protocol_list_length, in, inlen);
}

/* --- tsi_ssl_server_handshaker_factory methods implementation. --- */

tsi_result tsi_ssl_server_handshaker_factory_create_handshaker(
    tsi_ssl_server_handshaker_factory* self, tsi_handshaker** handshaker) {
  if (self->ssl_context_count == 0) return TSI_INVALID_ARGUMENT;
  /* Create the handshaker with the first context. We will switch if needed
     because of SNI in ssl_server_handshaker_factory_servername_callback.  */
  return create_tsi_ssl_handshaker(self->ssl_contexts[0], 0, nullptr,
                                   &self->base, handshaker);
}

void tsi_ssl_server_handshaker_factory_unref(
    tsi_ssl_server_handshaker_factory* self) {
  if (self == nullptr) return;
  tsi_ssl_handshaker_factory_unref(&self->base);
}

static void tsi_ssl_server_handshaker_factory_destroy(
    tsi_ssl_handshaker_factory* factory) {
  if (factory == nullptr) return;
  tsi_ssl_server_handshaker_factory* self =
      (tsi_ssl_server_handshaker_factory*)factory;
  size_t i;
  for (i = 0; i < self->ssl_context_count; i++) {
    if (self->ssl_contexts[i] != nullptr) {
      SSL_CTX_free(self->ssl_contexts[i]);
      tsi_peer_destruct(&self->ssl_context_x509_subject_names[i]);
    }
  }
  if (self->ssl_contexts != nullptr) gpr_free(self->ssl_contexts);
  if (self->ssl_context_x509_subject_names != nullptr) {
    gpr_free(self->ssl_context_x509_subject_names);
  }
  if (self->alpn_protocol_list != nullptr) gpr_free(self->alpn_protocol_list);
  gpr_free(self);
}

static int does_entry_match_name(const char* entry, size_t entry_length,
                                 const char* name) {
  const char* dot;
  const char* name_subdomain = nullptr;
  size_t name_length = strlen(name);
  size_t name_subdomain_length;
  if (entry_length == 0) return 0;

  /* Take care of '.' terminations. */
  if (name[name_length - 1] == '.') {
    name_length--;
  }
  if (entry[entry_length - 1] == '.') {
    entry_length--;
    if (entry_length == 0) return 0;
  }

  if ((name_length == entry_length) &&
      strncmp(name, entry, entry_length) == 0) {
    return 1; /* Perfect match. */
  }
  if (entry[0] != '*') return 0;

  /* Wildchar subdomain matching. */
  if (entry_length < 3 || entry[1] != '.') { /* At least *.x */
    gpr_log(GPR_ERROR, "Invalid wildchar entry.");
    return 0;
  }
  name_subdomain = strchr(name, '.');
  if (name_subdomain == nullptr) return 0;
  name_subdomain_length = strlen(name_subdomain);
  if (name_subdomain_length < 2) return 0;
  name_subdomain++; /* Starts after the dot. */
  name_subdomain_length--;
  entry += 2; /* Remove *. */
  entry_length -= 2;
  dot = strchr(name_subdomain, '.');
  if ((dot == nullptr) || (dot == &name_subdomain[name_subdomain_length - 1])) {
    gpr_log(GPR_ERROR, "Invalid toplevel subdomain: %s", name_subdomain);
    return 0;
  }
  if (name_subdomain[name_subdomain_length - 1] == '.') {
    name_subdomain_length--;
  }
  return ((entry_length > 0) && (name_subdomain_length == entry_length) &&
          strncmp(entry, name_subdomain, entry_length) == 0);
}

static int ssl_server_handshaker_factory_servername_callback(SSL* ssl, int* ap,
                                                             void* arg) {
  tsi_ssl_server_handshaker_factory* impl =
      (tsi_ssl_server_handshaker_factory*)arg;
  size_t i = 0;
  const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (servername == nullptr || strlen(servername) == 0) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  for (i = 0; i < impl->ssl_context_count; i++) {
    if (tsi_ssl_peer_matches_name(&impl->ssl_context_x509_subject_names[i],
                                  servername)) {
      SSL_set_SSL_CTX(ssl, impl->ssl_contexts[i]);
      return SSL_TLSEXT_ERR_OK;
    }
  }
  gpr_log(GPR_ERROR, "No match found for server name: %s.", servername);
  return SSL_TLSEXT_ERR_ALERT_WARNING;
}

#if TSI_OPENSSL_ALPN_SUPPORT
static int server_handshaker_factory_alpn_callback(
    SSL* ssl, const unsigned char** out, unsigned char* outlen,
    const unsigned char* in, unsigned int inlen, void* arg) {
  tsi_ssl_server_handshaker_factory* factory =
      (tsi_ssl_server_handshaker_factory*)arg;
  return select_protocol_list(out, outlen, in, inlen,
                              factory->alpn_protocol_list,
                              factory->alpn_protocol_list_length);
}
#endif /* TSI_OPENSSL_ALPN_SUPPORT */

static int server_handshaker_factory_npn_advertised_callback(
    SSL* ssl, const unsigned char** out, unsigned int* outlen, void* arg) {
  tsi_ssl_server_handshaker_factory* factory =
      (tsi_ssl_server_handshaker_factory*)arg;
  *out = factory->alpn_protocol_list;
  GPR_ASSERT(factory->alpn_protocol_list_length <= UINT_MAX);
  *outlen = (unsigned int)factory->alpn_protocol_list_length;
  return SSL_TLSEXT_ERR_OK;
}

/* --- tsi_ssl_handshaker_factory constructors. --- */

static tsi_ssl_handshaker_factory_vtable client_handshaker_factory_vtable = {
    tsi_ssl_client_handshaker_factory_destroy};

tsi_result tsi_create_ssl_client_handshaker_factory(
    const tsi_ssl_pem_key_cert_pair* pem_key_cert_pair,
    const char* pem_root_certs, const char* cipher_suites,
    const char** alpn_protocols, uint16_t num_alpn_protocols,
    tsi_ssl_client_handshaker_factory** factory) {
  SSL_CTX* ssl_context = nullptr;
  tsi_ssl_client_handshaker_factory* impl = nullptr;
  tsi_result result = TSI_OK;

  gpr_once_init(&init_openssl_once, init_openssl);

  if (factory == nullptr) return TSI_INVALID_ARGUMENT;
  *factory = nullptr;
  if (pem_root_certs == nullptr) return TSI_INVALID_ARGUMENT;

  ssl_context = SSL_CTX_new(TLSv1_2_method());
  if (ssl_context == nullptr) {
    gpr_log(GPR_ERROR, "Could not create ssl context.");
    return TSI_INVALID_ARGUMENT;
  }

  impl = (tsi_ssl_client_handshaker_factory*)gpr_zalloc(sizeof(*impl));
  tsi_ssl_handshaker_factory_init(&impl->base);
  impl->base.vtable = &client_handshaker_factory_vtable;

  impl->ssl_context = ssl_context;

  do {
    result =
        populate_ssl_context(ssl_context, pem_key_cert_pair, cipher_suites);
    if (result != TSI_OK) break;
    result = ssl_ctx_load_verification_certs(ssl_context, pem_root_certs,
                                             strlen(pem_root_certs), nullptr);
    if (result != TSI_OK) {
      gpr_log(GPR_ERROR, "Cannot load server root certificates.");
      break;
    }

    if (num_alpn_protocols != 0) {
      result = build_alpn_protocol_name_list(alpn_protocols, num_alpn_protocols,
                                             &impl->alpn_protocol_list,
                                             &impl->alpn_protocol_list_length);
      if (result != TSI_OK) {
        gpr_log(GPR_ERROR, "Building alpn list failed with error %s.",
                tsi_result_to_string(result));
        break;
      }
#if TSI_OPENSSL_ALPN_SUPPORT
      GPR_ASSERT(impl->alpn_protocol_list_length < UINT_MAX);
      if (SSL_CTX_set_alpn_protos(
              ssl_context, impl->alpn_protocol_list,
              (unsigned int)impl->alpn_protocol_list_length)) {
        gpr_log(GPR_ERROR, "Could not set alpn protocol list to context.");
        result = TSI_INVALID_ARGUMENT;
        break;
      }
#endif /* TSI_OPENSSL_ALPN_SUPPORT */
      SSL_CTX_set_next_proto_select_cb(
          ssl_context, client_handshaker_factory_npn_callback, impl);
    }
  } while (0);
  if (result != TSI_OK) {
    tsi_ssl_handshaker_factory_unref(&impl->base);
    return result;
  }
  SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, nullptr);
  /* TODO(jboeuf): Add revocation verification. */

  *factory = impl;
  return TSI_OK;
}

static tsi_ssl_handshaker_factory_vtable server_handshaker_factory_vtable = {
    tsi_ssl_server_handshaker_factory_destroy};

tsi_result tsi_create_ssl_server_handshaker_factory(
    const tsi_ssl_pem_key_cert_pair* pem_key_cert_pairs,
    size_t num_key_cert_pairs, const char* pem_client_root_certs,
    int force_client_auth, const char* cipher_suites,
    const char** alpn_protocols, uint16_t num_alpn_protocols,
    tsi_ssl_server_handshaker_factory** factory) {
  return tsi_create_ssl_server_handshaker_factory_ex(
      pem_key_cert_pairs, num_key_cert_pairs, pem_client_root_certs,
      force_client_auth ? TSI_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY
                        : TSI_DONT_REQUEST_CLIENT_CERTIFICATE,
      cipher_suites, alpn_protocols, num_alpn_protocols, factory);
}

tsi_result tsi_create_ssl_server_handshaker_factory_ex(
    const tsi_ssl_pem_key_cert_pair* pem_key_cert_pairs,
    size_t num_key_cert_pairs, const char* pem_client_root_certs,
    tsi_client_certificate_request_type client_certificate_request,
    const char* cipher_suites, const char** alpn_protocols,
    uint16_t num_alpn_protocols, tsi_ssl_server_handshaker_factory** factory) {
  tsi_ssl_server_handshaker_factory* impl = nullptr;
  tsi_result result = TSI_OK;
  size_t i = 0;

  gpr_once_init(&init_openssl_once, init_openssl);

  if (factory == nullptr) return TSI_INVALID_ARGUMENT;
  *factory = nullptr;
  if (num_key_cert_pairs == 0 || pem_key_cert_pairs == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }

  impl = (tsi_ssl_server_handshaker_factory*)gpr_zalloc(sizeof(*impl));
  tsi_ssl_handshaker_factory_init(&impl->base);
  impl->base.vtable = &server_handshaker_factory_vtable;

  impl->ssl_contexts =
      (SSL_CTX**)gpr_zalloc(num_key_cert_pairs * sizeof(SSL_CTX*));
  impl->ssl_context_x509_subject_names =
      (tsi_peer*)gpr_zalloc(num_key_cert_pairs * sizeof(tsi_peer));
  if (impl->ssl_contexts == nullptr ||
      impl->ssl_context_x509_subject_names == nullptr) {
    tsi_ssl_handshaker_factory_unref(&impl->base);
    return TSI_OUT_OF_RESOURCES;
  }
  impl->ssl_context_count = num_key_cert_pairs;

  if (num_alpn_protocols > 0) {
    result = build_alpn_protocol_name_list(alpn_protocols, num_alpn_protocols,
                                           &impl->alpn_protocol_list,
                                           &impl->alpn_protocol_list_length);
    if (result != TSI_OK) {
      tsi_ssl_handshaker_factory_unref(&impl->base);
      return result;
    }
  }

  for (i = 0; i < num_key_cert_pairs; i++) {
    do {
      impl->ssl_contexts[i] = SSL_CTX_new(TLSv1_2_method());
      if (impl->ssl_contexts[i] == nullptr) {
        gpr_log(GPR_ERROR, "Could not create ssl context.");
        result = TSI_OUT_OF_RESOURCES;
        break;
      }
      result = populate_ssl_context(impl->ssl_contexts[i],
                                    &pem_key_cert_pairs[i], cipher_suites);
      if (result != TSI_OK) break;

      if (pem_client_root_certs != nullptr) {
        STACK_OF(X509_NAME)* root_names = nullptr;
        result = ssl_ctx_load_verification_certs(
            impl->ssl_contexts[i], pem_client_root_certs,
            strlen(pem_client_root_certs), &root_names);
        if (result != TSI_OK) {
          gpr_log(GPR_ERROR, "Invalid verification certs.");
          break;
        }
        SSL_CTX_set_client_CA_list(impl->ssl_contexts[i], root_names);
        switch (client_certificate_request) {
          case TSI_DONT_REQUEST_CLIENT_CERTIFICATE:
            SSL_CTX_set_verify(impl->ssl_contexts[i], SSL_VERIFY_NONE, nullptr);
            break;
          case TSI_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY:
            SSL_CTX_set_verify(impl->ssl_contexts[i], SSL_VERIFY_PEER,
                               NullVerifyCallback);
            break;
          case TSI_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY:
            SSL_CTX_set_verify(impl->ssl_contexts[i], SSL_VERIFY_PEER, nullptr);
            break;
          case TSI_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY:
            SSL_CTX_set_verify(
                impl->ssl_contexts[i],
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                NullVerifyCallback);
            break;
          case TSI_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY:
            SSL_CTX_set_verify(
                impl->ssl_contexts[i],
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            break;
        }
        /* TODO(jboeuf): Add revocation verification. */
      }

      result = extract_x509_subject_names_from_pem_cert(
          pem_key_cert_pairs[i].cert_chain,
          &impl->ssl_context_x509_subject_names[i]);
      if (result != TSI_OK) break;

      SSL_CTX_set_tlsext_servername_callback(
          impl->ssl_contexts[i],
          ssl_server_handshaker_factory_servername_callback);
      SSL_CTX_set_tlsext_servername_arg(impl->ssl_contexts[i], impl);
#if TSI_OPENSSL_ALPN_SUPPORT
      SSL_CTX_set_alpn_select_cb(impl->ssl_contexts[i],
                                 server_handshaker_factory_alpn_callback, impl);
#endif /* TSI_OPENSSL_ALPN_SUPPORT */
      SSL_CTX_set_next_protos_advertised_cb(
          impl->ssl_contexts[i],
          server_handshaker_factory_npn_advertised_callback, impl);
    } while (0);

    if (result != TSI_OK) {
      tsi_ssl_handshaker_factory_unref(&impl->base);
      return result;
    }
  }

  *factory = impl;
  return TSI_OK;
}

/* --- tsi_ssl utils. --- */

int tsi_ssl_peer_matches_name(const tsi_peer* peer, const char* name) {
  size_t i = 0;
  size_t san_count = 0;
  const tsi_peer_property* cn_property = nullptr;
  int like_ip = looks_like_ip_address(name);

  /* Check the SAN first. */
  for (i = 0; i < peer->property_count; i++) {
    const tsi_peer_property* property = &peer->properties[i];
    if (property->name == nullptr) continue;
    if (strcmp(property->name,
               TSI_X509_SUBJECT_ALTERNATIVE_NAME_PEER_PROPERTY) == 0) {
      san_count++;

      if (!like_ip && does_entry_match_name(property->value.data,
                                            property->value.length, name)) {
        return 1;
      } else if (like_ip &&
                 strncmp(name, property->value.data, property->value.length) ==
                     0 &&
                 strlen(name) == property->value.length) {
        /* IP Addresses are exact matches only. */
        return 1;
      }
    } else if (strcmp(property->name,
                      TSI_X509_SUBJECT_COMMON_NAME_PEER_PROPERTY) == 0) {
      cn_property = property;
    }
  }

  /* If there's no SAN, try the CN, but only if its not like an IP Address */
  if (san_count == 0 && cn_property != nullptr && !like_ip) {
    if (does_entry_match_name(cn_property->value.data,
                              cn_property->value.length, name)) {
      return 1;
    }
  }

  return 0; /* Not found. */
}

/* --- Testing support. --- */
const tsi_ssl_handshaker_factory_vtable* tsi_ssl_handshaker_factory_swap_vtable(
    tsi_ssl_handshaker_factory* factory,
    tsi_ssl_handshaker_factory_vtable* new_vtable) {
  GPR_ASSERT(factory != nullptr);
  GPR_ASSERT(factory->vtable != nullptr);

  const tsi_ssl_handshaker_factory_vtable* orig_vtable = factory->vtable;
  factory->vtable = new_vtable;
  return orig_vtable;
}
