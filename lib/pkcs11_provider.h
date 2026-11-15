/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 bardimnik
 *
 * OpenSSL provider for Ed25519 signatures on PKCS#11 tokens.
 * Available on OpenSSL >= 3.0 only (XCA_HAS_PROVIDERS).
 */
#ifndef __PKCS11_PROVIDER_H
#define __PKCS11_PROVIDER_H

#include "openssl_compat.h"

#if XCA_HAS_PROVIDERS

#include <openssl/evp.h>
#include "opensc-pkcs11.h"

/* Create a provider-native ED25519 EVP_PKEY whose signature operations
 * are performed by the token (C_Sign with CKM_EDDSA). Returns NULL on
 * failure; the caller owns the returned key.
 *
 * Only the one-shot EVP_DigestSign() is supported (no streaming
 * update/final); this is what X509_sign() uses. The provider key keeps
 * the PKCS#11 session and object handles it was created with — the
 * session must outlive the key. */
EVP_PKEY *pkcs11_provider_key(const unsigned char *pub, size_t publen,
			CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE object);

#endif /* XCA_HAS_PROVIDERS */
#endif
