/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

/* This header equalizes a lot of OpenSSL 1.1.0 vs. 1.1.1
   API clashes by defining some macros if OpenSSL < 1.1.1
   is used. This way the code is written with the new API
   and have much less #ifdefs
*/

#ifndef __OPENSS_COMPAT_XCA_H
#define __OPENSS_COMPAT_XCA_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L

static inline int
EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
		size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	return EVP_DigestSignUpdate(ctx, tbs, tbslen) &&
		EVP_DigestSignFinal(ctx, sigret, siglen);
}

static inline int
EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
		size_t siglen, const unsigned char *tbs, size_t tbslen)
{
	return EVP_DigestVerifyUpdate(ctx, tbs, tbslen) &&
		EVP_DigestVerifyFinal(ctx, (unsigned char *)sigret, siglen);
}
#endif

#endif
