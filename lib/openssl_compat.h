/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

/* This header equalizes a lot of OpenSSL 1.1.0 vs. 1.0.0
   API clashes by defining some macros if OpenSSL < 1.1.0
   is used. This way the code is written with the new API
   and have much less #ifdefs
*/

#ifndef __OPENSS_COMPAT_XCA_H
#define __OPENSS_COMPAT_XCA_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#define RAND_bytes(buf, size) RAND_pseudo_bytes((buf), (size))

#define X509_get0_extensions(cert) ((cert)->cert_info->extensions)
#define X509_get_signature_nid(cert) OBJ_obj2nid((cert)->sig_alg->algorithm)
#define X509_REQ_get_signature_nid(req) OBJ_obj2nid((req)->sig_alg->algorithm)

#define EVP_PKEY_set_type(key, type) ((key)->type = (type))
#define EVP_PKEY_id(pkey) ((pkey)->type)

#define X509_REVOKED_get0_serialNumber(r) (r->serialNumber)
#define X509_REVOKED_get0_revocationDate(r) (r->revocationDate)

#define DSA_SIG_set0(dsa_sig, r, s) ((dsa_sig)->r = r, (dsa_sig)->s = s)
#define RSA_set0_key(r,_n,_e,_d) ((r)->n=(_n),(r)->e=(_e),(r)->d=(_d))
#define DSA_set0_pqg(d,_p,_q,_g) ((d)->p=(_p),(d)->q=(_q),(d)->g=(_g))
#define DSA_set0_key(d,pub,priv) ((d)->pub_key=(pub),(d)->priv_key=(priv))
#define EVP_PKEY_get0_DSA(pub) ((pub)->pkey.dsa)
#define EVP_PKEY_get0_RSA(pub) ((pub)->pkey.rsa)
#define EVP_PKEY_get0_EC_KEY(pub) ((pub)->pkey.ec)
#define EVP_PKEY_get0(p) ((p)->pkey.ptr)

#define X509_CRL_get_signature_nid(crl) OBJ_obj2nid((crl)->sig_alg->algorithm)
#define X509_CRL_get0_extensions(crl) ((crl)->crl->extensions)
#define X509_CRL_get0_lastUpdate(crl) ((crl)->crl->lastUpdate)
#define X509_CRL_get0_nextUpdate(crl) ((crl)->crl->nextUpdate)

static inline void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if (n) *n = r->n;
	if (e) *e = r->e;
	if (d) *d = r->d;
}

static inline void
DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
	if (p) *p = d->p;
	if (q) *q = d->q;
	if (g) *g = d->g;
}

static inline void
DSA_get0_key(const DSA *d, const BIGNUM **pub, const BIGNUM **priv)
{
	if (priv) *priv = d->priv_key;
	if (pub)  *pub  = d->pub_key;
}

static inline void
RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
	if (p) *p = r->p;
	if (q) *q = r->q;
}
static inline void
RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1,
							const BIGNUM **iqmp)
{
	if (dmp1) *dmp1=r->dmp1;
	if (dmq1) *dmq1=r->dmq1;
	if (iqmp) *iqmp=r->iqmp;
}

#endif

#endif
