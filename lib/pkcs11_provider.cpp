/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 bardimnik
 *
 * An OpenSSL provider that routes Ed25519 signature operations to a
 * PKCS#11 token (C_Sign with CKM_EDDSA).
 *
 * The provider is registered in-process with OSSL_PROVIDER_add_builtin()
 * and carries no global state: every provider key embeds the PKCS#11
 * context (function list, session, object handle) it belongs to, passed
 * through a private OSSL_PARAM at key import time.
 *
 * Used by pkcs11::getPrivateKey() instead of the deprecated ENGINE /
 * EVP_PKEY_METHOD mechanism on OpenSSL >= 3.0.
 */
#include "base.h"
#include "openssl_compat.h"

#if XCA_HAS_PROVIDERS

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <strings.h>
#include "opensc-pkcs11.h"

/* Private OSSL_PARAM carrying the PKCS#11 context at key import */
#define XCA_P11_CTX_PARAM "xca-pkcs11-ctx"

/* DER AlgorithmIdentifier of id-Ed25519: SEQUENCE { OID 1.3.101.112 } */
static const unsigned char xca_ed25519_algor[] = {
	0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70
};

namespace {

struct p11tok {
	CK_FUNCTION_LIST_PTR fl;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
};

struct p11key {
	unsigned char pub[32];
	size_t publen;
	p11tok tok;
};

struct p11sigctx {
	p11key *key;
};

/* ---------------- keymgmt ---------------- */


static void *p11_key_new(void *)
{
	p11key *k = (p11key *)OPENSSL_zalloc(sizeof *k);
	return k;
}


static void p11_key_free(void *keydata)
{
	OPENSSL_free(keydata);
}


static int p11_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	p11key *k = (p11key *)keydata;
	const OSSL_PARAM *p;

	if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
		return 0;
	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
	if (p == NULL || p->data_size != sizeof k->pub)
		return 0;
	memcpy(k->pub, p->data, p->data_size);
	k->publen = p->data_size;

	p = OSSL_PARAM_locate_const(params, XCA_P11_CTX_PARAM);
	if (p == NULL || p->data_size != sizeof k->tok)
		return 0;
	memcpy(&k->tok, p->data, sizeof k->tok);
	return 1;
}


static const OSSL_PARAM *p11_key_import_types(int selection)
{
	static OSSL_PARAM types[] = {
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_PUB_KEY,
				OSSL_PARAM_OCTET_STRING, NULL, 0),
		OSSL_PARAM_DEFN(XCA_P11_CTX_PARAM,
				OSSL_PARAM_OCTET_STRING, NULL, 0),
		OSSL_PARAM_END
	};
	if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
		return NULL;
	return types;
}


static int p11_key_has(void *keydata, int selection)
{
	p11key *k = (p11key *)keydata;

	if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
			OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return k->publen != 0;
	return 1;
}


static int p11_key_get_params(void *keydata, OSSL_PARAM out[])
{
	p11key *k = (p11key *)keydata;
	OSSL_PARAM *p;
	int ok = 1;

	for (p = out; p != NULL && p->key != NULL; p++) {
		if (OPENSSL_strcasecmp(p->key, OSSL_PKEY_PARAM_BITS) == 0) {
			ok &= OSSL_PARAM_set_int(p, 256);
		} else if (OPENSSL_strcasecmp(p->key,
					OSSL_PKEY_PARAM_SECURITY_BITS) == 0) {
			ok &= OSSL_PARAM_set_int(p, 128);
		} else if (OPENSSL_strcasecmp(p->key,
					OSSL_PKEY_PARAM_MAX_SIZE) == 0) {
			ok &= OSSL_PARAM_set_int(p, 64);
		} else if (OPENSSL_strcasecmp(p->key,
					OSSL_PKEY_PARAM_PUB_KEY) == 0) {
			ok &= OSSL_PARAM_set_octet_string(p, k->pub,
					k->publen);
		}
	}
	return ok;
}


static const OSSL_PARAM *p11_key_gettable_params(void *)
{
	static OSSL_PARAM tbl[] = {
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_BITS,
				OSSL_PARAM_INTEGER, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_SECURITY_BITS,
				OSSL_PARAM_INTEGER, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_MAX_SIZE,
				OSSL_PARAM_INTEGER, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_PUB_KEY,
				OSSL_PARAM_OCTET_STRING, NULL, 0),
		OSSL_PARAM_END
	};
	return tbl;
}

static int p11_key_export(void *keydata, int selection,
			OSSL_CALLBACK *param_cb, void *cbarg)
{
	p11key *k = (p11key *)keydata;
	OSSL_PARAM params[2];
	int ok;

	/* The token's private key is non-exportable. Rejecting an export
	 * that includes the private key part is essential: otherwise EVP
	 * imports a public-only key into a foreign provider (e.g. the
	 * default provider's ED25519 signature implementation) and
	 * signing fails there with "not a private key". */
	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
		return 0;
	if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
		return 0;
	params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
				k->pub, k->publen);
	params[1] = OSSL_PARAM_construct_end();
	ok = param_cb(params, cbarg);
	return ok;
}

static const OSSL_PARAM *p11_key_export_types(int selection)
{
	static OSSL_PARAM types[] = {
		OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_PUB_KEY,
				OSSL_PARAM_OCTET_STRING, NULL, 0),
		OSSL_PARAM_END
	};
	if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
		return NULL;
	return types;
}

static const OSSL_DISPATCH p11_keymgmt_functions[] = {
	{ OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11_key_new },
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11_key_free },
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11_key_has },
	{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11_key_import },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p11_key_import_types },
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11_key_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p11_key_export_types },
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p11_key_get_params },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
		(void (*)(void))p11_key_gettable_params },
	{ 0, NULL }
};

/* ---------------- signature ---------------- */


static void *p11_sig_newctx(void *, const char *)
{
	p11sigctx *ctx = (p11sigctx *)OPENSSL_zalloc(sizeof *ctx);
	return ctx;
}


static void p11_sig_freectx(void *sigctx)
{
	OPENSSL_free(sigctx);
}


static void *p11_sig_dupctx(void *sigctx)
{
	p11sigctx *src = (p11sigctx *)sigctx;
	p11sigctx *dst = (p11sigctx *)OPENSSL_zalloc(sizeof *dst);

	if (dst)
		*dst = *src;
	return dst;
}


static int p11_sig_digest_sign_init(void *sigctx, const char *mdname,
				void *provkey, const OSSL_PARAM params[])
{
	p11sigctx *ctx = (p11sigctx *)sigctx;

	(void)params;
	/* Ed25519 is a pure signature algorithm: only the NULL digest
	 * (as md_null) is accepted. */
	if (mdname != NULL && strcasecmp(mdname, "NULL") != 0 &&
			strcasecmp(mdname, "MD_NULL") != 0) {
		ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
				"Ed25519 does not accept a digest (%s)",
				mdname);
		return 0;
	}
	ctx->key = (p11key *)provkey;
	return ctx->key != NULL && ctx->key->publen != 0;
}


static int p11_sig_digest_sign(void *sigctx, unsigned char *sig,
			size_t *siglen, size_t sigsize,
			const unsigned char *tbs, size_t tbslen)
{
	p11sigctx *ctx = (p11sigctx *)sigctx;
	p11tok *t;
	CK_MECHANISM mech;
	CK_BYTE buf[128];
	CK_ULONG size = sizeof buf;
	CK_RV rv;

	if (ctx == NULL || ctx->key == NULL) {
		ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	t = &ctx->key->tok;
	memset(&mech, 0, sizeof mech);
	mech.mechanism = CKM_EDDSA;

	if (sig == NULL) {
		/* size query: an Ed25519 signature is always exactly
		 * 64 bytes, no need to bother the token. */
		*siglen = 64;
		return 1;
	}
	rv = t->fl->C_SignInit(t->session, &mech, t->object);
	if (rv != CKR_OK) {
		ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
				"C_SignInit failed, rv=%lu",
				(unsigned long)rv);
		return 0;
	}
	rv = t->fl->C_Sign(t->session, (CK_BYTE *)tbs, (CK_ULONG)tbslen,
				buf, &size);
	if (rv != CKR_OK) {
		ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
				"C_Sign failed, rv=%lu",
				(unsigned long)rv);
		return 0;
	}
	if (sigsize < size) {
		ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	memcpy(sig, buf, size);
	*siglen = size;
	return 1;
}


static int p11_sig_get_ctx_params(void *sigctx, OSSL_PARAM out[])
{
	OSSL_PARAM *p;
	int ok = 1;

	(void)sigctx;
	for (p = out; p != NULL && p->key != NULL; p++) {
		if (OPENSSL_strcasecmp(p->key,
				OSSL_SIGNATURE_PARAM_ALGORITHM_ID) == 0) {
			ok &= OSSL_PARAM_set_octet_string(p,
					xca_ed25519_algor,
					sizeof xca_ed25519_algor);
		}
	}
	return ok;
}


static const OSSL_PARAM *p11_sig_gettable_ctx_params(void *, void *)
{
	static OSSL_PARAM tbl[] = {
		OSSL_PARAM_DEFN(OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
				OSSL_PARAM_OCTET_STRING, NULL, 0),
		OSSL_PARAM_END
	};
	return tbl;
}

static const OSSL_DISPATCH p11_sig_functions[] = {
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11_sig_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p11_sig_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p11_sig_dupctx },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
		(void (*)(void))p11_sig_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))p11_sig_digest_sign },
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
		(void (*)(void))p11_sig_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
		(void (*)(void))p11_sig_gettable_ctx_params },
	{ 0, NULL }
};

static const OSSL_ALGORITHM p11_keymgmt_algorithm[] = {
	{ "ED25519", NULL, p11_keymgmt_functions,
		"XCA PKCS#11 Ed25519 key management" },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11_signature_algorithm[] = {
	{ "ED25519", NULL, p11_sig_functions,
		"XCA PKCS#11 Ed25519 signature" },
	{ NULL, NULL, NULL, NULL }
};


static const OSSL_ALGORITHM *p11_query_operation(void *, int operation_id,
						int *no_cache)
{
	(void)no_cache;
	switch (operation_id) {
	case OSSL_OP_KEYMGMT:
		return p11_keymgmt_algorithm;
	case OSSL_OP_SIGNATURE:
		return p11_signature_algorithm;
	}
	return NULL;
}


static void p11_teardown(void *)
{
}

static const OSSL_DISPATCH p11_provider_functions[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION,
		(void (*)(void))p11_query_operation },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p11_teardown },
	{ 0, NULL }
};

} // namespace

static int xca_p11_provider_init(const OSSL_CORE_HANDLE *handle,
			const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
			void **provctx)
{
	(void)handle;
	(void)in;
	*provctx = NULL;
	*out = p11_provider_functions;
	return 1;
}

/* The provider lives in its own OSSL_LIB_CTX so that its ED25519
 * implementation cannot conflict with the default provider's software
 * ED25519 in the default library context. The lazy initialization is
 * not thread safe; XCA only reaches this from the main thread. */
static OSSL_LIB_CTX *p11_libctx()
{
	static OSSL_LIB_CTX *ctx = NULL;

	if (ctx == NULL) {
		ctx = OSSL_LIB_CTX_new();
		if (ctx == NULL)
			return NULL;
		if (!OSSL_PROVIDER_add_builtin(ctx, "xca-pkcs11",
						xca_p11_provider_init) ||
				OSSL_PROVIDER_load(ctx, "xca-pkcs11")
					== NULL) {
			OSSL_LIB_CTX_free(ctx);
			ctx = NULL;
		}
	}
	return ctx;
}

/* Create a provider-native ED25519 EVP_PKEY bound to a PKCS#11 object. */
EVP_PKEY *pkcs11_provider_key(const unsigned char *pub, size_t publen,
			CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE object)
{
	EVP_PKEY *evp = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	p11tok tok;
	OSSL_PARAM params[3];
	OSSL_LIB_CTX *libctx = p11_libctx();

	if (libctx == NULL)
		return NULL;
	tok.fl = fl;
	tok.session = session;
	tok.object = object;

	params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
				(void *)pub, publen);
	params[1] = OSSL_PARAM_construct_octet_string(XCA_P11_CTX_PARAM,
				&tok, sizeof tok);
	params[2] = OSSL_PARAM_construct_end();

	kctx = EVP_PKEY_CTX_new_from_name(libctx, "ED25519", NULL);
	if (kctx == NULL)
		goto out;
	if (EVP_PKEY_fromdata_init(kctx) <= 0)
		goto out;
	if (EVP_PKEY_fromdata(kctx, &evp, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
				params) <= 0) {
		evp = NULL;
		goto out;
	}
out:
	EVP_PKEY_CTX_free(kctx);
	return evp;
}

#endif /* XCA_HAS_PROVIDERS */
