/*
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */
#include <openssl/evp.h>

#include "builtin_curves.h"
#include "exception.h"
#include "func.h"

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#include "opensc-pkcs11.h"

static const int x962_curve_nids[] = {
	NID_X9_62_prime192v1,
	NID_X9_62_prime192v2,
	NID_X9_62_prime192v3,
	NID_X9_62_prime239v1,
	NID_X9_62_prime239v2,
	NID_X9_62_prime239v3,
	NID_X9_62_prime256v1,

	NID_X9_62_c2pnb163v1,
	NID_X9_62_c2pnb163v2,
	NID_X9_62_c2pnb163v3,
	NID_X9_62_c2pnb176v1,
	NID_X9_62_c2tnb191v1,
	NID_X9_62_c2tnb191v2,
	NID_X9_62_c2tnb191v3,
	NID_X9_62_c2pnb208w1,
	NID_X9_62_c2tnb239v1,
	NID_X9_62_c2tnb239v2,
	NID_X9_62_c2tnb239v3,
	NID_X9_62_c2pnb272w1,
	NID_X9_62_c2pnb304w1,
	NID_X9_62_c2tnb359v1,
	NID_X9_62_c2pnb368w1,
	NID_X9_62_c2tnb431r1
};

static const int other_curve_nids[] = {
	NID_sect113r1,
	NID_sect113r2,
	NID_sect131r1,
	NID_sect131r2,
	NID_sect163k1,
	NID_sect163r1,
	NID_sect163r2,
	NID_sect193r1,
	NID_sect193r2,
	NID_sect233k1,
	NID_sect233r1,
	NID_sect239k1,
	NID_sect283k1,
	NID_sect283r1,
	NID_sect409k1,
	NID_sect409r1,
	NID_sect571k1,
	NID_sect571r1,

	NID_secp112r1,
	NID_secp112r2,
	NID_secp128r1,
	NID_secp128r2,
	NID_secp160k1,
	NID_secp160r1,
	NID_secp160r2,
	NID_secp192k1,
	NID_secp224k1,
	NID_secp224r1,
	NID_secp256k1,
	NID_secp384r1,
	NID_secp521r1,

	NID_wap_wsg_idm_ecid_wtls1,
	NID_wap_wsg_idm_ecid_wtls3,
	NID_wap_wsg_idm_ecid_wtls4,
	NID_wap_wsg_idm_ecid_wtls5,
	NID_wap_wsg_idm_ecid_wtls6,
	NID_wap_wsg_idm_ecid_wtls7,
	NID_wap_wsg_idm_ecid_wtls8,
	NID_wap_wsg_idm_ecid_wtls9,
	NID_wap_wsg_idm_ecid_wtls10,
	NID_wap_wsg_idm_ecid_wtls11,
	NID_wap_wsg_idm_ecid_wtls12,

#ifdef NID_brainpoolP160r1
	NID_brainpoolP160r1,
	NID_brainpoolP160t1,
	NID_brainpoolP192r1,
	NID_brainpoolP192t1,
	NID_brainpoolP224r1,
	NID_brainpoolP224t1,
	NID_brainpoolP256r1,
	NID_brainpoolP256t1,
	NID_brainpoolP320r1,
	NID_brainpoolP320t1,
	NID_brainpoolP384r1,
	NID_brainpoolP384t1,
	NID_brainpoolP512r1,
	NID_brainpoolP512t1
#endif
};

builtin_curves::builtin_curves()
{
	int i, num_curves = EC_get_builtin_curves(NULL, 0);
	EC_builtin_curve *curves = (EC_builtin_curve*)OPENSSL_malloc(
		(int)(sizeof(EC_builtin_curve) *num_curves));

	check_oom(curves);

	BIGNUM *order = BN_new();
	check_oom(order);

	EC_get_builtin_curves(curves, num_curves);

	for (i=0; i< num_curves; i++) {
		size_t j;
		int flag = 0, nid = curves[i].nid;
		unsigned long type = 0;

		for (j=0; j<ARRAY_SIZE(x962_curve_nids); j++) {
			if (x962_curve_nids[j] == nid) {
				flag = CURVE_X962;
				break;
			}
		}
		if (!flag) {
			for (j=0; j<ARRAY_SIZE(other_curve_nids); j++) {
				if (other_curve_nids[j] == nid) {
					flag = CURVE_OTHER;
					break;
				}
			}
		}
		if (!flag)
			continue;

		EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
		EC_GROUP_get_order(group, order, NULL);

		switch (EC_METHOD_get_field_type(EC_GROUP_method_of(group))) {
		case NID_X9_62_prime_field:
			type = CKF_EC_F_P;
			break;
		case NID_X9_62_characteristic_two_field:
			type = CKF_EC_F_2M;
			break;
		default:
			continue;
		}
#undef PRINT_KNOWN_CURVES
#ifdef PRINT_KNOWN_CURVES
		fprintf(stderr, "%50s %27s %20s %s\n",
			curves[i].comment, OBJ_nid2sn(nid),
			CCHAR(OBJ_obj2QString(OBJ_nid2obj(nid), 1)),
			type == CKF_EC_F_P ? "Fp" : "F2m");
#endif
		append(builtin_curve(nid, QString(curves[i].comment),
			BN_num_bits(order), flag, type));
                EC_GROUP_free(group);
	}
	BN_free(order);
}
#else
builtin_curves::builtin_curves() { }

#endif
