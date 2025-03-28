/* The "32bit hash" in public_keys, x509super, requests, certs and crls
 * is used to quickly find items in the DB by reference.
 * It consists of the first 4 bytes of a SHA1 hash.
 * Collisions are of course possible.
 *
 * All binaries are stored Base64 encoded in a column of type
 * ' B64_BLOB ' It is defined here as 'TEXT' which is huge, except
 * on mysql where LONGTEXT is used.
 */

#define B64_BLOB "_B64_BLOB_"

/*
 * The B64(DER(something)) function means DER encode something
 * and then Base64 encode that.
 * So finally this is PEM without newlines, header and footer
 *
 * Dates are always stored as 'CHAR(15)' in the
 * ASN.1 Generalized time 'yyyyMMddHHmmssZ' format
 */

#define DB_DATE "CHAR(15)"

/*
 * Configuration settings from
 *  the Options dialog, window size, last export directory,
 *  default key type and size,
 *  table column (position, sort order, visibility)
 */

	schemas[0]
<< "CREATE TABLE settings ("
	"key_ CHAR(20) UNIQUE, "        // mySql does not like 'key' or 'option"
	"value " B64_BLOB ")"
<< "INSERT INTO settings (key_, value) VALUES ('schema', '" INITIAL_SCHEMA_VERSION "')"

/*
 * All items (keys, tokens, requests, certs, crls, templates)
 * are stored here with the primary key and some common data
 * The other tables containing the details reference the 'id'
 * as FOREIGN KEY.
 */
<< "CREATE TABLE items("
	"id INTEGER PRIMARY KEY, "
	"name VARCHAR(128), "                // Internal name of the item
	"type INTEGER, "                // enum pki_type
	"source INTEGER, "                // enum pki_source
	"date " DB_DATE ", "                // Time of insertion (creation/import)
	"comment VARCHAR(2048), "
	"stamp INTEGER NOT NULL DEFAULT 0, " // indicate concurrent access
	"del SMALLINT NOT NULL DEFAULT 0)"

/*
 * Storage of public keys. Private keys and tokens also store
 * their public part here.
 */
<< "CREATE TABLE public_keys ("
	"item INTEGER, "                // reference to items(id)
	"type CHAR(4), "                // RSA DSA EC (as text)
	"hash INTEGER, "                // 32 bit hash
	"len INTEGER, "                        // key size in bits
	"\"public\" " B64_BLOB ", "        // B64(DER(public key))
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * The private part of RSA, DSA, EC keys.
 * references to 'items' and 'public_keys'
 */
<< "CREATE TABLE private_keys ("
	"item INTEGER, "                // reference to items(id)
	"ownPass INTEGER, "                // Encrypted by DB pwd or own pwd
	"private " B64_BLOB ", "        // B64(Encrypt(DER(private key)))
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Smart cards or other PKCS#11 tokens
 * references to 'items' and 'public_keys'
 */
<< "CREATE TABLE tokens ("
	"item INTEGER, "                  // reference to items(id)
	"card_manufacturer VARCHAR(64), " // Card location data
	"card_serial VARCHAR(64), "          // as text
	"card_model VARCHAR(64), "
	"card_label VARCHAR(64), "
	"slot_label VARCHAR(64), "
	"object_id VARCHAR(64), "          // Unique ID on the token
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Encryption and hash mechanisms supported by a token
 */
<< "CREATE TABLE token_mechanism ("
	"item INTEGER, "                // reference to items(id)
	"mechanism INTEGER, "                // PKCS#11: CK_MECHANISM_TYPE
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * An X509 Super class, consisting of a
 *  - Distinguishd name hash
 *  - Referenced key in the database
 *  - hash of the public key, used for lookups if there
 *    is no key to reference
 * used by Requests and certificates and the use-counter of keys:
 * 'SELECT from x509super WHERE pkey=?'
 */
<< "CREATE TABLE x509super ("
	"item INTEGER, "                // reference to items(id)
	"subj_hash INTEGER, "           // 32 bit hash of the Distinguished name
	"pkey INTEGER, "                // reference to the key items(id)
	"key_hash INTEGER, "            // 32 bit hash of the public key
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (pkey) REFERENCES items (id)) "

/*
 * PKCS#10 Certificate request details
 * also takes information from the 'x509super' table.
 */
<< "CREATE TABLE requests ("
	"item INTEGER, "                // reference to items(id)
	"hash INTEGER, "                // 32 bit hash of the request
	"signed INTEGER, "              // Whether it was once signed.
	"request " B64_BLOB ", "        // B64(DER(PKCS#10 request))
	"FOREIGN KEY (item) REFERENCES items (id)) "

/*
 * X509 certificate details
 * also takes information from the 'x509super' table.
 * The content of the columns: hash, iss_hash, serial, ca
 * can also be retrieved directly from the certificate, but are good
 * to lurk around for faster lookup
 */
<< "CREATE TABLE certs ("
	"item INTEGER, "                // reference to items(id)
	"hash INTEGER, "                // 32 bit hash of the cert
	"iss_hash INTEGER, "            // 32 bit hash of the issuer DN
	"serial VARCHAR(64), "          // Serial number of the certificate
	"issuer INTEGER, "              // The items(id) of the issuer or NULL
	"ca INTEGER, "                  // CA: yes / no from BasicConstraints
	"cert " B64_BLOB ", "           // B64(DER(certificate))
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

/*
 * X509 cartificate Authority data
 */
<< "CREATE TABLE authority ("
	"item INTEGER, "                // reference to items(id)
	"template INTEGER, "            // items(id) of the default template
	"crlExpire " DB_DATE ", "       // CRL expiry date
	"crlNo INTEGER, "               // Last CRL Number
	"crlDays INTEGER, "             // CRL days until renewal
	"dnPolicy VARCHAR(1024), "      // DistinguishedName policy (UNUSED)
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (template) REFERENCES items (id)) "

/*
 * Storage of CRLs
 */
<< "CREATE TABLE crls ("
	"item INTEGER, "                // reference to items(id)
	"hash INTEGER, "                // 32 bit hash of the CRL
	"num INTEGER, "                 // Number of revoked certificates
	"iss_hash INTEGER, "            // 32 bit hash of the issuer DN
	"issuer INTEGER, "              // The items(id) of the issuer or NULL
	"crl " B64_BLOB ", "            // B64(DER(revocation list))
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

/*
 * Revocations (serial, date, reason, issuer) used to create new
 * CRLs. 'Manage revocations'
 */
<< "CREATE TABLE revocations ("
	"caId INTEGER, "                // reference to certs(item)
	"serial VARCHAR(64), "          // Serial of the revoked certificate
	"date " DB_DATE ", "            // Time of creating the revocation
	"invaldate " DB_DATE ", "       // Time of invalidation
	"crlNo INTEGER, "               // Crl Number of CRL of first appearance
	"reasonBit INTEGER, "           // Bit number of the revocation reason
	"FOREIGN KEY (caId) REFERENCES items (id))"

/*
 * Templates
 */
<< "CREATE TABLE templates ("
	"item INTEGER, "                // reference to items(id)
	"version INTEGER, "             // Version of the template format
	"template " B64_BLOB ", "       // The base64 encoded template
	"FOREIGN KEY (item) REFERENCES items (id))"

/* Views */
<< "CREATE VIEW view_public_keys AS SELECT "
	"items.id, items.name, items.type AS item_type, items.date, "
	"items.source, items.comment, "
	"public_keys.type as key_type, public_keys.len, public_keys.\"public\", "
	"private_keys.ownPass, "
	"tokens.card_manufacturer, tokens.card_serial, tokens.card_model, "
	"tokens.card_label, tokens.slot_label, tokens.object_id "
	"FROM public_keys LEFT JOIN items ON public_keys.item = items.id "
	"LEFT JOIN private_keys ON private_keys.item = public_keys.item "
	"LEFT JOIN tokens ON public_keys.item = tokens.item"

<< "CREATE VIEW view_certs AS SELECT "
	"items.id, items.name, items.type, items.date AS item_date, "
	"items.source, items.comment, "
	"x509super.pkey, "
	"certs.serial AS certs_serial, certs.issuer, certs.ca, certs.cert, "
	"authority.template, authority.crlExpire, "
	"authority.crlNo AS auth_crlno, authority.crlDays, authority.dnPolicy, "
	"revocations.serial, revocations.date, revocations.invaldate, "
	"revocations.crlNo, revocations.reasonBit "
	"FROM certs LEFT JOIN items ON certs.item = items.id "
	"LEFT JOIN x509super ON x509super.item = certs.item "
	"LEFT JOIN authority ON authority.item = certs.item "
	"LEFT JOIN revocations ON revocations.caId = certs.issuer "
	                        "AND revocations.serial = certs.serial"

<< "CREATE VIEW view_requests AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"x509super.pkey, "
	"requests.request, requests.signed "
	"FROM requests LEFT JOIN items ON requests.item = items.id "
	"LEFT JOIN x509super ON x509super.item = requests.item"

<< "CREATE VIEW view_crls AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"crls.num, crls.issuer, crls.crl "
	"FROM crls LEFT JOIN items ON crls.item = items.id "

<< "CREATE VIEW view_templates AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"templates.version, templates.template "
	"FROM templates LEFT JOIN items ON templates.item = items.id"

<< "CREATE VIEW view_private AS SELECT "
	"name, private FROM private_keys JOIN items ON "
	"items.id = private_keys.item"


<< "CREATE INDEX i_settings_key_ ON settings (key_)"
<< "CREATE INDEX i_items_id ON items (id)"
<< "CREATE INDEX i_public_keys_item ON public_keys (item)"
<< "CREATE INDEX i_public_keys_hash ON public_keys (hash)"
<< "CREATE INDEX i_private_keys_item ON private_keys (item)"
<< "CREATE INDEX i_tokens_item ON tokens (item)"
<< "CREATE INDEX i_token_mechanism_item ON token_mechanism (item)"
<< "CREATE INDEX i_x509super_item ON x509super (item)"
<< "CREATE INDEX i_x509super_subj_hash ON x509super (subj_hash)"
<< "CREATE INDEX i_x509super_key_hash ON x509super (key_hash)"
<< "CREATE INDEX i_x509super_pkey ON x509super (pkey)"
<< "CREATE INDEX i_requests_item ON requests (item)"
<< "CREATE INDEX i_requests_hash ON requests (hash)"
<< "CREATE INDEX i_certs_item ON certs (item)"
<< "CREATE INDEX i_certs_hash ON certs (hash)"
<< "CREATE INDEX i_certs_iss_hash ON certs (iss_hash)"
<< "CREATE INDEX i_certs_serial ON certs (serial)"
<< "CREATE INDEX i_certs_issuer ON certs (issuer)"
<< "CREATE INDEX i_certs_ca ON certs (ca)"
<< "CREATE INDEX i_authority_item ON authority (item)"
<< "CREATE INDEX i_crls_item ON crls (item)"
<< "CREATE INDEX i_crls_hash ON crls (hash)"
<< "CREATE INDEX i_crls_iss_hash ON crls (iss_hash)"
<< "CREATE INDEX i_crls_issuer ON crls (issuer)"
<< "CREATE INDEX i_revocations_caId_serial ON revocations (caId, serial)"
<< "CREATE INDEX i_templates_item ON templates (item)"
<< "CREATE INDEX i_items_stamp ON items (stamp)"

	;
/* Schema Version 2: Views added to quickly load the data */

/* Schema Version 3: Add indexes over hashes and primary, foreign keys */

/* Schema Version 4: Add private key view to extract a private key with:
	mysql:      mysql -sNp -u xca xca_msq -e
	or sqlite:  sqlite3 ~/sqlxdb.xdb
	or psql:    psql -t -h 192.168.140.7 -U xca -d xca_pg -c
	        'SELECT private FROM view_private WHERE name=\"pk8key\";' |\
	        base64 -d | openssl pkcs8 -inform DER
 * First mysql/psql will ask for a password and then OpenSSL will ask for
 * the database password.
 */

/* Schema Version 5: Extend settings value size from 1024 to B64_BLOB
 * SQLite does not support 'ALTER TABLE settings MODIFY ...'
 */

	schemas[5]
<< "ALTER TABLE settings RENAME TO __settings"
<< "CREATE TABLE settings ("
	"key_ CHAR(20) UNIQUE, "        // mySql does not like 'key' or 'option'
	"value " B64_BLOB ")"
<< "INSERT INTO settings(key_, value) "
	"SELECT key_, value "
	"FROM __settings"
<< "DROP TABLE __settings"
<< "UPDATE settings SET value='6' WHERE key_='schema'"
	;

	schemas[6]
<< "ALTER TABLE items ADD del SMALLINT NOT NULL DEFAULT 0"
<< "CREATE INDEX i_items_del ON items (del)"
<< "UPDATE settings SET value='7' WHERE key_='schema'"
	;

	schemas[7]
// OpenVPN TA (tls-auth) keys associated to the CA to be
// the same for all issued certificates
<< "CREATE TABLE takeys ("
	"item INTEGER UNIQUE, "        // reference to items(id) of the CA
	"value " B64_BLOB ", "         // The base64 encoded 2048 bit key
	"FOREIGN KEY (item) REFERENCES items (id))"
<< "UPDATE settings SET value='8' WHERE key_='schema'"
	;

/* When adding new tables or views, also add them to the list
 * in XSqlQuery::rewriteQuery(QString) in lib/sql.cpp
 */
