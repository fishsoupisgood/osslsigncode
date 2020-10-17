#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>



static void *cert_to_der (const X509 *x, size_t *len)
{
	unsigned char *ret = NULL;

	*len = i2d_X509 ((X509 *) x, &ret);


	return ret;
}

static int cert_cmp (const X509 *a, const X509 *b)
{
	void *ad, *bd;
	size_t adl, bdl, dl;
	int ret;

	if ((!a) && (!b)) return 0;

	if (!a) return -1;

	if (!b) return 1;

	ad = cert_to_der (a, &adl);
	bd = cert_to_der (b, &bdl);

	dl = adl > bdl ? bdl : adl;


	ret = memcmp (ad, bd, dl);

	if (!ret) {
		if (adl > bdl) ret = 1;

		if (bdl > adl) ret = -1;
	}

	OPENSSL_free (bd);
	OPENSSL_free (ad);


	return ret;
}


static int cert_cmp_fn (const X509 *const  *a, const X509 *const *b)
{
	return cert_cmp (*a, *b);
}


/* OpenSSL has PKCS7 signed-data type wrong */
/* with the list of certificates as a SEQUENCE rather than a SET */
/* windows wintrust.dll since 13/Oct/2020 doesn't like tihs */
/* We can fix it for output by reordering the certs in the structure */
/* This has no side effects for a fixed OpenSSL */

void pkcs7_cert_order_fix (PKCS7 *p7)
{
	STACK_OF (X509) *certs;

	if (!PKCS7_type_is_signed (p7))
		return;

	certs = sk_X509_new (cert_cmp_fn);

	while (sk_X509_num (p7->d.sign->cert))
		sk_X509_push (certs, sk_X509_pop (p7->d.sign->cert));

	sk_X509_sort (certs);


	while (sk_X509_num (certs))
		sk_X509_unshift (p7->d.sign->cert, sk_X509_pop (certs));

	sk_X509_free (certs);

	//catwoe_show (p7, stderr);

}



static EVP_PKEY *make_rsa_key (unsigned size)
{
	EVP_PKEY *pkey = EVP_PKEY_new();
	RSA *rsa = RSA_new();
	BIGNUM *bne = BN_new();


	BN_set_word (bne, RSA_F4);
	RSA_generate_key_ex (rsa, size, bne, NULL);

	EVP_PKEY_assign_RSA (pkey, rsa);

	return pkey;
}

static X509 *make_cert (EVP_PKEY *key, const char *cn)
{
	X509 *x509 = X509_new();
	X509_NAME *name;

	X509_gmtime_adj (X509_get_notBefore (x509), 0);
	X509_gmtime_adj (X509_get_notAfter (x509), 31536000L);

	X509_set_pubkey (x509, key);

	name = X509_get_subject_name (x509);
	X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, cn, -1, -1, 0);

	X509_set_issuer_name (x509, name);

	X509_sign (x509, key, EVP_sha256());

	return x509;
}




static int cert_order_test_for_bug (void)
{
	static int result = -1;
	static int tested;
	PKCS7 *p7;
	EVP_PKEY *sig_key;
	X509 *sig_cert;
	EVP_PKEY *extra_key1, *extra_key2;
	X509 *extra_cert1, *extra_cert2;
	BIO *sig_bio;

	unsigned char *blob = NULL;
	const unsigned char *ptr;

	size_t blob_len;

	if (tested) return result;

	tested++;


	sig_key = make_rsa_key (1024);
	sig_cert = make_cert (sig_key, "Cheetah");

	extra_key1 = make_rsa_key (1024);
	extra_cert1 = make_cert (extra_key1, "Dolphin");

	extra_key2 = make_rsa_key (1024);
	extra_cert2 = make_cert (extra_key2, "Giraffe");

	p7 = PKCS7_new();
	PKCS7_set_type (p7, NID_pkcs7_signed);
	PKCS7_content_new (p7, NID_pkcs7_data);

	PKCS7_add_signature (p7, sig_cert, sig_key, EVP_sha256());

	PKCS7_add_certificate (p7, extra_cert2);
	PKCS7_add_certificate (p7, extra_cert1);


	sig_bio = PKCS7_dataInit (p7, NULL);
	BIO_write (sig_bio, "Penguin", 5);
	BIO_flush (sig_bio);
	PKCS7_dataFinal (p7, sig_bio);

	blob_len = i2d_PKCS7 (p7, &blob);

	X509_free (extra_cert2);
	EVP_PKEY_free (extra_key2);

	X509_free (extra_cert1);
	EVP_PKEY_free (extra_key1);

	X509_free (sig_cert);
	EVP_PKEY_free (sig_key);

	PKCS7_free (p7);

	if (!blob)
		return result;

	ptr = blob;
	p7 = d2i_PKCS7 (NULL, &ptr, blob_len);

	{
		FILE *f = fopen ("meh.der", "w");
		fwrite (blob, 1, blob_len, f);
		fclose (f);
	}

	OPENSSL_free (blob);

	if (!p7) return result;


	do {

		if (!PKCS7_type_is_signed (p7))
			break;

		if (sk_X509_num (p7->d.sign->cert) != 2)
			break;


		extra_cert1 = sk_X509_value (p7->d.sign->cert, 0);
		extra_cert2 = sk_X509_value (p7->d.sign->cert, 1);

		result = (cert_cmp (extra_cert1, extra_cert2) > 0) ? 1 : 0;

	} while (0);

	PKCS7_free (p7);

	return result;

}


static char *cert_to_der_str (X509 *x)
{
	size_t xlen;
	unsigned char *xbuf = cert_to_der (x, &xlen);
	char buf[40];
	char *ptr = buf;
	unsigned i;

	buf[0] = 0;

	for (i = 0; i < ((sizeof (buf) - 1) / 3); ++i)
		ptr += sprintf (ptr, "%s%02x", i ? ":" : "", xbuf[i]);

	OPENSSL_free (xbuf);

	return strdup (buf);
}

static int does_cert_match_si (X509 *x, PKCS7_SIGNER_INFO *si)
{
	X509 *xm;
	int ret;

	if (!si) return 0;

	xm = X509_dup (x);

	X509_set_serialNumber (xm, ASN1_INTEGER_dup (si->issuer_and_serial->serial));

	X509_set_issuer_name (xm, X509_NAME_dup (si->issuer_and_serial->issuer));


	ret = !X509_issuer_and_serial_cmp (x, xm);

	X509_free (xm);

	return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static const unsigned char *ASN1_STRING_get0_data (const ASN1_STRING *asn1)
{
	return M_ASN1_STRING_data (asn1);
}
#endif


void pkcs7_cert_order_show (PKCS7 *p7, FILE *f)
{
	STACK_OF (X509) * signers = NULL;
	STACK_OF (X509) * certs = NULL;
	ASN1_TYPE *cs;
	unsigned n, i;
	int signer;

	PKCS7_SIGNER_INFO *si;
	PKCS7_SIGNER_INFO *cs_si = NULL;


	fprintf (f, "pkcs7 certificate order:\n");

	if (!PKCS7_type_is_signed (p7))
		return;

	signers = PKCS7_get0_signers (p7, NULL, 0);
	certs = p7->d.sign->cert;
	n = sk_X509_num (certs);

	si = sk_PKCS7_SIGNER_INFO_value (p7->d.sign->signer_info, 0);

	cs = PKCS7_get_attribute (si, NID_pkcs9_countersignature);

	if (cs) {
		size_t len = ASN1_STRING_length (cs->value.asn1_string);
		const unsigned char *buf, *ptr;

		ptr = buf = ASN1_STRING_get0_data (cs->value.asn1_string);

		d2i_PKCS7_SIGNER_INFO (&cs_si, &ptr, len);
	}


	for (i = 0; i < n; ++i) {
		X509 *x = sk_X509_value (certs, i);

		char *subject =
		    X509_NAME_oneline (X509_get_subject_name (x), NULL, 0);
		char flags[3] = "  ";
		char *der = cert_to_der_str (x);

		if (does_cert_match_si (x, si)) flags[0] = '*';

		if (does_cert_match_si (x, cs_si)) flags[1] = '+';


		if (i && (cert_cmp (sk_X509_value (certs, i - 1), x) >= 0))
			fprintf (f, " -- ORDER WRONG HERE --\n");

		fprintf (f, "%d:%s\t%s %s\n", i, flags, der, subject);
		OPENSSL_free (subject);
		free (der);
	}

	return;
}



int pkcs7_cert_order_check (PKCS7 *p7, FILE *f)
{
	STACK_OF (X509) *certs;
	X509 *a, *b;
	unsigned i, n;
	int err = 0;

	/* This openssl is good, so the test will tell us nothing */
	if (cert_order_test_for_bug() == 0)  {
		printf ("OpenSSL version lacks bug - unable to test certificate order\n");
		return 1;
	}

	if (!PKCS7_type_is_signed (p7)) {
		printf ("Wrong pkcs7 type\n");
		return 0;
	}

	certs = p7->d.sign->cert;
	n = sk_X509_num (certs);

	for (i = 1; i < n; ++i) {

		a = sk_X509_value (certs, i - 1);
		b = sk_X509_value (certs, i);

		if (cert_cmp (a, b) >= 0)
			err++;
	}

	if (!err) {
		printf ("PKCS7 certificate order correct\n");

		return 1;
	}

	printf ("PKCS7 certificate order wrong\n");

	pkcs7_cert_order_show (p7, f);

	return 0;
}


