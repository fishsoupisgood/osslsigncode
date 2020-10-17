
#define DEFINE_STACK_OF(a) \
	DECLARE_STACK_OF(a) \
	STACK_OF(a); \
	static STACK_OF(a) * sk_ ## a ##_new_null(void) { return SKM_sk_new_null(a) ; } \
	static int sk_ ## a ##_unshift(STACK_OF(a) *st, a *val) { return SKM_sk_unshift(a, (st), (val)); } \
	static int sk_ ## a ##_push(STACK_OF(a) *st, a *val) { return SKM_sk_push(a, (st), (val)); } \
	static int sk_ ## a ##_num(STACK_OF(a) *st) { return SKM_sk_num(a, (st)); } \
	static a * sk_ ## a ##_value(STACK_OF(a) *st, int i) { return SKM_sk_value(a, (st), (i)); } \
	static void sk_ ## a ##_free(STACK_OF(a) *st) { return SKM_sk_free(a, (st)); }

# define EVP_MD_CTX_new EVP_MD_CTX_create
# define EVP_MD_CTX_free EVP_MD_CTX_destroy

#define X509_get0_notBefore(a) X509_get_notBefore(a)
#define X509_get0_notAfter(a) X509_get_notAfter(a)

X509_VERIFY_PARAM *X509_STORE_get0_param (X509_STORE *s)
{
	return s->param;
}


const unsigned char *ASN1_STRING_get0_data (ASN1_STRING *s)
{
	return s->data;
}



#define DEFAULT_SEPARATOR ':'
#define CH_ZERO '\0'


static void *OPENSSL_zalloc (size_t s)
{
	void *ret = OPENSSL_malloc (s);

	if (ret)
		memset (ret, 0, s);

	return ret;
}

int ascii_isdigit (const char inchar)
{
	if (inchar > 0x2F && inchar < 0x3A)
		return 1;

	return 0;
}


int OPENSSL_hexchar2int (unsigned char c)
{
#ifdef CHARSET_EBCDIC
	c = os_toebcdic[c];
#endif

	switch (c) {
	case '0':
		return 0;

	case '1':
		return 1;

	case '2':
		return 2;

	case '3':
		return 3;

	case '4':
		return 4;

	case '5':
		return 5;

	case '6':
		return 6;

	case '7':
		return 7;

	case '8':
		return 8;

	case '9':
		return 9;

	case 'a':
	case 'A':
		return 0x0A;

	case 'b':
	case 'B':
		return 0x0B;

	case 'c':
	case 'C':
		return 0x0C;

	case 'd':
	case 'D':
		return 0x0D;

	case 'e':
	case 'E':
		return 0x0E;

	case 'f':
	case 'F':
		return 0x0F;
	}

	return -1;
}


static int hexstr2buf_sep (unsigned char *buf, size_t buf_n, size_t *buflen, const char *str, const char sep)
{
	unsigned char *q;
	unsigned char ch, cl;
	int chi, cli;
	const unsigned char *p;
	size_t cnt;

	for (p = (const unsigned char *)str, q = buf, cnt = 0; *p;) {
		ch = *p++;

		/* A separator of CH_ZERO means there is no separator */
		if (ch == sep && sep != CH_ZERO)
			continue;

		cl = *p++;

		if (!cl) {
			//CRYPTOerr(0, CRYPTO_R_ODD_NUMBER_OF_DIGITS);
			return 0;
		}

		cli = OPENSSL_hexchar2int (cl);
		chi = OPENSSL_hexchar2int (ch);

		if (cli < 0 || chi < 0) {
			//CRYPTOerr(0, CRYPTO_R_ILLEGAL_HEX_DIGIT);
			return 0;
		}

		cnt++;

		if (q != NULL) {
			if (cnt > buf_n) {
				//CRYPTOerr(0, CRYPTO_R_TOO_SMALL_BUFFER);
				return 0;
			}

			*q++ = (unsigned char) ((chi << 4) | cli);
		}
	}

	if (buflen != NULL)
		*buflen = cnt;

	return 1;
}


unsigned char *openssl_hexstr2buf_sep (const char *str, long *buflen, const char sep)
{
	unsigned char *buf;
	size_t buf_n, tmp_buflen;

	buf_n = strlen (str) >> 1;

	if ((buf = OPENSSL_malloc (buf_n)) == NULL) {
		CRYPTOerr (0, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (buflen != NULL)
		*buflen = 0;

	tmp_buflen = 0;

	if (hexstr2buf_sep (buf, buf_n, &tmp_buflen, str, sep)) {
		if (buflen != NULL)
			*buflen = (long)tmp_buflen;

		return buf;
	}

	OPENSSL_free (buf);
	return NULL;
}

unsigned char *OPENSSL_hexstr2buf (const char *str, long *buflen)
{
	return openssl_hexstr2buf_sep (str, buflen, DEFAULT_SEPARATOR);
}

static int buf2hexstr_sep (char *str, size_t str_n, size_t *strlen, const unsigned char *buf, size_t buflen, const char sep)
{
	static const char hexdig[] = "0123456789ABCDEF";
	const unsigned char *p;
	char *q;
	size_t i;
	int has_sep = (sep != CH_ZERO);
	size_t len = has_sep ? buflen * 3 : 1 + buflen * 2;

	if (strlen != NULL)
		*strlen = len;

	if (str == NULL)
		return 1;

	if (str_n < (unsigned long)len) {
		//CRYPTOerr(0, CRYPTO_R_TOO_SMALL_BUFFER);
		return 0;
	}

	q = str;

	for (i = 0, p = buf; i < buflen; i++, p++) {
		*q++ = hexdig[ (*p >> 4) & 0xf];
		*q++ = hexdig[*p & 0xf];

		if (has_sep)
			*q++ = sep;
	}

	if (has_sep)
		--q;

	*q = CH_ZERO;

#ifdef CHARSET_EBCDIC
	ebcdic2ascii (str, str, q - str - 1);
#endif
	return 1;
}

char *openssl_buf2hexstr_sep (const unsigned char *buf, long buflen, char sep)
{
	char *tmp;
	size_t tmp_n;

	if (buflen == 0)
		return OPENSSL_zalloc (1);

	tmp_n = (sep != CH_ZERO) ? buflen * 3 : 1 + buflen * 2;

	if ((tmp = OPENSSL_malloc (tmp_n)) == NULL) {
		CRYPTOerr (0, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (buf2hexstr_sep (tmp, tmp_n, NULL, buf, buflen, sep))
		return tmp;

	OPENSSL_free (tmp);
	return NULL;
}


char *OPENSSL_buf2hexstr (const unsigned char *buf, long buflen)
{
	return openssl_buf2hexstr_sep (buf, buflen, ':');
}



struct tm *OPENSSL_gmtime (const time_t *timer, struct tm *result)
{
	struct tm *ts = NULL;

#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_VMS)
	{
		/*
		 * On VMS, gmtime_r() takes a 32-bit pointer as second argument.
		 * Since we can't know that |result| is in a space that can easily
		 * translate to a 32-bit pointer, we must store temporarily on stack
		 * and copy the result.  The stack is always reachable with 32-bit
		 * pointers.
		 */
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE
# pragma pointer_size save
# pragma pointer_size 32
#endif
		struct tm data, *ts2 = &data;
#if defined OPENSSL_SYS_VMS && __INITIAL_POINTER_SIZE
# pragma pointer_size restore
#endif

		if (gmtime_r (timer, ts2) == NULL)
			return NULL;

		memcpy (result, ts2, sizeof (struct tm));
		ts = result;
	}
#elif defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_SYS_MACOSX)

	if (gmtime_r (timer, result) == NULL)
		return NULL;

	ts = result;
#elif defined (OPENSSL_SYS_WINDOWS) && defined(_MSC_VER) && _MSC_VER >= 1400 && !defined(_WIN32_WCE)

	if (gmtime_s (result, timer))
		return NULL;

	ts = result;
#else
	ts = gmtime (timer);

	if (ts == NULL)
		return NULL;

	memcpy (result, ts, sizeof (struct tm));
	ts = result;
#endif
	return ts;
}



static int leap_year (const int year)
{
	if (year % 400 == 0 || (year % 100 != 0 && year % 4 == 0))
		return 1;

	return 0;
}

static void determine_days (struct tm *tm)
{
	static const int ydays[12] = {
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
	};
	int y = tm->tm_year + 1900;
	int m = tm->tm_mon;
	int d = tm->tm_mday;
	int c;

	tm->tm_yday = ydays[m] + d - 1;

	if (m >= 2) {
		/* March and onwards can be one day further into the year */
		tm->tm_yday += leap_year (y);
		m += 2;
	} else {
		/* Treat January and February as part of the previous year */
		m += 14;
		y--;
	}

	c = y / 100;
	y %= 100;
	/* Zeller's congruence */
	tm->tm_wday = (d + (13 * m) / 5 + y + y / 4 + c / 4 + 5 * c + 6) % 7;
}


# define ASN1_STRING_FLAG_X509_TIME 0x100

int asn1_time_to_tm (struct tm *tm, const ASN1_TIME *d)
{
	static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
	static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
	static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	char *a;
	int n, i, i2, l, o, min_l = 11, strict = 0, end = 6, btz = 5, md;
	struct tm tmp;
#if defined(CHARSET_EBCDIC)
	const char upper_z = 0x5A, num_zero = 0x30, period = 0x2E, minus = 0x2D, plus = 0x2B;
#else
	const char upper_z = 'Z', num_zero = '0', period = '.', minus = '-', plus = '+';
#endif

	/*
	 * ASN1_STRING_FLAG_X509_TIME is used to enforce RFC 5280
	 * time string format, in which:
	 *
	 * 1. "seconds" is a 'MUST'
	 * 2. "Zulu" timezone is a 'MUST'
	 * 3. "+|-" is not allowed to indicate a time zone
	 */
	if (d->type == V_ASN1_UTCTIME) {
		if (d->flags & ASN1_STRING_FLAG_X509_TIME) {
			min_l = 13;
			strict = 1;
		}
	} else if (d->type == V_ASN1_GENERALIZEDTIME) {
		end = 7;
		btz = 6;

		if (d->flags & ASN1_STRING_FLAG_X509_TIME) {
			min_l = 15;
			strict = 1;
		} else
			min_l = 13;
	} else
		return 0;

	l = d->length;
	a = (char *)d->data;
	o = 0;
	memset (&tmp, 0, sizeof (tmp));

	/*
	 * GENERALIZEDTIME is similar to UTCTIME except the year is represented
	 * as YYYY. This stuff treats everything as a two digit field so make
	 * first two fields 00 to 99
	 */

	if (l < min_l)
		goto err;

	for (i = 0; i < end; i++) {
		if (!strict && (i == btz) && ((a[o] == upper_z) || (a[o] == plus) || (a[o] == minus))) {
			i++;
			break;
		}

		if (!ascii_isdigit (a[o]))
			goto err;

		n = a[o] - num_zero;

		/* incomplete 2-digital number */
		if (++o == l)
			goto err;

		if (!ascii_isdigit (a[o]))
			goto err;

		n = (n * 10) + a[o] - num_zero;

		/* no more bytes to read, but we haven't seen time-zone yet */
		if (++o == l)
			goto err;

		i2 = (d->type == V_ASN1_UTCTIME) ? i + 1 : i;

		if ((n < min[i2]) || (n > max[i2]))
			goto err;

		switch (i2) {
		case 0:
			/* UTC will never be here */
			tmp.tm_year = n * 100 - 1900;
			break;

		case 1:
			if (d->type == V_ASN1_UTCTIME)
				tmp.tm_year = n < 50 ? n + 100 : n;
			else
				tmp.tm_year += n;

			break;

		case 2:
			tmp.tm_mon = n - 1;
			break;

		case 3:

			/* check if tm_mday is valid in tm_mon */
			if (tmp.tm_mon == 1) {
				/* it's February */
				md = mdays[1] + leap_year (tmp.tm_year + 1900);
			} else
				md = mdays[tmp.tm_mon];

			if (n > md)
				goto err;

			tmp.tm_mday = n;
			determine_days (&tmp);
			break;

		case 4:
			tmp.tm_hour = n;
			break;

		case 5:
			tmp.tm_min = n;
			break;

		case 6:
			tmp.tm_sec = n;
			break;
		}
	}

	/*
	 * Optional fractional seconds: decimal point followed by one or more
	 * digits.
	 */
	if (d->type == V_ASN1_GENERALIZEDTIME && a[o] == period) {
		if (strict)
			/* RFC 5280 forbids fractional seconds */
			goto err;

		if (++o == l)
			goto err;

		i = o;

		while ((o < l) && ascii_isdigit (a[o]))
			o++;

		/* Must have at least one digit after decimal point */
		if (i == o)
			goto err;

		/* no more bytes to read, but we haven't seen time-zone yet */
		if (o == l)
			goto err;
	}

	/*
	 * 'o' will never point to '\0' at this point, the only chance
	 * 'o' can point to '\0' is either the subsequent if or the first
	 * else if is true.
	 */
	if (a[o] == upper_z)
		o++;

	else if (!strict && ((a[o] == plus) || (a[o] == minus))) {
		int offsign = a[o] == minus ? 1 : -1;
		int offset = 0;

		o++;

		/*
		 * if not equal, no need to do subsequent checks
		 * since the following for-loop will add 'o' by 4
		 * and the final return statement will check if 'l'
		 * and 'o' are equal.
		 */
		if (o + 4 != l)
			goto err;

		for (i = end; i < end + 2; i++) {
			if (!ascii_isdigit (a[o]))
				goto err;

			n = a[o] - num_zero;
			o++;

			if (!ascii_isdigit (a[o]))
				goto err;

			n = (n * 10) + a[o] - num_zero;
			i2 = (d->type == V_ASN1_UTCTIME) ? i + 1 : i;

			if ((n < min[i2]) || (n > max[i2]))
				goto err;

			/* if tm is NULL, no need to adjust */
			if (tm != NULL) {
				if (i == end)
					offset = n * 3600;
				else if (i == end + 1)
					offset += n * 60;
			}

			o++;
		}

		if (offset && !OPENSSL_gmtime_adj (&tmp, 0, offset * offsign))
			goto err;
	} else {
		/* not Z, or not +/- in non-strict mode */
		goto err;
	}

	if (o == l) {
		/* success, check if tm should be filled */
		if (tm != NULL)
			*tm = tmp;

		return 1;
	}

err:
	return 0;
}


int ASN1_TIME_to_tm (const ASN1_TIME *s, struct tm *tm)
{
	if (s == NULL) {
		time_t now_t;

		time (&now_t);
		memset (tm, 0, sizeof (*tm));

		if (OPENSSL_gmtime (&now_t, tm) != NULL)
			return 1;

		return 0;
	}

	return asn1_time_to_tm (tm, s);
}



uint32_t X509_get_extended_key_usage (X509 *x)
{
	/* Call for side-effect of computing hash and caching extensions */
	if (X509_check_purpose (x, -1, -1) != 1)
		return 0;

	if (x->ex_flags & EXFLAG_XKUSAGE)
		return x->ex_xkusage;

	return UINT32_MAX;
}

int X509_CRL_up_ref (X509_CRL *crl)
{
	//XXX: not thread safe but we don't have any
	crl->references++;

	return (crl->references > 1) ? 1 : 0;
}
