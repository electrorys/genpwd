#include <stdio.h>
#include <string.h>
#include "genpwd.h"
#include "mkpwd.h"

struct pwdtest {
	const char *master;
	const unsigned char *salt; size_t slen;
	const char *name;
	int passes_number, string_offset, password_length;
	const char *xpwd;
};

int selftest(void)
{
	int i, ret = 1;
	const char *d[] = {NULL, NULL, NULL};
	char *xpwd = NULL;
	struct pwdtest ptst[3];
	const unsigned char salt0[] = {0xa6, 0x5d, 0x7f, 0x7e};
	const unsigned char salt1[] = {0xd1, 0x23, 0xbb, 0x35, 0xa9, 0x92, 0x78, 0x42, 0xca, 0x8d};

	memset(&ptst, 0, sizeof(ptst));

	ptst[0].master = "test"; ptst[0].name = "test";
	ptst[0].salt = salt0; ptst[0].slen = sizeof(salt0);
	ptst[0].passes_number = 887; ptst[0].string_offset = 11; ptst[0].password_length = 30;
	ptst[0].xpwd = "BRqetv5PIFEVgr8KEuyCiXKQ66xZZX";

	ptst[1].master = "tIXV75fU9Qk7uI"; ptst[1].name = "user@example.org";
	ptst[1].salt = salt1; ptst[1].slen = sizeof(salt1);
	ptst[1].passes_number = 4056; ptst[1].string_offset = 17; ptst[1].password_length = 25;
	ptst[1].xpwd = "vqS8Q4Y63aGgQI0DbvFeFeU2D";

#ifdef _SELFTEST_CURRENT
#undef _SELFTEST_CURRENT
	ptst[2].master = testmaster; ptst[2].name = testname;
	ptst[2].salt = salt; ptst[2].slen = salt_length;
	ptst[2].passes_number = default_passes_number; ptst[2].string_offset = default_string_offset; ptst[2].password_length = default_password_length;
	ptst[2].xpwd = testxpwd;
#endif

	for (i = 0; i < sizeof(ptst)/sizeof(ptst[0]); i++) {
		if (!ptst[i].master) continue;

		mkpwd_passes_number = ptst[i].passes_number;
		mkpwd_string_offset = ptst[i].string_offset;
		mkpwd_password_length = ptst[i].password_length;
		d[0] = ptst[i].master; d[1] = ptst[i].name;

		xpwd = mkpwd(ptst[i].salt, ptst[i].slen, d);
		if (!xpwd[0] && xpwd[1]) {
			fprintf(stderr, xpwd+1);
			ret = 0;
			break;
		}

		if (strncmp(xpwd, ptst[i].xpwd, MKPWD_OUTPUT_MAX) != 0) { ret = 0; break; }
		memset(xpwd, 0, MKPWD_OUTPUT_MAX);
	}

	memset(&ptst, 0, sizeof(ptst));

	return ret;
}
