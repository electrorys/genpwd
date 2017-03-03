/* change salt to get another unique profile */
static const unsigned char salt[] = {0x00, 0x00};

/* selftest data for current salt */
/* #define _SELFTEST_CURRENT */
#ifdef _SELFTEST_CURRENT
static const char testmaster[] = "x";
static const char testname[] = "x";
static const char testxpwd[] = "123";
#endif

static int plen = 15;
static int offs = 15;
static int numrounds = 5000;

static const unsigned char tweak[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
