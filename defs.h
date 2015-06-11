// change salt to get another unique profile
static const unsigned char salt[] = {0x00, 0x00};

// selftest data for current salt
/* #define _SELFTEST_CURRENT */
static const char testmaster[] = "x";
static const char testname[] = "x";
static const char testxpwd[] = "123";

static int plen = 15;
static int offs = 15;
static int numrounds = 5000;
