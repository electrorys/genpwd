/* change salt to get another unique profile */
const unsigned char salt[] = {0x00, 0x00};

/* selftest data for current salt */
#ifdef _SELFTEST_CURRENT
const char testmaster[] = "x";
const char testname[] = "x";
const char testxpwd[] = "123";
#endif

int default_password_length = 15;
int default_string_offset = 15;
int default_passes_number = 5000;

const unsigned char tweak[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
