const unsigned char salt[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

#ifdef _SELFTEST_CURRENT
const char testmaster[] = "V8UlNKHXqye7Xgq";
const char testname[] = "genpwd password demo";
const char testxpwd[] = "6eNuk423uPKSYBG";
#endif

int default_password_length = 15;
int default_string_offset = 15;
int default_passes_number = 5000;
