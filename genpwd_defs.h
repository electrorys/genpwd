#ifndef _GENPWD_DEFAULTS_HEADER
#define _GENPWD_DEFAULTS_HEADER

gpwd_yesno genpwd_save_ids = YES;

/* moEcRAeWbF9BGddi/Hm52RC2LkAryffE2hxMrYiwPSo= */

size_t genpwd_szsalt = 8;
gpwd_byte genpwd_salt[GENPWD_MAX_SALT] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

size_t default_password_length = 15;
size_t default_string_offset = 15;
size_t default_turns_number = 5000;

short default_password_format = MKPWD_FMT_B64;
char *default_password_charset = NULL;

#endif
