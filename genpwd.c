#include "genpwd.h"
#include "genpwd_defs.h"

static char *masterpw;
static char *identifier;
static short format_option = MKPWD_FMT_B64;
static char *charset;
static gpwd_yesno no_newline;
static char *fkeyname;
static gpwd_yesno genkeyf;
static int kfd = 1;

char *progname;

static char *stoi;

static struct mkpwd_args *mkpwa;
static struct getpasswd_state *getps;

static void usage(void)
{
	if (optopt == 'V') {
		char *shash = genpwd_malloc(64);
		genpwd_say("genpwd passwords keeper, version %s.", _GENPWD_VERSION);
		genpwd_hash_defaults(shash, 64);
		genpwd_say("Defaults hash: %s", shash);
		genpwd_free(shash);
		genpwd_exit(0);
	}

	genpwd_say("usage: %s [opts] [--]", progname);
	genpwd_say("\n");
	genpwd_say("genpwd: generate passwords that could be recalled later.");
	genpwd_say("\n");
	genpwd_say("  -L <file>: load genpwd defaults from file.");
	genpwd_say("  -O: output only numeric octal password");
	genpwd_say("  -D: output only numeric password (useful for pin numeric codes)");
	genpwd_say("  -X: output hexadecimal password");
	genpwd_say("  -8: output base85 password");
	genpwd_say("  -9: output base95 password");
	genpwd_say("  -C: like normal password, but with more digits");
	genpwd_say("  -U charset: generate password characters from the given charset");
	genpwd_say("  -U <alnum>: generate password characters from [a-zA-Z0-9] charset");
	genpwd_say("  -U <alpha>: generate password characters from [a-zA-Z] charset");
	genpwd_say("  -U <digit>: generate password characters from [0-9] charset");
	genpwd_say("  -U <xdigit>: generate password characters from [0-9a-f] charset");
	genpwd_say("  -U <uxdigit>: generate password characters from [0-9A-F] charset");
	genpwd_say("  -U <lower>: generate password characters from [a-z] charset");
	genpwd_say("  -U <upper>: generate password characters from [A-Z] charset");
	genpwd_say("  -U <ascii>: generate password characters from all ASCII characters");
	genpwd_say("  -k: request generation of binary keyfile");
	genpwd_say("  -j: omit newline when printing password");
	genpwd_say("  -N: do not save ID data typed in Name field");
	genpwd_say("  -i: list identifiers from .genpwd.ids");
	genpwd_say("  -I file: use alternate ids file instead of .genpwd.ids");
	genpwd_say("  -l pwlen: sets the cut-out region of 'big-passwd' string");
	genpwd_say("  -w outkey: write key or password to this file");
	genpwd_say("\n");
	genpwd_exit(1);
}

static int getps_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	if (chr == '\x03') { /* ^C */
		getps->retn = ((size_t)-2);
		return 6;
	}
	return 1;
}

static inline int isctrlchr(int c)
{
	if (c == 9) return 0;
	if (c >= 0 && c <= 31) return 1;
	if (c == 127) return 1;
	return 0;
}

static int getps_plain_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	int x;

	x = getps_filter(getps, chr, pos);
	if (x != 1) return x;

	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

int main(int argc, char **argv)
{
	int c;
	char *s, *d;
	size_t x;

	install_signals();

	progname = genpwd_strdup(basename(*argv));
	mkpwa = genpwd_malloc(sizeof(struct mkpwd_args));
	getps = genpwd_malloc(sizeof(struct getpasswd_state));
	masterpw = genpwd_malloc(GENPWD_MAXPWD);
	identifier = genpwd_malloc(GENPWD_MAXPWD);

	s = genpwd_malloc(PATH_MAX);
	d = getenv("HOME");
	if (!d) d = "";
	if (xstrlcpy(s, d, PATH_MAX) >= PATH_MAX) goto _baddfname;
	if (xstrlcat(s, "/.genpwd.defs", PATH_MAX) >= PATH_MAX) goto _baddfname;
	genpwd_read_defaults(s, YES);
_baddfname:
	genpwd_free(s);

	if (genpwd_save_ids == NO) genpwd_will_saveids(SAVE_IDS_NEVER);

	opterr = 0;
	while ((c = getopt(argc, argv, "L:l:ODX89U:CiI:jNkw:")) != -1) {
		switch (c) {
			case 'L':
				genpwd_read_defaults(optarg, NO);
				break;
			case 'l':
				default_password_length = strtoul(optarg, &stoi, 10);
				if (!fkeyname
				&& (!str_empty(stoi) || default_password_length == 0))
					xerror(NO, YES, "%s: invalid password length number", optarg);
				break;
			case 'O':
				format_option = MKPWD_FMT_OCT;
				break;
			case 'D':
				format_option = MKPWD_FMT_DEC;
				break;
			case 'X':
				format_option = MKPWD_FMT_HEX;
				break;
			case '8':
				format_option = MKPWD_FMT_A85;
				break;
			case '9':
				format_option = MKPWD_FMT_A95;
				break;
			case 'C':
				format_option = MKPWD_FMT_CPWD;
				break;
			case 'U':
				format_option = MKPWD_FMT_UNIV;
				if (!strcmp(optarg, "<alnum>"))
					optarg = ALNUM_STRING;
				else if (!strcmp(optarg, "<alpha>"))
					optarg = ALPHA_STRING;
				else if (!strcmp(optarg, "<digit>"))
					optarg = DIGIT_STRING;
				else if (!strcmp(optarg, "<xdigit>"))
					optarg = XDIGIT_STRING;
				else if (!strcmp(optarg, "<uxdigit>"))
					optarg = UXDIGIT_STRING;
				else if (!strcmp(optarg, "<ascii>"))
					optarg = ASCII_STRING;
				else if (!strcmp(optarg, "<lower>"))
					optarg = LOWER_STRING;
				else if (!strcmp(optarg, "<upper>"))
					optarg = UPPER_STRING;
				charset = genpwd_strdup(optarg);
				break;
			case 'j':
				no_newline = YES;
				break;
			case 'N':
				if (genpwd_save_ids == NO) {
					if (genpwd_will_saveids(SAVE_IDS_QUERY) == SAVE_IDS_NEVER)
						genpwd_will_saveids(SAVE_IDS_OVERRIDE);
					else genpwd_will_saveids(SAVE_IDS_NEVER);
				}
				genpwd_will_saveids(SAVE_IDS_NEVER);
				break;
			case 'i':
				genpwd_listids();
				break;
			case 'I':
				/* will be erased later */
				if (genpwd_ids_filename) genpwd_free(genpwd_ids_filename);
				genpwd_ids_filename = genpwd_strdup(optarg);
				break;
			case 'k':
				if (!fkeyname) xerror(NO, YES, "specify outkey with -w.");
				genkeyf = YES;
				break;
			case 'w':
				if (fkeyname) genpwd_free(fkeyname);
				fkeyname = genpwd_strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}

	for (x = 1; x < argc; x++) {
		memset(argv[x], 0, strlen(argv[x]));
		argv[x] = NULL;
	}
	argc = 1;

	mkpwa->pwd = masterpw;
	mkpwa->salt = genpwd_salt;
	mkpwa->szsalt = genpwd_szsalt;

	getps->fd = getps->efd = -1;
	getps->passwd = masterpw;
	getps->pwlen = genpwd_szalloc(masterpw)-1;
	getps->echo = "Enter master: ";
	getps->charfilter = getps_filter;
	getps->maskchar = 'x';
	x = xgetpasswd(getps);
	if (x == NOSIZE) xerror(NO, NO, "getting password");
	if (x == ((size_t)-2)) genpwd_exit(1);

	if (mkpwd_hint(mkpwa) == MKPWD_NO && mkpwa->error) xerror(NO, YES, "%s", mkpwa->error);
	genpwd_esay("Password hint: %s", mkpwa->result);
	genpwd_free(mkpwa->result);

	mkpwa->id = identifier;

	getps->fd = getps->efd = -1;
	getps->passwd = identifier;
	getps->pwlen = genpwd_szalloc(identifier)-1;
	getps->echo = "Enter name: ";
	getps->charfilter = getps_plain_filter;
	getps->maskchar = 0;
	x = xgetpasswd(getps);
	if (x == NOSIZE) xerror(NO, NO, "getting name");
	if (x == ((size_t)-2)) genpwd_exit(1);

	genpwd_loadids(NULL);
	if (!genpwd_is_dupid(identifier)) {
		genpwd_addid(identifier);
		genpwd_will_saveids(SAVE_IDS_PLEASE);
	}

	mkpwd_adjust(mkpwa);

	if (fkeyname) {
		if (!(!strcmp(fkeyname, "-")))
			kfd = creat(fkeyname, S_IRUSR | S_IWUSR);
		if (kfd == -1) xerror(NO, NO, "%s", fkeyname);
		if (kfd != 1) no_newline = YES;
	}

	mkpwa->format = format_option;
	if (charset) mkpwa->charset = charset;
	if (!genkeyf) {
		if (mkpwd(mkpwa) == MKPWD_NO && mkpwa->error)
			xerror(NO, YES, "%s", mkpwa->error);
		write(kfd, mkpwa->result, mkpwa->szresult);
		if (!no_newline) write(kfd, "\n", 1);
	}
	else {
		if (mkpwd_key(mkpwa) == MKPWD_NO && mkpwa->error) xerror(NO, YES, "%s", mkpwa->error);
		write(kfd, mkpwa->result, mkpwa->szresult);
	}

	if (kfd != 1) close(kfd);
	genpwd_saveids();
	genpwd_exit(0);

	return 0;
}
