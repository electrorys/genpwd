#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>

#include "genpwd.h"
#include "getpasswd.h"
#include "genpwd_defs.h"

static char master[256], name[256];
static const char *d[] = {master, name, NULL, NULL};
static char *pwdout;
static int format_option;
static int no_newline;
static char *fkeyname;
static int genkeyf;
static char *data;
static int i, c, kfd = 1;

char *progname;

static char *stoi;

size_t salt_length = sizeof(salt);

static struct getpasswd_state getps;

static void usage(void)
{
	if (optopt == 'V') {
		printf("genpwd passwords keeper, version %s.\n", _GENPWD_VERSION);
		exit(0);
	}

	printf("usage: %s [-rODX8946mdULNik] [-n PASSES] [-o OFFSET] [-l PASSLEN]"
		" [-s filename] [-I idsfile] [-w outkey]\n\n", progname);
	printf("  -O: output only numeric octal password\n");
	printf("  -D: output only numeric password (useful for pin numeric codes)\n");
	printf("  -X: output hexadecimal password\n");
	printf("  -8: output base85 password\n");
	printf("  -9: output base95 password\n");
	printf("  -4: output an ipv4 address\n");
	printf("  -6: output an ipv6 address\n");
	printf("  -m: output a mac address\n");
	printf("  -d data: provide optional data for -46m options\n");
	printf("  -U: output a UUID\n");
	printf("  -k: request generation of binary keyfile\n");
	printf("  -L: omit newline when printing password\n");
	printf("  -N: do not save ID data typed in Name field\n");
	printf("  -i: list identifiers from .genpwd.ids\n");
	printf("  -I file: use alternate ids file instead of .genpwd.ids\n");
	printf("  -n PASSES: set number of PASSES of skein1024 function\n");
	printf("  -o OFFSET: offset from beginning of 'big-passwd' string\n");
	printf("  -l PASSLEN: sets the cut-out region of 'big-passwd' string\n");
	printf("  -s filename: load alternative binary salt from filename\n");
	printf("  -w outkey: write key or password to this file\n\n");
	exit(1);
}

static int getps_filter(struct getpasswd_state *getps, int chr, size_t pos)
{
	if (chr == '\x03') { /* ^C */
		getps->retn = NOSIZE;
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

static int getps_plain_filter(struct getpasswd_state *getps, int chr, size_t pos)
{
	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

int main(int argc, char **argv)
{
	progname = basename(argv[0]);

	if (!selftest())
		xerror(0, 1, "Self test failed. Program probably broken.");

	if (genpwd_save_ids == 0) will_saveids(SAVE_IDS_NEVER);

	opterr = 0;
	while ((c = getopt(argc, argv, "n:o:l:ODX89iI:s:LNkw:46md:U")) != -1) {
		switch (c) {
			case 'n':
				default_passes_number = strtol(optarg, &stoi, 10);
				if (*stoi || default_passes_number < 0 || default_passes_number > MKPWD_ROUNDS_MAX)
					xerror(0, 1, "%s: rounds number must be between 0 and %u", optarg, MKPWD_ROUNDS_MAX);
				break;
			case 'o':
				default_string_offset = strtol(optarg, &stoi, 10);
				if (*stoi || default_string_offset < 0 || default_string_offset > MKPWD_OUTPUT_MAX)
					xerror(0, 1, "%s: offset must be between 0 and %u", optarg, MKPWD_OUTPUT_MAX);
				break;
			case 'l':
				default_password_length = strtol(optarg, &stoi, 10);
				if (!fkeyname
				&& (*stoi || !default_password_length || default_password_length < 0 || default_password_length > MKPWD_OUTPUT_MAX))
					xerror(0, 1, "%s: password length must be between 1 and %u", optarg, MKPWD_OUTPUT_MAX);
				break;
			case 'O':
				format_option = 3;
				break;
			case 'D':
				format_option = 1;
				break;
			case 'X':
				format_option = 2;
				break;
			case '8':
				format_option = 4;
				break;
			case '9':
				format_option = 5;
				break;
			case 's':
				loadsalt(optarg, &loaded_salt, &salt_length);
				break;
			case 'L':
				no_newline = 1;
				break;
			case 'N':
				if (genpwd_save_ids == 0) {
					if (will_saveids(SAVE_IDS_QUERY) == SAVE_IDS_NEVER)
						will_saveids(SAVE_IDS_OVERRIDE);
					else will_saveids(SAVE_IDS_NEVER);
				}
				will_saveids(SAVE_IDS_NEVER);
				break;
			case 'i':
				listids();
				break;
			case 'I':
				/* will be erased later */
				if (genpwd_ids_filename) genpwd_free(genpwd_ids_filename);
				genpwd_ids_filename = genpwd_strdup(optarg);
				if (!genpwd_ids_filename) xerror(0, 0, "strdup(%s)", optarg);
				break;
			case 'k':
				if (!fkeyname) xerror(0, 1, "specify outkey with -w.");
				genkeyf = 1;
				break;
			case 'w':
				if (fkeyname) genpwd_free(fkeyname);
				fkeyname = genpwd_strdup(optarg);
				if (!fkeyname) xerror(0, 0, "strdup(%s)", optarg);
				break;
			case '4':
				format_option = 0x1004;
				if (data) genpwd_free(data);
				data = genpwd_strdup("0.0.0.0/0");
				if (!data) xerror(0, 0, "strdup");
				break;
			case '6':
				format_option = 0x1006;
				if (data) genpwd_free(data);
				data = genpwd_strdup("::/0");
				if (!data) xerror(0, 0, "strdup");
				break;
			case 'm':
				format_option = 0x1001;
				if (data) genpwd_free(data);
				data = genpwd_strdup("0:0:0:0:0:0.0");
				if (!data) xerror(0, 0, "strdup");
				break;
			case 'd':
				if (data) genpwd_free(data);
				data = genpwd_strdup(optarg);
				if (!data) xerror(0, 0, "strdup(%s)", optarg);
				break;
			case 'U':
				format_option = 0xff;
				break;
			default:
				usage();
				break;
		}
	}

	for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;

	memset(&getps, 0, sizeof(struct getpasswd_state));
	getps.fd = getps.efd = -1;
	getps.passwd = master;
	getps.pwlen = sizeof(master)-1;
	getps.echo = "Enter master: ";
	getps.charfilter = getps_filter;
	getps.maskchar = 'x';
	if (xgetpasswd(&getps) == NOSIZE) return 1;
	memset(&getps, 0, sizeof(struct getpasswd_state));

	pwdout = mkpwd_hint(loaded_salt, salt_length, master);
	fprintf(stderr, "Password hint: %s\n", pwdout);
	memset(pwdout, 0, 4);

	getps.fd = getps.efd = -1;
	getps.passwd = name;
	getps.pwlen = sizeof(name)-1;
	getps.echo = "Enter name: ";
	getps.charfilter = getps_plain_filter;
	getps.maskchar = 0;
	if (xgetpasswd(&getps) == NOSIZE) return 1;
	memset(&getps, 0, sizeof(struct getpasswd_state));

	loadids(NULL);
	if (!is_dupid(name)) {
		addid(name);
		will_saveids(SAVE_IDS_PLEASE);
	}

	mkpwd_adjust();

	if (fkeyname) {
		if (!(!strcmp(fkeyname, "-")))
			kfd = open(fkeyname, O_WRONLY | O_CREAT | O_LARGEFILE | O_TRUNC, 0666);
		if (kfd == -1) xerror(0, 0, fkeyname);
		if (kfd != 1) if (fchmod(kfd, S_IRUSR | S_IWUSR) != 0)
			xerror(0, 0, "chmod of %s failed", fkeyname);
		if (kfd != 1) no_newline = 1;
	}

	mkpwd_output_format = format_option;
	if (!genkeyf) {
		if (format_option >= 0x1001 && format_option <= 0x1006) d[2] = data;
		pwdout = mkpwd(loaded_salt, salt_length, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(0, 1, pwdout+1);
		write(kfd, pwdout, strlen(pwdout));
		if (!no_newline) write(kfd, "\n", 1);
		memset(pwdout, 0, MKPWD_OUTPUT_MAX); pwdout = NULL;
	}
	else {
		pwdout = mkpwbuf(loaded_salt, salt_length, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(0, 1, pwdout+1);
		write(kfd, pwdout, default_password_length);
		genpwd_free(pwdout); /* will erase automatically */
	}

	if (kfd != 1) close(kfd);

	saveids();

	genpwd_exit_memory();

	return 0;
}
