#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>

#include "genpwd.h"
#include "defs.h"

#define _strpp(x) #x
#define _istr(x) _strpp(x)
#define SMKPWD_OUTPUT_MAX _istr(MKPWD_OUTPUT_MAX)
#define SMKPWD_ROUNDS_MAX _istr(MKPWD_ROUNDS_MAX)

static char *progname = NULL;

static char *stoi;

size_t _slen = sizeof(salt);

static void usage(void)
{
	printf("usage: %s [-rODX8946mUN] [-n PASSES] [-o OFFSET] [-l PASSLEN]"
	       	" [-s/k filename/-]\n\n", progname);
	printf("  -r: repeat mode\n");
	printf("  -O: output only numeric octal password\n");
	printf("  -D: output only numeric password (useful for pin numeric codes)\n");
	printf("  -X: output hexadecimal password\n");
	printf("  -8: output base85 password\n");
	printf("  -9: output base95 password\n");
	printf("  -4[ADDR/PFX]: output an ipv4 address*\n");
	printf("  -6[ADDR/PFX]: output an ipv6 address*\n");
	printf("  -m[ADDR.PFX]: output a mac address*\n");
	printf("    * - ADDR/PFX: example: 127.16.0.0/16 (generates local address)\n");
	printf("    * - ADDR.PFX: example: 04:5e:30:23:00:00.32 \n");
	printf("  -U: output a UUID\n");
	printf("  -N: do not save ID data typed in Name field\n");
	printf("  -n PASSES: set number of PASSES of skein1024 function\n");
	printf("  -o OFFSET: offset from beginning of 'big-passwd' string\n");
	printf("  -l PASSLEN: with offset, sets the region of passwd substring from"
	       	" 'big-passwd' string\n");
	printf("  -s filename: load alternative binary salt from filename"
	       	" or stdin (if '-')\n");
	printf("  -k filename: generate a keyfile instead of password\n\n");
	exit(1);
}

/* Thanks to musl for this code */
static void getpasswd(char *password, const char *echo, size_t pwdlen)
{
	int fd;
	struct termios s, t;
	ssize_t l;

	if ((fd = open("/dev/tty", O_RDONLY|O_NOCTTY)) < 0) fd = 0;

	tcgetattr(fd, &t);
	s = t;
	t.c_lflag &= ~ECHO;
	t.c_lflag |= ICANON;
	t.c_iflag &= ~(INLCR|IGNCR);
	t.c_iflag |= ICRNL;
	tcsetattr(fd, TCSAFLUSH, &t);
	tcdrain(fd);

	fputs(echo, stderr);
	fflush(stderr);

	l = read(fd, password, pwdlen);
	if (l >= 0) {
		if (l > 0 && password[l-1] == '\n') l--;
		password[l] = 0;
	}

	fputc('\n', stderr);
	fflush(stderr);

	tcsetattr(fd, TCSAFLUSH, &s);

	if (fd > 2) close(fd);
}

static void getstring(char *out, const char *echo, int len)
{
	int fd;
	ssize_t l;

	fputs(echo, stderr);
	fflush(stderr);

	if ((fd = open("/dev/tty", O_RDONLY|O_NOCTTY)) < 0) fd = 0;

	l = read(fd, out, len);
	if (l >= 0) {
		if (l > 0 && out[l-1] == '\n') l--;
		out[l] = 0;
	}

	if (fd > 2) close(fd);
}


int main(int argc, char **argv)
{
	progname = basename(argv[0]);

	char master[256] = {0}, name[256] = {0};
	const char *d[] = {master, name, NULL, NULL};
	char *pwdout = NULL;

	int format_option = 0;
	int repeat = 0;
	char keyfile[1024] = {0};
	char data[256] = {0};

	int c = 0;

	if (!selftest())
		xerror("Self test failed. Program probably broken.");

	opterr = 0;
	while ((c = getopt(argc, argv, "n:ro:l:ODX89s:Nk:4::6::m::U")) != -1) {
		switch (c) {
			case 'r':
				repeat = 1;
				break;
			case 'n':
				default_passes_number = strtol(optarg, &stoi, 10);
				if (*stoi || default_passes_number < 0 || default_passes_number > MKPWD_ROUNDS_MAX)
					xerror("rounds number must be between 0 and "
						SMKPWD_ROUNDS_MAX);
				break;
			case 'o':
				default_string_offset = strtol(optarg, &stoi, 10);
				if (*stoi || default_string_offset < 0 || default_string_offset > MKPWD_OUTPUT_MAX)
					xerror("offset must be between 0 and " SMKPWD_OUTPUT_MAX);
				break;
			case 'l':
				default_password_length = strtol(optarg, &stoi, 10);
				if (!keyfile[0]
				&& (*stoi || !default_password_length || default_password_length < 0 || default_password_length > MKPWD_OUTPUT_MAX))
					xerror("password length must be between 1 and "
						SMKPWD_OUTPUT_MAX);
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
				loadsalt(optarg, &_salt, &_slen);
				break;
			case 'N':
				to_saveids(-1);
				break;
			case 'k':
				strncpy(keyfile, optarg, sizeof(keyfile)-1);
				break;
			case '4':
				format_option = 0x1004;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "0.0.0.0/0");
				break;
			case '6':
				format_option = 0x1006;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "::/0");
				break;
			case 'm':
				format_option = 0x1001;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "0:0:0:0:0:0.0");
				break;
			case 'U':
				format_option = 0xff;
				break;
			default:
				usage();
				break;
		}
	}

	int i; for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;

_again:
	getpasswd(master, "Enter master:", sizeof(master)-1);
	if (repeat) {
		char rep[sizeof(master)] = {0};
		getpasswd(rep, "Repeat master:", sizeof(rep)-1);
		if (strncmp(master, rep, sizeof(master)-1)) {
			fprintf(stderr, "Master passwords don't match\n");
			goto _again;
		}
		memset(rep, 0, sizeof(rep));
	}
	if (!name[0])
		getstring(name, "Enter name:", sizeof(name)-1);

	loadids(NULL);
	if (!is_dupid(name)) {
		addid(name);
		to_saveids(1);
	}

	mkpwd_adjust();

	mkpwd_output_format = format_option;
	if (!keyfile[0]) {
		if (format_option >= 0x1001 && format_option <= 0x1006) d[2] = data;
		pwdout = mkpwd(_salt, _slen, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(pwdout+1);
	
		printf("%s\n", pwdout);
		memset(pwdout, 0, MKPWD_OUTPUT_MAX); pwdout = NULL;
	}
	else {
		FILE *f;

		if (!strcmp(keyfile, "-")) f = stdout;
		else {
			f = fopen(keyfile, "wb");
			if (!f) { perror(keyfile); fclose(f); exit(1); }
			if (fchmod(fileno(f), S_IRUSR | S_IWUSR) != 0) {
				perror(keyfile); fclose(f); exit(1);
			}
		}

		pwdout = mkpwbuf(_salt, _slen, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(pwdout+1);

		fwrite(pwdout, default_password_length, 1, f);
		fclose(f);
		memset(pwdout, 0, default_password_length); genpwd_free(pwdout);
	}

	saveids();

	return 0;
}
