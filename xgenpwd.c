#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <forms.h>
#include "genpwd.h"
#include "defs.h"

#define _strpp(x) #x
#define _istr(x) _strpp(x)
#define SMKPWD_OUTPUT_MAX _istr(MKPWD_OUTPUT_MAX)
#define SMKPWD_ROUNDS_MAX _istr(MKPWD_ROUNDS_MAX)

static char overwr[128];
static const char *poverwr = overwr;

static FL_FORM *form;
static FL_OBJECT *master, *name, *outbox;
static FL_OBJECT *mkbutton, *copybutton, *clearbutton, *quitbutton;
static int xmaster, xname;

static int numopt;
static char data[1024];
#if 0
static char **ids;
static int nids;
static int needtosaveids;
#endif

static char *progname;

static char *stoi;

static const unsigned char *_salt = salt;
static size_t _slen = sizeof(salt);

static void usage(void)
{
	printf("usage: %s [-rxODX8946mUN] [-n PASSES] [-o OFFSET]"
	       	" [-l PASSLEN] [-s filename/-]\n\n", progname);
	printf("  -r: (ignored)\n");
	printf("  -x: (ignored)\n");
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
	printf("  -n PASSES: set number of PASSES of skein1024 function\n");
	printf("  -o OFFSET: offset from beginning of 'big-passwd' string\n");
	printf("  -l PASSLEN: with offset, sets the region of passwd substring from"
	       	" 'big-passwd' string\n");
	printf("  -s filename: load alternative binary salt from filename"
			" or stdin (if '-')\n\n");
	printf("xgenpwd specific options:\n");
	printf("  -N: (unimplemented)\n\n");
	exit(1);
}

void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(2);
}

static void daemonise()
{
#ifdef DAEMONISE
	pid_t pid, sid;
	int i;

	pid = fork();
	if (pid < 0)
		exit(-1);
	if (pid > 0)
		exit(0);

	sid = setsid();
	if (sid < 0)
		exit(-1);

	close(0);
	close(1);
	close(2);
	for (i = 0; i < 3; i++)
		open("/dev/null", O_RDWR);
#else
	return;
#endif
}

static void saveinputpos(void)
{
	xmaster = strlen(fl_get_input(master));
	xname = strlen(fl_get_input(name));
}

static void restoreinputpos(void)
{
	fl_set_input_cursorpos(master, xmaster, 1);
	fl_set_input_cursorpos(name, xname, 1);
}

static void process_entries(void)
{
	const char *d[4] = {NULL};
	char *output;

	rounds = numrounds;
	offset = offs;
	passlen = plen;
	dechex = numopt;
	d[0] = fl_get_input(master); d[1] = fl_get_input(name); d[2] = NULL;
	if (!d[1][0]) return;
	if (numopt >= 0x1001 && numopt <= 0x1006) { d[2] = data; d[3] = NULL; }
	output = mkpwd(_salt, _slen, d);

	fl_set_object_label(outbox, !*output ? output+1 : output);

	memset(output, 0, MKPWD_OUTPUT_MAX); output = NULL;
}

static void copyclipboard(void)
{
	const char *data = fl_get_object_label(outbox);
	long len = (long)strlen(data);

	fl_stuff_clipboard(outbox, 0, data, len, NULL);
}

static void clearentries(void)
{
	fl_set_input(master, poverwr);
	fl_set_input(name, poverwr);
	fl_set_object_label(outbox, poverwr);

	fl_set_input(master, "");
	fl_set_input(name, "");
	fl_set_object_label(outbox, "");

	fl_set_focus_object(form, master);
}

int main(int argc, char **argv)
{
	int c;
	FL_OBJECT *called = NULL;

	progname = basename(argv[0]);

	if (!selftest())
		xerror("Self test failed. Program probably broken.");

	memset(overwr, 0, sizeof(overwr));
	memset(overwr, 'X', sizeof(overwr)-1);

	opterr = 0;
	while ((c = getopt(argc, argv, "n:rxo:l:ODX89s:4::6::m::UN")) != -1) {
		switch (c) {
			case 'r':
				/* ignored for now */
				break;
			case 'n':
				numrounds = strtol(optarg, &stoi, 10);
				if (*stoi || numrounds < 0 || numrounds > MKPWD_ROUNDS_MAX)
					xerror("rounds number must be between 0 and "
						SMKPWD_ROUNDS_MAX);
				break;
			case 'o':
				offs = strtol(optarg, &stoi, 10);
				if (*stoi || offs < 0 || offs > MKPWD_OUTPUT_MAX)
					xerror("offset must be between 0 and " SMKPWD_OUTPUT_MAX);
				break;
			case 'l':
				plen = strtol(optarg, &stoi, 10);
				if (*stoi || !plen || plen < 0 || plen > MKPWD_OUTPUT_MAX)
					xerror("password length must be between 1 and "
						SMKPWD_OUTPUT_MAX);
				break;
			case 'x':
				/* ignored */
				break;
			case 'O':
				numopt = 3;
				break;
			case 'D':
				numopt = 1;
				break;
			case 'X':
				numopt = 2;
				break;
			case '8':
				numopt = 4;
				break;
			case '9':
				numopt = 5;
				break;
			case 's':
				loadsalt(optarg, &_salt, &_slen);
				break;
			case '4':
				numopt = 0x1004;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "0.0.0.0/0");
				break;
			case '6':
				numopt = 0x1006;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "::/0");
				break;
			case 'm':
				numopt = 0x1001;
				if (optarg) strncpy(data, optarg, sizeof(data)-1);
				else strcpy(data, "0:0:0:0:0:0.0");
				break;
			case 'U':
				numopt = 0xff;
				break;
			case 'N':
				/* XXX unimplemented but needed! */
				break;
			default:
				usage();
				break;
		}
	}

	daemonise();

	fl_initialize(&argc, argv, "xgenpwd", NULL, 0);

	int i; for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;

	form = fl_bgn_form(FL_BORDER_BOX, 280, 165);

	master = fl_add_input(FL_SECRET_INPUT, 5, 5, 270, 30, "Master:");
	fl_set_object_return(master, FL_RETURN_CHANGED);

	name = fl_add_input(FL_NORMAL_INPUT, 5, 40, 270, 30, "Name:");
	fl_set_object_return(name, FL_RETURN_CHANGED);

	outbox = fl_add_box(FL_SHADOW_BOX, 5, 75, 270, 50, "");

	mkbutton = fl_add_button(FL_NORMAL_BUTTON, 5, 130, 60, 30, "Make");
	fl_set_object_shortcut(mkbutton, "^M", 0);
	copybutton = fl_add_button(FL_NORMAL_BUTTON, 75, 130, 60, 30, "Copy");
	fl_set_object_shortcut(copybutton, "^B", 0);
	clearbutton = fl_add_button(FL_NORMAL_BUTTON, 145, 130, 60, 30, "Clear");
	fl_set_object_shortcut(clearbutton, "^L", 0);
	quitbutton = fl_add_button(FL_NORMAL_BUTTON, 215, 130, 60, 30, "Quit");
	fl_set_object_shortcut(quitbutton, "^[", 0);

	fl_end_form();

	fl_show_form(form, FL_PLACE_CENTER, FL_FULLBORDER, "xgenpwd");

	do {
		saveinputpos();

		if (called == mkbutton)
			process_entries();
		else if (called == copybutton)
			copyclipboard();
		else if (called == clearbutton)
			clearentries();
		else if (called == quitbutton) break;

		restoreinputpos();
	} while ((called = fl_do_forms()));

	fl_set_object_label(outbox, poverwr);
	fl_set_input(master, poverwr);
	fl_set_input(name, poverwr);

	fl_finish();

	return 0;
}
