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

#define TITLE_SHOW_CHARS 16

#define _genpwd_ids     ".genpwd.ids"

static char overwr[128];
static const char *poverwr = overwr;

static FL_FORM *form;
static Window win;
static FL_OBJECT *master, *name, *mhashbox, *outbox, *idsbr;
static FL_OBJECT *masbut, *nambut, *mkbutton, *copybutton, *clearbutton, *quitbutton;
static int xmaster, xname;

#include "icon.xpm"

static int format_option;
static char data[1024];

static char *progname;
static char newtitle[TITLE_SHOW_CHARS+sizeof("...")];

static char *stoi;

size_t _slen = sizeof(salt);

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
	printf("  -N: do not load and save ID data typed in Name field\n\n");
	exit(1);
}

static void fill_list(const char *str)
{
	fl_addto_browser(idsbr, str);
}

static void select_entry(FL_OBJECT *brobj, long arg)
{
	fl_set_input(name, fl_get_browser_line(brobj, fl_get_browser(brobj)));
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
	char cpmaster[MKPWD_OUTPUT_MAX];
	char mhash[8];
	const char *d[4] = {NULL};
	char *output, *fmt;

	load_defs();

	mkpwd_output_format = format_option;
	memset(cpmaster, 0, sizeof(cpmaster));
	memcpy(cpmaster, fl_get_input(master), mkpwd_password_length);
	d[0] = cpmaster; d[1] = fl_get_input(name); d[2] = NULL;
	if (!d[1][0]) return;
	if (format_option >= 0x1001 && format_option <= 0x1006) { d[2] = data; d[3] = NULL; }
	output = mkpwd(_salt, _slen, d);

	fl_set_object_label(outbox, !*output ? output+1 : output);

	memset(mhash, 0, sizeof(mhash));
	sk1024(cpmaster, strlen(cpmaster), mhash, 16);
	memset(cpmaster, 0, sizeof(cpmaster));
	/* reuse cpmaster, no password is here */
	snprintf(cpmaster, sizeof(cpmaster), "%02hx%02hx",
		(uint8_t)mhash[0], (uint8_t)mhash[1]);

	fl_set_object_label(mhashbox, cpmaster);

	memset(mhash, 0, sizeof(mhash));
	memset(cpmaster, 0, sizeof(cpmaster));
	memset(output, 0, MKPWD_OUTPUT_MAX); output = NULL;

	if (!is_dupid(d[1])) {
		addid(d[1]);
		to_saveids(1);
		fl_addto_browser(idsbr, d[1]);
	}

	memset(newtitle, 0, sizeof(newtitle));
	memcpy(newtitle, d[1], TITLE_SHOW_CHARS);
	if (strlen(d[1]) >= TITLE_SHOW_CHARS) fmt = "%s: %s...";
	else fmt = "%s: %s";
	fl_wintitle_f(win, fmt, progname, newtitle);
}

static void copyclipboard(void)
{
	const char *data = fl_get_object_label(outbox);
	long len = (long)strlen(data);

	fl_stuff_clipboard(outbox, 0, data, len, NULL);
}

static void clearinput(FL_OBJECT *input)
{
	fl_set_input(input, poverwr);
	fl_set_input(input, "");
}

static void clearentries(void)
{
	clearinput(master);
	clearinput(name);

	fl_set_object_label(outbox, poverwr);
	fl_set_object_label(outbox, "");
	fl_set_object_label(mhashbox, " -- ");

	fl_wintitle(win, progname);
	fl_set_focus_object(form, master);
	fl_deselect_browser(idsbr);
}

static void removeitem(void)
{
	int x = fl_get_browser(idsbr);
	const char *line = fl_get_browser_line(idsbr, x);

	clearinput(name);
	if (!delid(line)) return;
	fl_delete_browser_line(idsbr, x);
	to_saveids(1);
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
				if (*stoi || !default_password_length || default_password_length < 0 || default_password_length > MKPWD_OUTPUT_MAX)
					xerror("password length must be between 1 and "
						SMKPWD_OUTPUT_MAX);
				break;
			case 'x':
				/* ignored */
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
			case 'N':
				to_saveids(-1);
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

	form = fl_bgn_form(FL_BORDER_BOX, 280, 360);

	master = fl_add_input(FL_SECRET_INPUT, 5, 5, 205, 25, NULL);
	fl_set_object_return(master, FL_RETURN_CHANGED);
	fl_set_object_dblclick(master, 0);
	fl_set_input_maxchars(master, 64); /* XXX */

	mhashbox = fl_add_box(FL_FLAT_BOX, 215, 5, 30, 25, " -- ");

	masbut = fl_add_button(FL_NORMAL_BUTTON, 250, 5, 25, 25, "X");
	fl_set_object_shortcut(masbut, "^T", 0);

	name = fl_add_input(FL_NORMAL_INPUT, 5, 35, 240, 25, NULL);
	fl_set_object_return(name, FL_RETURN_CHANGED);

	nambut = fl_add_button(FL_NORMAL_BUTTON, 250, 35, 25, 25, "X");
	fl_set_object_shortcut(nambut, "^U", 0);

	idsbr = fl_add_browser(FL_HOLD_BROWSER, 5, 65, 270, 200, NULL);
	fl_set_object_return(idsbr, FL_RETURN_SELECTION);
	fl_set_object_callback(idsbr, select_entry, 0);
	fl_set_object_dblbuffer(idsbr, 1);
	fl_freeze_form(form);
	loadids(fill_list);
	fl_unfreeze_form(form);
	fl_set_browser_topline(idsbr, 1);

	outbox = fl_add_box(FL_SHADOW_BOX, 5, 270, 270, 50, NULL);

	mkbutton = fl_add_button(FL_NORMAL_BUTTON, 5, 325, 60, 30, "Make");
	fl_set_object_shortcut(mkbutton, "^M", 0);
	copybutton = fl_add_button(FL_NORMAL_BUTTON, 75, 325, 60, 30, "Copy");
	fl_set_object_shortcut(copybutton, "^B", 0);
	clearbutton = fl_add_button(FL_NORMAL_BUTTON, 145, 325, 60, 30, "Clear");
	fl_set_object_shortcut(clearbutton, "^L", 0);
	quitbutton = fl_add_button(FL_NORMAL_BUTTON, 215, 325, 60, 30, "Quit");
	fl_set_object_shortcut(quitbutton, "^[", 0);

	fl_end_form();

	fl_show_form(form, FL_PLACE_CENTER, FL_FULLBORDER, "xgenpwd");

	win = fl_winget();

	fl_set_form_icon_data(form, icon);
	fl_set_cursor(win, XC_left_ptr);

	do {
		saveinputpos();

		if (called == mkbutton)
			process_entries();
		else if (called == copybutton)
			copyclipboard();
		else if (called == clearbutton)
			clearentries();
		else if (called == masbut) {
			clearinput(master);
			fl_set_object_label(mhashbox, " -- ");
		}
		else if (called == nambut)
			removeitem();
		else if (called == quitbutton) break;

		restoreinputpos();
	} while ((called = fl_do_forms()));

	clearentries();

	saveids();

	fl_finish();

	return 0;
}
