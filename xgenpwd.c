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

static FL_FORM *form;
static Window win;
static FL_OBJECT *master, *name, *mhashbox, *outbox, *idsbr, *pwlcnt;
static FL_OBJECT *masbut, *nambut, *mkbutton, *copybutton, *clearbutton, *quitbutton;

#include "icon.xpm"

static int format_option;
static char data[1024];

static char *progname;
static char newtitle[64];

static char *stoi;

size_t _slen = sizeof(salt);

static void usage(void)
{
	printf("usage: %s [-ODX8946mUN] [-n PASSES] [-o OFFSET]"
	       	" [-l PASSLEN] [-s filename/-]\n\n", progname);
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
			" or stdin (if '-')\n\n");
	exit(1);
}

static void fill_list(const char *str)
{
	fl_addto_browser(idsbr, str);
}

static void select_entry(FL_OBJECT *brobj, long arg FL_UNUSED_ARG)
{
	fl_set_input(name, fl_get_browser_line(brobj, fl_get_browser(brobj)));
}

static void set_password_length(FL_OBJECT *obj FL_UNUSED_ARG, long data FL_UNUSED_ARG)
{
	default_password_length = (int)fl_get_counter_value(pwlcnt);
}

static void set_output_label_size(int output_passwd_length)
{
	int lsize;

	if (output_passwd_length < 15) lsize = FL_MEDIUM_SIZE;
	else if (output_passwd_length < 30) lsize = FL_NORMAL_SIZE;
	else if (output_passwd_length < 37) lsize = FL_SMALL_SIZE;
	else lsize = FL_TINY_SIZE;

	fl_set_object_lsize(outbox, lsize);
}

static void process_entries(void)
{
	char password[MKPWD_OUTPUT_MAX]; size_t pwl;
	const char *d[4] = {NULL};
	char *output, *fmt;
	size_t n;

	mkpwd_adjust();

	mkpwd_output_format = format_option;
	memset(password, 0, sizeof(password));
	d[0] = fl_get_input(master);
	pwl = strlen(d[0]);
	memcpy(password, d[0], pwl);
	d[0] = password; d[1] = fl_get_input(name); d[2] = NULL;
	if (!d[1][0]) return;
	if (format_option >= 0x1001 && format_option <= 0x1006) { d[2] = data; d[3] = NULL; }
	output = mkpwd(_salt, _slen, d);

	fmt = mkpwd_hint(password, pwl);
	fl_set_object_label(mhashbox, fmt);
	memset(fmt, 0, 4);

	n = strlen(output); /* no utf8 there... */
	if (n != default_password_length) {
		*output = 0;
		strcpy(output+1, "INVALID");
	}

	set_output_label_size(n);
	fl_set_object_label(outbox, !*output ? output+1 : output);

	memset(password, 0, sizeof(password));
	memset(output, 0, MKPWD_OUTPUT_MAX); output = NULL;

	if (!is_dupid(d[1])) {
		addid(d[1]);
		to_saveids(1);
		fl_addto_browser(idsbr, d[1]);
	}

	memset(newtitle, 0, sizeof(newtitle));
	memcpy(newtitle+(sizeof(newtitle)-(sizeof(newtitle)/2)), d[1], TITLE_SHOW_CHARS);
	if (strlen(d[1]) >= TITLE_SHOW_CHARS) fmt = "%s: %s...";
	else fmt = "%s: %s";
	snprintf(newtitle, sizeof(newtitle), fmt, progname,
		newtitle+(sizeof(newtitle)-(sizeof(newtitle)/2)));
	fl_wintitle(win, newtitle);
	memset(newtitle, 0, sizeof(newtitle));
}

static void copyclipboard(void)
{
	const char *data = fl_get_object_label(outbox);
	long len = (long)strlen(data);

	fl_stuff_clipboard(outbox, 0, data, len, NULL);
}

/* A HACK! But no other way to ensure that password is wiped out... */
struct zero_input_hack {
	char *str;
	unsigned int pad1[2];
	int pad2[3];
	int size;
};

static void safe_zero_input(FL_OBJECT *input)
{
	struct zero_input_hack *spec = (struct zero_input_hack *)input->spec;
	memset(spec->str, 0, spec->size);
}

static void clearinput(FL_OBJECT *input)
{
	safe_zero_input(input);
	fl_set_input(input, NULL);
}

static void safe_zero_object_label(FL_OBJECT *obj)
{
	size_t n = strlen(obj->label);
	memset(obj->label, 0, n);
}

static void clearentries(void)
{
	clearinput(master);
	clearinput(name);

	safe_zero_object_label(outbox);
	fl_set_object_label(outbox, " -- ");
	safe_zero_object_label(mhashbox);
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

	fl_malloc = genpwd_malloc;
	fl_free = genpwd_free;
	fl_realloc = genpwd_realloc;
	fl_calloc = genpwd_calloc;

	if (!selftest())
		xerror("Self test failed. Program probably broken.");

	opterr = 0;
	while ((c = getopt(argc, argv, "n:o:l:ODX89s:4::6::m::UN")) != -1) {
		switch (c) {
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

	fl_set_border_width(-1);
	fl_initialize(&argc, argv, "xgenpwd", NULL, 0);

	int i; for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;

	form = fl_bgn_form(FL_BORDER_BOX, 280, 385);

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

	outbox = fl_add_box(FL_SHADOW_BOX, 5, 270, 270, 50, " -- ");

	pwlcnt = fl_add_counter(FL_SIMPLE_COUNTER, 5, 325, 270, 20, NULL);
	fl_set_counter_precision(pwlcnt, 0);
	fl_set_counter_value(pwlcnt, (double)default_password_length);
	fl_set_counter_bounds(pwlcnt, (double)0, (double)MKPWD_OUTPUT_MAX);
	fl_set_counter_step(pwlcnt, (double)1, (double)0);
	fl_set_counter_repeat(pwlcnt, 150);
	fl_set_counter_min_repeat(pwlcnt, 25);
	fl_set_object_callback(pwlcnt, set_password_length, 0);

	mkbutton = fl_add_button(FL_NORMAL_BUTTON, 5, 350, 60, 30, "Make");
	fl_set_object_shortcut(mkbutton, "^M", 0);
	copybutton = fl_add_button(FL_NORMAL_BUTTON, 75, 350, 60, 30, "Copy");
	fl_set_object_shortcut(copybutton, "^B", 0);
	clearbutton = fl_add_button(FL_NORMAL_BUTTON, 145, 350, 60, 30, "Clear");
	fl_set_object_shortcut(clearbutton, "^L", 0);
	quitbutton = fl_add_button(FL_NORMAL_BUTTON, 215, 350, 60, 30, "Quit");
	fl_set_object_shortcut(quitbutton, "^[", 0);

	fl_end_form();

	fl_show_form(form, FL_PLACE_CENTER, FL_FULLBORDER, "xgenpwd");

	win = fl_winget();

	fl_set_form_icon_data(form, icon);
	fl_set_cursor(win, XC_left_ptr);

	do {
		if (called == mkbutton)
			process_entries();
		else if (called == copybutton)
			copyclipboard();
		else if (called == clearbutton)
			clearentries();
		else if (called == masbut) {
			clearinput(master);
			safe_zero_object_label(mhashbox);
			fl_set_object_label(mhashbox, " -- ");
		}
		else if (called == nambut)
			removeitem();
		else if (called == quitbutton) break;
	} while ((called = fl_do_forms()));

	clearentries();

	saveids();

	fl_finish();

	return 0;
}
