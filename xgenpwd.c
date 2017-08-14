#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

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

#define TITLE_SHOW_CHARS 16

static FL_FORM *form;
static Window win;
static FL_OBJECT *master, *name, *mhashbox, *outbox, *idsbr, *pwlcnt;
static FL_OBJECT *masbut, *nambut, *mkbutton, *copybutton, *clearbutton, *quitbutton;
static FL_OBJECT *search, *srchup, *srchdown;

static FL_COLOR srchcol1, srchcol2;

#include "icon.xpm"

static int format_option;
static int do_not_show;
static char data[128];
static char shadowed[MKPWD_OUTPUT_MAX];

char *progname;
static char newtitle[64];

static char *stoi;

size_t _slen = sizeof(salt);

static void usage(void)
{
	if (optopt == 'V') {
		printf("genpwd passwords keeper.\n");
		printf("Version %s, X11 XForms port.\n", _GENPWD_VERSION);
		exit(0);
	}

	printf("usage: %s [-xODX8946mdUNi] [-n PASSES] [-o OFFSET]"
		" [-l PASSLEN] [-s filename/-]\n\n", progname);
	printf("  -x: do not show password in output box. 'Copy' button will work.\n");
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
	printf("  -N: do not save ID data typed in Name field\n");
	printf("  -i: list identifiers from .genpwd.ids\n");
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

static void clearinput(FL_OBJECT *input);

static void select_entry(FL_OBJECT *brobj, long arg FL_UNUSED_ARG)
{
	const char *sel = fl_get_browser_line(brobj, fl_get_browser(brobj));
	const char *srch = fl_get_input(search);

	fl_set_input(name, sel);
	if (!arg) {
		clearinput(search);
		fl_set_object_color(search, srchcol1, srchcol2);
	}
	if (!arg && srch && *srch && strstr(sel, srch))
		fl_set_object_color(search, srchcol1, FL_LIGHTGREEN);
}

/* TODO: optimise these three somehow... */
static void searchitem(void)
{
	const char *what = fl_get_input(search);
	const char *srch;
	int x;

	if (!what || !*what) goto out;

	for (x = 1, srch = NULL; ; x++) {
		srch = fl_get_browser_line(idsbr, x);
		if (!srch) goto out;
		if (strstr(srch, what)) {
			fl_select_browser_line(idsbr, x);
			fl_set_browser_topline(idsbr, x);
			select_entry(idsbr, 1/* true: do not do additional color work */);
			fl_set_object_color(search, srchcol1, FL_LIGHTGREEN);
			return;
		}
	}

out:	fl_deselect_browser(idsbr);
	clearinput(name);
	fl_set_object_color(search, srchcol1, (what && !*what) ? srchcol2 : FL_INDIANRED);
}

static void searchitemup(void)
{
	const char *what = fl_get_input(search);
	const char *srch;
	int idx = fl_get_browser(idsbr);
	int x;

	if (!what || !*what || !idx) return;

	for (x = idx-1, srch = NULL; x >= 1; x--) {
		srch = fl_get_browser_line(idsbr, x);
		if (!srch) return;
		if (strstr(srch, what)) {
			fl_select_browser_line(idsbr, x);
			fl_set_browser_topline(idsbr, x);
			select_entry(idsbr, 1);
			fl_set_object_color(search, srchcol1, FL_LIGHTGREEN);
			return;
		}
	}
}

static void searchitemdown(void)
{
	const char *what = fl_get_input(search);
	const char *srch;
	int idx = fl_get_browser(idsbr);
	int x;

	if (!what || !*what || !idx) return;

	for (x = idx+1, srch = NULL; ; x++) {
		srch = fl_get_browser_line(idsbr, x);
		if (!srch) return;
		if (strstr(srch, what)) {
			fl_select_browser_line(idsbr, x);
			fl_set_browser_topline(idsbr, x);
			select_entry(idsbr, 1);
			fl_set_object_color(search, srchcol1, FL_LIGHTGREEN);
			return;
		}
	}
}

static void set_password_length(FL_OBJECT *obj FL_UNUSED_ARG, long data FL_UNUSED_ARG)
{
	default_password_length = (int)fl_get_counter_value(pwlcnt);
}

static void set_output_label_size(int output_passwd_length)
{
	int lsize;

	if (output_passwd_length <= 18) lsize = FL_MEDIUM_SIZE;
	else if (output_passwd_length <= 25) lsize = FL_NORMAL_SIZE;
	else if (output_passwd_length <= 32) lsize = FL_SMALL_SIZE;
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

	fmt = mkpwd_hint(_salt, _slen, password);
	fl_set_object_label(mhashbox, fmt);
	memset(fmt, 0, 4);

	n = strlen(output); /* no utf8 there... */
	if (n && n != default_password_length && format_option <= 5) {
		memset(output, 0, MKPWD_OUTPUT_MAX);
		strcpy(output+1, "(INVALID)");
		n = sizeof("(INVALID)")-1;
	}

	if (do_not_show && *output) {
		memset(shadowed, 0, sizeof(shadowed));
		set_output_label_size(sizeof("(HIDDEN)")-1);
		fl_set_object_label(outbox, "(HIDDEN)");
		strncpy(shadowed, output, n);
	}
	else {
		set_output_label_size(n);
		fl_set_object_label(outbox, !*output ? output+1 : output);
	}

	fl_deactivate_object(master);

	memset(password, 0, sizeof(password));
	if (*output) memset(output, 0, MKPWD_OUTPUT_MAX); output = NULL;

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
	const char *data = shadowed[0] ? shadowed : fl_get_object_label(outbox);
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
	fl_activate_object(master);
	clearinput(name);

	safe_zero_object_label(outbox);
	fl_set_object_label(outbox, " -- ");
	safe_zero_object_label(mhashbox);
	fl_set_object_label(mhashbox, " -- ");

	clearinput(search);
	fl_set_object_color(search, srchcol1, srchcol2);

	fl_wintitle(win, progname);
	fl_set_focus_object(form, master);
	fl_deselect_browser(idsbr);
}

static void removeitem(void)
{
	int x = fl_get_browser(idsbr);
	const char *line = fl_get_browser_line(idsbr, x);

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
		xerror(0, 1, "Self test failed. Program probably broken.");

	opterr = 0;
	while ((c = getopt(argc, argv, "xn:o:l:ODX89is:46md:UN")) != -1) {
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
				if (*stoi || !default_password_length || default_password_length < 0 || default_password_length > MKPWD_OUTPUT_MAX)
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
				loadsalt(optarg, &_salt, &_slen);
				break;
			case '4':
				format_option = 0x1004;
				strcpy(data, "0.0.0.0/0");
				break;
			case '6':
				format_option = 0x1006;
				strcpy(data, "::/0");
				break;
			case 'm':
				format_option = 0x1001;
				strcpy(data, "0:0:0:0:0:0.0");
				break;
			case 'd':
				memset(data, 0, sizeof(data));
				strncpy(data, optarg, sizeof(data)-1);
				break;
			case 'U':
				format_option = 0xff;
				break;
			case 'N':
				to_saveids(-1);
				break;
			case 'i':
				listids();
				break;
			case 'x':
				do_not_show = 1;
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

	form = fl_bgn_form(FL_BORDER_BOX, 280, 410);

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
	loadids(fill_list);
	fl_set_browser_topline(idsbr, 1);

	search = fl_add_input(FL_NORMAL_INPUT, 5, 270, 210, 25, NULL);
	fl_set_object_return(search, FL_RETURN_CHANGED);
	fl_get_object_color(search, &srchcol1, &srchcol2);
	srchup = fl_add_button(FL_NORMAL_BUTTON, 220, 270, 25, 25, "@8>");
	fl_set_object_shortcut(srchup, "^P", 0);
	srchdown = fl_add_button(FL_NORMAL_BUTTON, 250, 270, 25, 25, "@2>");
	fl_set_object_shortcut(srchdown, "^N", 0);

	outbox = fl_add_box(FL_SHADOW_BOX, 5, 300, 270, 50, " -- ");
	fl_set_object_lstyle(outbox, FL_FIXED_STYLE|FL_BOLD_STYLE);

	pwlcnt = fl_add_counter(FL_SIMPLE_COUNTER, 5, 355, 270, 20, NULL);
	fl_set_counter_precision(pwlcnt, 0);
	fl_set_counter_value(pwlcnt, (double)default_password_length);
	fl_set_counter_bounds(pwlcnt, (double)0, (double)MKPWD_OUTPUT_MAX);
	fl_set_counter_step(pwlcnt, (double)1, (double)0);
	fl_set_counter_repeat(pwlcnt, 150);
	fl_set_counter_min_repeat(pwlcnt, 25);
	fl_set_object_callback(pwlcnt, set_password_length, 0);

	mkbutton = fl_add_button(FL_NORMAL_BUTTON, 5, 380, 60, 25, "Make");
	fl_set_object_shortcut(mkbutton, "^M", 0);
	copybutton = fl_add_button(FL_NORMAL_BUTTON, 75, 380, 60, 25, "Copy");
	fl_set_object_shortcut(copybutton, "^B", 0);
	clearbutton = fl_add_button(FL_NORMAL_BUTTON, 145, 380, 60, 25, "Clear");
	fl_set_object_shortcut(clearbutton, "^L", 0);
	quitbutton = fl_add_button(FL_NORMAL_BUTTON, 215, 380, 60, 25, "Quit");
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
			fl_activate_object(master);
			fl_set_focus_object(form, master);
			safe_zero_object_label(mhashbox);
			fl_set_object_label(mhashbox, " -- ");
		}
		else if (called == nambut) {
			clearinput(name);
			fl_set_focus_object(form, name);
			removeitem();
		}
		else if (called == search)
			searchitem();
		else if (called == srchup)
			searchitemup();
		else if (called == srchdown)
			searchitemdown();
		else if (called == quitbutton) break;
	} while ((called = fl_do_forms()));

	clearentries();
	memset(data, 0, sizeof(data));
	memset(shadowed, 0, sizeof(shadowed));

	saveids();

	fl_finish();

	genpwd_exit_memory();

	return 0;
}
