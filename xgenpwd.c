#include "genpwd.h"
#include "genpwd_defs.h"
#include <forms.h>

#include "x11icon.lst"

#define CLASSAPPNAME "xgenpwd"

int xwin_assign_icon_bmp(Display *d, Window w, const void *data);

#define TITLE_SHOW_CHARS 16

/* embedded genpwd parts */
static char *s_masterpw, *s_identifier;
static gpwd_yesno no_newline;
static char *fkeyname;
static gpwd_yesno genkeyf;
static int kfd = 1;
static gpwd_yesno merged = NO;
static gpwd_yesno do_random_pw = NO;
static gpwd_yesno shownumbers = NO;
static int *delentries;

static FL_FORM *form;
static Window win;
static FL_OBJECT *masterpw, *identifier, *mhashbox, *outbox, *idsbr;
static FL_OBJECT *pwlcnt, *pwloffs;
static FL_OBJECT *pwlfmt, *pwlchrs;
static FL_OBJECT *maspwbut, *idbut, *mkbutton, *copybutton, *clearbutton, *quitbutton;
static FL_OBJECT *search, *srchup, *srchdown;
static FL_OBJECT *hidepw;
static FL_OBJECT *called;

static FL_COLOR srchcol1, srchcol2;

static gpwd_yesno do_not_show;
static char *shadowed;

char *progname;

static char *stoi;

static struct mkpwd_args *mkpwa;
static struct getpasswd_state *getps;

static void usage(void)
{
	if (optopt == 'V') {
		char *shash = genpwd_malloc(64);

		genpwd_say("xgenpwd passwords keeper.");
		genpwd_say("Version %s, X11 XForms port.", _GENPWD_VERSION);
		genpwd_hash_defaults(shash, 64);
		genpwd_say("Defaults hash: %s", shash);
		genpwd_free(shash);
		genpwd_exit(0);
	}

	genpwd_say("usage: %s [opts] [--]", progname);
	genpwd_say("\n");
	genpwd_say("xgenpwd: generate passwords that could be recalled later.");
	genpwd_say("\n");
	genpwd_say("  -L <file>: load genpwd defaults from file.");
	genpwd_say("  -x: do not show password in output box. 'Copy' button will work.");
	genpwd_say("  -B: make password from base64 substring");
	genpwd_say("  -C: like normal password, but with more digits");
	genpwd_say("  -U charset: generate password characters from the given charset");
	genpwd_say("  -U " GENPWD_ALNUM_STRING_NAME ": generate password characters from [a-zA-Z0-9] charset");
	genpwd_say("  -U " GENPWD_ALPHA_STRING_NAME ": generate password characters from [a-zA-Z] charset");
	genpwd_say("  -U " GENPWD_DIGIT_STRING_NAME ": generate password characters from [0-9] charset");
	genpwd_say("  -U " GENPWD_XDIGIT_STRING_NAME ": generate password characters from [0-9a-f] charset");
	genpwd_say("  -U " GENPWD_UXDIGIT_STRING_NAME ": generate password characters from [0-9A-F] charset");
	genpwd_say("  -U " GENPWD_LOWER_STRING_NAME ": generate password characters from [a-z] charset");
	genpwd_say("  -U " GENPWD_UPPER_STRING_NAME ": generate password characters from [A-Z] charset");
	genpwd_say("  -U " GENPWD_ASCII_STRING_NAME ": generate password characters from all ASCII characters");
	genpwd_say("  -k: request generation of binary keyfile");
	genpwd_say("  -j: omit newline when printing password");
	genpwd_say("  -M <file>: load ids from file and merge them into current list.");
	genpwd_say("    After merging, program will terminate. This option can be given multiple times.");
	genpwd_say("  -N: do not save ID data typed in Name field");
	genpwd_say("  -R: do not ask for anything, and just generate random password of specified quality.");
	genpwd_say("  -i: list identifiers from .genpwd.ids");
	genpwd_say("  -I file: use alternate ids file instead of .genpwd.ids");
	genpwd_say("  -l pwlen: sets result password length");
	genpwd_say("  -w outkey: write key or password to this file");
	genpwd_say("  -n: with -i: show numbers near each entry.");
	genpwd_say("  -D <N>: delete numbered entry from .genpwd.ids file.");
	genpwd_say("\n");
	genpwd_exit(1);
}

static void update_classname(void)
{
	XClassHint clh;
	memset(&clh, 0, sizeof(XClassHint));
	clh.res_name = CLASSAPPNAME;
	clh.res_class = CLASSAPPNAME;
	XSetClassHint(fl_get_display(), win, &clh);
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

static void fill_list(const char *str)
{
	fl_addto_browser(idsbr, str);
}

static void clearinput(FL_OBJECT *input);

static void select_entry(FL_OBJECT *brobj, long arg FL_UNUSED_ARG)
{
	const char *sel = fl_get_browser_line(brobj, fl_get_browser(brobj));
	const char *srch = fl_get_input(search);

	fl_set_input(identifier, sel);
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

	if (!what || str_empty(what)) goto out;

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
	clearinput(identifier);
	fl_set_object_color(search, srchcol1, (what && str_empty(what)) ? srchcol2 : FL_INDIANRED);
}

static void searchitemup(void)
{
	const char *what = fl_get_input(search);
	const char *srch;
	int idx = fl_get_browser(idsbr);
	int x;

	if (!what || str_empty(what) || !idx) return;

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

	if (!what || str_empty(what) || !idx) return;

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
	default_password_length = (size_t)fl_get_counter_value(pwlcnt);
}

static void set_password_offset(FL_OBJECT *obj FL_UNUSED_ARG, long data FL_UNUSED_ARG)
{
	default_string_offset = (size_t)fl_get_counter_value(pwloffs);
}

static void set_password_format(FL_OBJECT *obj, long data FL_UNUSED_ARG)
{
	int fmt = fl_get_select_item(obj)->val;
	const char *chrs;

	if (fmt != 1) fl_deactivate_object(pwlchrs);
	if (fmt == 0) fl_activate_object(pwloffs);
	else fl_deactivate_object(pwloffs);
	switch (fmt) {
		case 0: default_password_format = MKPWD_FMT_B64; break;
		case 1: default_password_format = MKPWD_FMT_UNIV;
			fl_activate_object(pwlchrs);
			chrs = fl_get_input(pwlchrs);
			if (str_empty(chrs)) chrs = GENPWD_ALNUM_STRING_NAME;
			fl_set_input(pwlchrs, chrs);
			genpwd_free(default_password_charset);
			default_password_charset = genpwd_strdup(pwl_charset_string(chrs));
			break;
		case 2: default_password_format = MKPWD_FMT_CPWD; break;
	}
}


static void set_output_label_size(int output_passwd_length)
{
	int lsize;

	if (output_passwd_length <= 10) lsize = FL_HUGE_SIZE;
	else if (output_passwd_length <= 14) lsize = FL_LARGE_SIZE;
	else if (output_passwd_length <= 18) lsize = FL_MEDIUM_SIZE;
	else if (output_passwd_length <= 25) lsize = FL_NORMAL_SIZE;
	else if (output_passwd_length <= 32) lsize = FL_SMALL_SIZE;
	else lsize = FL_TINY_SIZE;

	fl_set_object_lsize(outbox, lsize);
}

static void hidepwd(void)
{
	do_not_show = fl_get_button(hidepw) ? YES : NO;
	if (do_not_show) {
		genpwd_free(shadowed);
		shadowed = genpwd_strdup(fl_get_object_label(outbox));
		set_output_label_size(CSTR_SZ("(HIDDEN)"));
		fl_set_object_label(outbox, "(HIDDEN)");
	}
	else {
		set_output_label_size(strlen(shadowed));
		fl_set_object_label(outbox, shadowed);
	}
}

static void process_entries(void)
{
	char *title, *fmt;

	mkpwd_adjust(mkpwa);
	set_password_format(pwlfmt, 0);
	mkpwa->charset = default_password_charset;

	if (do_random_pw == YES) {
		genpwd_will_saveids(SAVE_IDS_NEVER);
		s_masterpw = genpwd_malloc(GENPWD_PWD_MAX);
		s_identifier = genpwd_malloc(GENPWD_PWD_MAX);
		genpwd_getrandom(s_masterpw, genpwd_szalloc(s_masterpw));
		genpwd_getrandom(s_identifier, genpwd_szalloc(s_identifier));
		mkpwa->pwd = s_masterpw;
		mkpwa->id = s_identifier;
		mkpwa->szpwd = genpwd_szalloc(s_masterpw);
		mkpwa->szid = genpwd_szalloc(s_identifier);
	}
	else {
		mkpwa->pwd = fl_get_input(masterpw);
		mkpwa->id = fl_get_input(identifier);
		if (str_empty(mkpwa->id)) return;

		if (mkpwd_hint(mkpwa) == MKPWD_NO) goto _inval;
		fl_set_object_label(mhashbox, mkpwa->result);
		genpwd_free(mkpwa->result);
	}

	if (mkpwd(mkpwa) == MKPWD_NO) goto _inval;
	if (mkpwa->szresult != default_password_length) {
_inval:		fl_set_object_label(outbox, "(password generation error)");
		return;
	}

	if (do_not_show) {
		genpwd_free(shadowed);
		set_output_label_size(CSTR_SZ("(HIDDEN)"));
		fl_set_object_label(outbox, "(HIDDEN)");
		shadowed = genpwd_strdup(mkpwa->result);
	}
	else {
		set_output_label_size(mkpwa->szresult);
		fl_set_object_label(outbox, mkpwa->result);
	}

	if (masterpw) fl_deactivate_object(masterpw);
	genpwd_free(mkpwa->result);
	if (do_random_pw == YES) {
		genpwd_free(s_masterpw);
		genpwd_free(s_identifier);
		return;
	}

	if (!genpwd_is_dupid(mkpwa->id)) fl_addto_browser(idsbr, mkpwa->id);
	genpwd_addid(mkpwa->id);
	genpwd_will_saveids(SAVE_IDS_PLEASE);

	title = genpwd_malloc(TITLE_SHOW_CHARS*4);
	memcpy(title+(TITLE_SHOW_CHARS*2), mkpwa->id, TITLE_SHOW_CHARS);
	if (strlen(mkpwa->id) >= TITLE_SHOW_CHARS) fmt = "%s: %s...";
	else fmt = "%s: %s";
	snprintf(title, TITLE_SHOW_CHARS*2, fmt, progname, title+(TITLE_SHOW_CHARS*2));
	fl_wintitle(win, title);
	genpwd_free(title);
}

static void copyclipboard(void)
{
	const char *data = do_not_show ? shadowed : fl_get_object_label(outbox);
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
	if (masterpw) {
		clearinput(masterpw);
		fl_set_input_maxchars(masterpw, 64);
		fl_activate_object(masterpw);
	}
	if (identifier) clearinput(identifier);

	safe_zero_object_label(outbox);
	fl_set_object_label(outbox, " -- ");

	if (mhashbox) {
		safe_zero_object_label(mhashbox);
		fl_set_object_label(mhashbox, " -- ");
	}

	if (search) clearinput(search);
	if (search) fl_set_object_color(search, srchcol1, srchcol2);

	fl_wintitle(win, progname);
	if (masterpw) fl_set_focus_object(form, masterpw);
	if (idsbr) fl_deselect_browser(idsbr);
}

static void removeitem(void)
{
	int x = fl_get_browser(idsbr);
	const char *line = fl_get_browser_line(idsbr, x);

	if (!genpwd_delid(line)) return;
	fl_delete_browser_line(idsbr, x);
	genpwd_will_saveids(SAVE_IDS_PLEASE);
}

int main(int argc, char **argv)
{
	int c;
	char *s, *d;
	size_t x;
	FL_COORD yoffs = 0;

	install_signals();

	progname = genpwd_strdup(basename(*argv));
	mkpwa = genpwd_malloc(sizeof(struct mkpwd_args));

	fl_malloc = genpwd_malloc;
	fl_free = genpwd_free;
	fl_realloc = genpwd_realloc;
	fl_calloc = genpwd_calloc;

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
	while ((c = getopt(argc, argv, "L:xl:U:BCiI:jM:NRkw:nD:")) != -1) {
		switch (c) {
			case 'L':
				genpwd_read_defaults(optarg, NO);
				break;
			case 'l':
				default_password_length = strtol(optarg, &stoi, 10);
				if (!fkeyname
				&& (!str_empty(stoi) || default_password_length <= 0))
					xerror(NO, YES, "%s: invalid password length number", optarg);
				break;
			case 'B':
				default_password_format = MKPWD_FMT_B64;
				break;
			case 'C':
				default_password_format = MKPWD_FMT_CPWD;
				break;
			case 'U':
				default_password_format = MKPWD_FMT_UNIV;
				genpwd_free(default_password_charset);
				default_password_charset = genpwd_strdup(pwl_charset_string(optarg));
				break;
			case 'j':
				no_newline = YES;
				break;
			case 'M':
				c = genpwd_loadids_from_file(optarg, NULL);
				if (c == -1) xerror(NO, NO, "%s", optarg);
				else if (c == 0) xerror(NO, YES, "%s: cannot decipher", optarg);
				merged = YES;
				break;
			case 'N':
				if (genpwd_save_ids == NO) {
					if (genpwd_will_saveids(SAVE_IDS_QUERY) == SAVE_IDS_NEVER)
						genpwd_will_saveids(SAVE_IDS_OVERRIDE);
					else genpwd_will_saveids(SAVE_IDS_NEVER);
				}
				genpwd_will_saveids(SAVE_IDS_NEVER);
				break;
			case 'R':
				do_random_pw = YES;
				break;
			case 'i':
				genpwd_listids(shownumbers);
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
			case 'x':
				do_not_show = YES;
				break;
			case 'n':
				shownumbers = YES;
				break;
			case 'D':
				x = (genpwd_szalloc(delentries) / sizeof(int));
				delentries = genpwd_realloc(delentries, (x + 1) * sizeof(int));
				delentries[x] = ATOX(optarg);
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

	if (delentries) {
		size_t n;

		genpwd_loadids(NULL);
		for (x = 0; x < (genpwd_szalloc(delentries) / sizeof(int)); x++) {
			n = delentries[x];
			if (n >= 1 && n <= nids) {
				s = ids[n-1];
				genpwd_delid(s);
			}
		}
		genpwd_will_saveids(SAVE_IDS_PLEASE);
		genpwd_free(delentries);
		goto _wriexit;
	}

	if (merged == YES) {
		genpwd_loadids(NULL);
		genpwd_will_saveids(SAVE_IDS_PLEASE);
		goto _wriexit;
	}

	/* embedded genpwd copy */
	if (fkeyname) {
		getps = genpwd_malloc(sizeof(struct getpasswd_state));
		s_masterpw = genpwd_malloc(GENPWD_PWD_MAX);
		s_identifier = genpwd_malloc(GENPWD_PWD_MAX);

		mkpwd_adjust(mkpwa);

		mkpwa->pwd = s_masterpw;
		mkpwa->id = s_identifier;

		if (do_random_pw == YES) {
			genpwd_will_saveids(SAVE_IDS_NEVER);
			genpwd_getrandom(s_masterpw, genpwd_szalloc(s_masterpw));
			genpwd_getrandom(s_identifier, genpwd_szalloc(s_identifier));
			mkpwa->szpwd = genpwd_szalloc(s_masterpw);
			mkpwa->szid = genpwd_szalloc(s_identifier);
			goto _do_random;
		}

		getps->fd = getps->efd = -1;
		getps->passwd = s_masterpw;
		getps->pwlen = genpwd_szalloc(s_masterpw)-1;
		getps->echo = "Enter master: ";
		getps->charfilter = getps_filter;
		getps->maskchar = 'x';
		x = xgetpasswd(getps);
		if (x == NOSIZE) xerror(NO, NO, "getting passwd");
		if (x == ((size_t)-2)) genpwd_exit(1);

		if (mkpwd_hint(mkpwa) == MKPWD_NO) xerror(NO, YES, "error generating password hint");
		genpwd_esay("Password hint: %s", mkpwa->result);
		genpwd_free(mkpwa->result);

		getps->fd = getps->efd = -1;
		getps->passwd = s_identifier;
		getps->pwlen = genpwd_szalloc(s_identifier)-1;
		getps->echo = "Enter name: ";
		getps->charfilter = getps_plain_filter;
		getps->maskchar = 0;
		x = xgetpasswd(getps);
		if (x == NOSIZE) xerror(NO, NO, "getting name");
		if (x == ((size_t)-2)) genpwd_exit(1);

		genpwd_loadids(NULL);
		genpwd_addid(s_identifier);
		genpwd_will_saveids(SAVE_IDS_PLEASE);

_do_random:	if (!(!strcmp(fkeyname, "-")))
			kfd = creat(fkeyname, S_IRUSR | S_IWUSR);
		if (kfd == -1) xerror(NO, NO, "%s", fkeyname);
		if (kfd != 1) no_newline = YES;

		if (!genkeyf) {
			if (mkpwd(mkpwa) == MKPWD_NO) xerror(NO, YES, "error generating password");
			write(kfd, mkpwa->result, mkpwa->szresult);
			if (!no_newline) write(kfd, "\n", 1);
		}
		else {
			if (mkpwd_key(mkpwa) == MKPWD_NO) xerror(NO, YES, "error generating keyfile");
			write(kfd, mkpwa->result, mkpwa->szresult);
		}

		if (kfd != 1) close(kfd);
		genpwd_saveids();
		genpwd_exit(0);

		return 0;
	}

	fl_set_border_width(-1);
	fl_initialize(&argc, argv, CLASSAPPNAME, NULL, 0);

	if (do_random_pw == YES) {
		form = fl_bgn_form(FL_BORDER_BOX, 280, 145);
		yoffs = 295;
		goto _do_x_random;
	}
	else form = fl_bgn_form(FL_BORDER_BOX, 280, 440);

	masterpw = fl_add_input(FL_SECRET_INPUT, 5, 5, 205, 25, NULL);
	fl_set_object_return(masterpw, FL_RETURN_CHANGED);
	fl_set_object_dblclick(masterpw, 0);
	fl_set_input_maxchars(masterpw, 64);

	mhashbox = fl_add_box(FL_FLAT_BOX, 215, 5, 30, 25, " -- ");

	maspwbut = fl_add_button(FL_NORMAL_BUTTON, 250, 5, 25, 25, "X");
	fl_set_object_shortcut(maspwbut, "^T", 0);

	identifier = fl_add_input(FL_NORMAL_INPUT, 5, 35, 240, 25, NULL);
	fl_set_object_return(identifier, FL_RETURN_CHANGED);

	idbut = fl_add_button(FL_NORMAL_BUTTON, 250, 35, 25, 25, "X");
	fl_set_object_shortcut(idbut, "^U", 0);

	idsbr = fl_add_browser(FL_HOLD_BROWSER, 5, 65, 270, 200, NULL);
	fl_set_object_return(idsbr, FL_RETURN_SELECTION);
	fl_set_object_callback(idsbr, select_entry, 0);
	fl_set_object_dblbuffer(idsbr, 1);
	genpwd_loadids(fill_list);
	fl_set_browser_topline(idsbr, 1);

	search = fl_add_input(FL_NORMAL_INPUT, 5, 270, 210, 25, NULL);
	fl_set_object_return(search, FL_RETURN_CHANGED);
	fl_get_object_color(search, &srchcol1, &srchcol2);
	srchup = fl_add_button(FL_NORMAL_BUTTON, 220, 270, 25, 25, "@8>");
	fl_set_object_shortcut(srchup, "^P", 0);
	srchdown = fl_add_button(FL_NORMAL_BUTTON, 250, 270, 25, 25, "@2>");
	fl_set_object_shortcut(srchdown, "^N", 0);

_do_x_random:
	outbox = fl_add_box(FL_SHADOW_BOX, 5, 300 - yoffs, 270, 50, " -- ");
	fl_set_object_lstyle(outbox, FL_FIXED_STYLE|FL_BOLD_STYLE);

	hidepw = fl_add_button(FL_PUSH_BUTTON, 253, 301 - yoffs, 20, 20, "@9+");
	fl_set_object_shortcut(hidepw, "^X", 0);
	if (do_not_show) fl_set_button(hidepw, 1);

	pwlcnt = fl_add_counter(FL_SIMPLE_COUNTER, 5, 355 - yoffs, 80, 20, NULL);
	fl_set_counter_precision(pwlcnt, 0);
	fl_set_counter_value(pwlcnt, (double)default_password_length);
	fl_set_counter_bounds(pwlcnt, (double)0, (double)GENPWD_PWD_MAX);
	fl_set_counter_step(pwlcnt, (double)1, (double)0);
	fl_set_counter_repeat(pwlcnt, 150);
	fl_set_counter_min_repeat(pwlcnt, 15);
	fl_set_object_callback(pwlcnt, set_password_length, 0);

	pwloffs = fl_add_counter(FL_SIMPLE_COUNTER, 90, 355 - yoffs, 80, 20, NULL);
	fl_set_counter_precision(pwloffs, 0);
	fl_set_counter_value(pwloffs, (double)default_string_offset);
	fl_set_counter_bounds(pwloffs, (double)0, (double)GENPWD_PWD_MAX);
	fl_set_counter_step(pwloffs, (double)1, (double)0);
	fl_set_counter_repeat(pwloffs, 150);
	fl_set_counter_min_repeat(pwloffs, 15);
	fl_set_object_callback(pwloffs, set_password_offset, 0);

	pwlchrs = fl_add_input(FL_NORMAL_INPUT, 5, 380 - yoffs, 270, 25, NULL);
	fl_set_object_return(pwlchrs, FL_RETURN_CHANGED);
	fl_deactivate_object(pwlchrs);
	fl_set_input(pwlchrs, "");

	pwlfmt = fl_add_select(FL_DROPLIST_SELECT, 175, 355 - yoffs, 100, 20, NULL);
	fl_add_select_items(pwlfmt, "Base64");
	fl_add_select_items(pwlfmt, "Charset");
	fl_add_select_items(pwlfmt, "DigiChr");
	fl_set_select_policy(pwlfmt, FL_POPUP_NORMAL_SELECT);
	switch (default_password_format) {
		case MKPWD_FMT_B64: fl_set_select_item(pwlfmt, fl_get_select_item_by_value(pwlfmt, 0)); break;
		case MKPWD_FMT_UNIV:
			fl_set_select_item(pwlfmt, fl_get_select_item_by_value(pwlfmt, 1));
			fl_deactivate_object(pwloffs);
			fl_activate_object(pwlchrs);
			fl_set_input(pwlchrs, pwl_charset_name(default_password_charset));
			break;
		case MKPWD_FMT_CPWD: fl_set_select_item(pwlfmt, fl_get_select_item_by_value(pwlfmt, 2));
			fl_deactivate_object(pwloffs);
			break;
	}
	fl_set_object_callback(pwlfmt, set_password_format, 0);

	mkbutton = fl_add_button(FL_NORMAL_BUTTON, 5, 410 - yoffs, 60, 25, "Make");
	fl_set_object_shortcut(mkbutton, "^M", 0);
	copybutton = fl_add_button(FL_NORMAL_BUTTON, 75, 410 - yoffs, 60, 25, "Copy");
	fl_set_object_shortcut(copybutton, "^B", 0);
	clearbutton = fl_add_button(FL_NORMAL_BUTTON, 145, 410 - yoffs, 60, 25, "Clear");
	fl_set_object_shortcut(clearbutton, "^L", 0);
	quitbutton = fl_add_button(FL_NORMAL_BUTTON, 215, 410 - yoffs, 60, 25, "Quit");
	fl_set_object_shortcut(quitbutton, "^[", 0);

	fl_end_form();

	win = fl_prepare_form_window(form, FL_PLACE_CENTER, FL_FULLBORDER, CLASSAPPNAME);
	update_classname();
	fl_show_form_window(form);
	xwin_assign_icon_bmp(fl_get_display(), win, x11_icon_bmp);
	fl_set_cursor(win, XC_left_ptr);

	do {
		if (called == mkbutton)
			process_entries();
		else if (called == copybutton)
			copyclipboard();
		else if (called == clearbutton)
			clearentries();
		else if (called == maspwbut) {
			if (masterpw) {
				clearinput(masterpw);
				fl_set_input_maxchars(masterpw, 64);
				fl_activate_object(masterpw);
				fl_set_focus_object(form, masterpw);
			}
			if (mhashbox) {
				safe_zero_object_label(mhashbox);
				fl_set_object_label(mhashbox, " -- ");
			}
		}
		else if (called == idbut) {
			if (identifier) {
				clearinput(identifier);
				fl_set_focus_object(form, identifier);
			}
			if (idsbr) removeitem();
		}
		else if (called == search) {
			if (idsbr && search) searchitem();
		}
		else if (called == srchup) {
			if (idsbr && search && srchup) searchitemup();
		}
		else if (called == srchdown) {
			if (idsbr && search && srchdown) searchitemdown();
		}
		else if (called == hidepw)
			hidepwd();
		else if (called == quitbutton) break;
	} while ((called = fl_do_forms()));

	clearentries();
	fl_finish();
_wriexit:
	genpwd_saveids();
	genpwd_exit(0);

	return 0;
}
