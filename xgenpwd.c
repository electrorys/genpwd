#include "genpwd.h"
#include "genpwd_defs.h"
#include <forms.h>

#include "icon.xpm"

#define TITLE_SHOW_CHARS 16

/* embedded genpwd parts */
static char *s_masterpw, *s_identifier;
static int no_newline;
static char *fkeyname;
static int genkeyf;
static int kfd = 1;

static size_t x;

static FL_FORM *form;
static Window win;
static FL_OBJECT *masterpw, *identifier, *mhashbox, *outbox, *idsbr, *pwlcnt;
static FL_OBJECT *maspwbut, *idbut, *mkbutton, *copybutton, *clearbutton, *quitbutton;
static FL_OBJECT *search, *srchup, *srchdown, *reloadids;
static FL_OBJECT *called;

static FL_COLOR srchcol1, srchcol2;

static short format_option = MKPWD_FMT_B64;
static int do_not_show;
static int do_not_grab;
static char *shadowed;
static int c;
static size_t x;

char *progname;

static char *stoi;

size_t salt_length = sizeof(salt);

static struct mkpwd_args *mkpwa;
static struct getpasswd_state *getps;

static void usage(void)
{
	if (optopt == 'V') {
		genpwd_say("genpwd passwords keeper.");
		genpwd_say("Version %s, X11 XForms port.", _GENPWD_VERSION);
		genpwd_exit(0);
	}

	genpwd_say("usage: %s [-xGODX89Nik] [-n PASSES] [-o OFFSET] [-l PASSLEN]"
		"[-s filename] [-I idsfile] [-w outkey]", progname);
	genpwd_say("\n");
	genpwd_say("  -x: do not show password in output box. 'Copy' button will work.");
	genpwd_say("  -G: disable exclusive keyboard grabbing");
	genpwd_say("  -O: output only numeric octal password");
	genpwd_say("  -D: output only numeric password (useful for pin numeric codes)");
	genpwd_say("  -X: output hexadecimal password");
	genpwd_say("  -8: output base85 password");
	genpwd_say("  -9: output base95 password");
	genpwd_say("  -k: request generation of binary keyfile");
	genpwd_say("  -N: do not save ID data typed in Name field");
	genpwd_say("  -i: list identifiers from .genpwd.ids");
	genpwd_say("  -I file: use alternate ids file instead of .genpwd.ids");
	genpwd_say("  -n PASSES: set number of PASSES of skein1024 function");
	genpwd_say("  -o OFFSET: offset from beginning of 'big-passwd' string");
	genpwd_say("  -l PASSLEN: sets the cut-out region of 'big-passwd' string");
	genpwd_say("  -s filename: load alternative binary salt from filename");
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
	clearinput(identifier);
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

static void grab_keyboard(int do_grab)
{
	int status = 0;
	char errstr[128];

	if (do_grab) {
		status = XGrabKeyboard(fl_display, win, False,
			 GrabModeAsync, GrabModeAsync, CurrentTime);
	}
	else XUngrabKeyboard(fl_display, CurrentTime);
	if (status > 0) {
		XGetErrorText(fl_display, status, errstr, sizeof(errstr));
		xerror(0, 1, "Keyboard grab failed: %s [%d]", errstr, status);
	}
}

static void reload_ids(void)
{
	saveids(); /* save modified, if any, clean things up */
	fl_clear_browser(idsbr); /* clear browser */
	loadids(fill_list); /* reload list again */
	fl_set_browser_topline(idsbr, 1);
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
	char *title, *fmt;

	mkpwa->format = format_option;
	mkpwa->pwd = fl_get_input(masterpw);
	mkpwa->id = fl_get_input(identifier);
	if (!*mkpwa->id) return;
	mkpwa->salt = loaded_salt;
	mkpwa->szsalt = salt_length;
	mkpwd_adjust(mkpwa);

	if (mkpwd_hint(mkpwa) == MKPWD_NO && mkpwa->error) goto _inval;
	fl_set_object_label(mhashbox, mkpwa->result);
	genpwd_free(mkpwa->result);

	if (mkpwd(mkpwa) == MKPWD_NO && mkpwa->error) goto _inval;
	if (mkpwa->szresult != default_password_length) {
_inval:		set_output_label_size(strlen(mkpwa->error));
		fl_set_object_label(outbox, mkpwa->error);
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

	fl_deactivate_object(masterpw);
	genpwd_free(mkpwa->result);

	if (!is_dupid(mkpwa->id)) {
		addid(mkpwa->id);
		will_saveids(SAVE_IDS_PLEASE);
		fl_addto_browser(idsbr, mkpwa->id);
	}

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
	clearinput(masterpw);
	fl_set_input_maxchars(masterpw, 64);
	fl_activate_object(masterpw);
	clearinput(identifier);

	safe_zero_object_label(outbox);
	fl_set_object_label(outbox, " -- ");
	safe_zero_object_label(mhashbox);
	fl_set_object_label(mhashbox, " -- ");

	clearinput(search);
	fl_set_object_color(search, srchcol1, srchcol2);

	fl_wintitle(win, progname);
	fl_set_focus_object(form, masterpw);
	fl_deselect_browser(idsbr);
}

static void removeitem(void)
{
	int x = fl_get_browser(idsbr);
	const char *line = fl_get_browser_line(idsbr, x);

	if (!delid(line)) return;
	fl_delete_browser_line(idsbr, x);
	will_saveids(SAVE_IDS_PLEASE);
}

int main(int argc, char **argv)
{
	install_signals();

	progname = genpwd_strdup(basename(*argv));
	mkpwa = genpwd_malloc(sizeof(struct mkpwd_args));

	fl_malloc = genpwd_malloc;
	fl_free = genpwd_free;
	fl_realloc = genpwd_realloc;
	fl_calloc = genpwd_calloc;

	if (genpwd_save_ids == 0) will_saveids(SAVE_IDS_NEVER);

	opterr = 0;
	while ((c = getopt(argc, argv, "xGn:o:l:ODX89iI:s:Nkw:")) != -1) {
		switch (c) {
			case 'n':
				default_passes_number = strtol(optarg, &stoi, 10);
				if (*stoi || default_passes_number < 0)
					xerror(0, 1, "%s: invalid passes number", optarg);
				break;
			case 'o':
				default_string_offset = strtol(optarg, &stoi, 10);
				if (*stoi || default_string_offset < 0)
					xerror(0, 1, "%s: invalid offset number", optarg);
				break;
			case 'l':
				default_password_length = strtol(optarg, &stoi, 10);
				if (!fkeyname
				&& (*stoi || default_password_length <= 0))
					xerror(0, 1, "%s: invalid password length number", optarg);
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
			case 's':
				loaded_salt = read_alloc_file(optarg, &salt_length);
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
				break;
			case 'k':
				if (!fkeyname) xerror(0, 1, "specify outkey with -w.");
				genkeyf = 1;
				break;
			case 'w':
				if (fkeyname) genpwd_free(fkeyname);
				fkeyname = genpwd_strdup(optarg);
				break;
			case 'x':
				do_not_show = 1;
				break;
			case 'G':
				do_not_grab = 1;
				break;
			default:
				usage();
				break;
		}
	}

	fl_set_border_width(-1);
	fl_initialize(&argc, argv, "xgenpwd", NULL, 0);

	for (x = 1; x < argc; x++) {
		memset(argv[x], 0, strlen(argv[x]));
		argv[x] = NULL;
	}
	argc = 1;

	/* embedded genpwd copy */
	if (fkeyname) {
		getps = genpwd_malloc(sizeof(struct getpasswd_state));
		s_masterpw = genpwd_malloc(GENPWD_MAXPWD);
		s_identifier = genpwd_malloc(GENPWD_MAXPWD);

		mkpwa->pwd = s_masterpw;
		mkpwa->salt = loaded_salt;
		mkpwa->szsalt = salt_length;

		getps->fd = getps->efd = -1;
		getps->passwd = s_masterpw;
		getps->pwlen = genpwd_szalloc(s_masterpw)-1;
		getps->echo = "Enter master: ";
		getps->charfilter = getps_filter;
		getps->maskchar = 'x';
		x = xgetpasswd(getps);
		if (x == NOSIZE) xerror(0, 0, "getting passwd");
		if (x == ((size_t)-2)) genpwd_exit(1);

		if (mkpwd_hint(mkpwa) == MKPWD_NO && mkpwa->error) xerror(0, 1, "%s", mkpwa->error);
		genpwd_esay("Password hint: %s", mkpwa->result);
		genpwd_free(mkpwa->result);

		mkpwa->id = s_identifier;

		getps->fd = getps->efd = -1;
		getps->passwd = s_identifier;
		getps->pwlen = genpwd_szalloc(s_identifier)-1;
		getps->echo = "Enter name: ";
		getps->charfilter = getps_plain_filter;
		getps->maskchar = 0;
		x = xgetpasswd(getps);
		if (x == NOSIZE) xerror(0, 0, "getting name");
		if (x == ((size_t)-2)) genpwd_exit(1);

		loadids(NULL);
		if (!is_dupid(s_identifier)) {
			addid(s_identifier);
			will_saveids(SAVE_IDS_PLEASE);
		}

		mkpwd_adjust(mkpwa);

		if (!(!strcmp(fkeyname, "-")))
			kfd = creat(fkeyname, S_IRUSR | S_IWUSR);
		if (kfd == -1) xerror(0, 0, "%s", fkeyname);
		if (kfd != 1) no_newline = 1;

		mkpwa->format = format_option;
		if (!genkeyf) {
			if (mkpwd(mkpwa) == MKPWD_NO && mkpwa->error)
				xerror(0, 1, "%s", mkpwa->error);
			write(kfd, mkpwa->result, mkpwa->szresult);
			if (!no_newline) write(kfd, "\n", 1);
		}
		else {
			if (mkpwd_key(mkpwa) == MKPWD_NO && mkpwa->error) xerror(0, 1, "%s", mkpwa->error);
			write(kfd, mkpwa->result, mkpwa->szresult);
		}

		if (kfd != 1) close(kfd);
		saveids();
		genpwd_exit(0);

		return 0;
	}

	form = fl_bgn_form(FL_BORDER_BOX, 280, 410);

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
	loadids(fill_list);
	fl_set_browser_topline(idsbr, 1);

	search = fl_add_input(FL_NORMAL_INPUT, 5, 270, 180, 25, NULL);
	fl_set_object_return(search, FL_RETURN_CHANGED);
	fl_get_object_color(search, &srchcol1, &srchcol2);
	srchup = fl_add_button(FL_NORMAL_BUTTON, 190, 270, 25, 25, "@8>");
	fl_set_object_shortcut(srchup, "^P", 0);
	srchdown = fl_add_button(FL_NORMAL_BUTTON, 220, 270, 25, 25, "@2>");
	fl_set_object_shortcut(srchdown, "^N", 0);
	reloadids = fl_add_button(FL_NORMAL_BUTTON, 250, 270, 25, 25, "R");
	fl_set_object_shortcutkey(reloadids, XK_F5);

	outbox = fl_add_box(FL_SHADOW_BOX, 5, 300, 270, 50, " -- ");
	fl_set_object_lstyle(outbox, FL_FIXED_STYLE|FL_BOLD_STYLE);

	pwlcnt = fl_add_counter(FL_SIMPLE_COUNTER, 5, 355, 270, 20, NULL);
	fl_set_counter_precision(pwlcnt, 0);
	fl_set_counter_value(pwlcnt, (double)default_password_length);
	fl_set_counter_bounds(pwlcnt, (double)0, (double)GENPWD_MAXPWD);
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
	if (!do_not_grab) grab_keyboard(1);

	do {
		if (called == mkbutton)
			process_entries();
		else if (called == copybutton)
			copyclipboard();
		else if (called == clearbutton)
			clearentries();
		else if (called == maspwbut) {
			clearinput(masterpw);
			fl_set_input_maxchars(masterpw, 64);
			fl_activate_object(masterpw);
			fl_set_focus_object(form, masterpw);
			safe_zero_object_label(mhashbox);
			fl_set_object_label(mhashbox, " -- ");
		}
		else if (called == idbut) {
			clearinput(identifier);
			fl_set_focus_object(form, identifier);
			removeitem();
		}
		else if (called == search)
			searchitem();
		else if (called == srchup)
			searchitemup();
		else if (called == srchdown)
			searchitemdown();
		else if (called == reloadids)
			reload_ids();
		else if (called == quitbutton) break;
	} while ((called = fl_do_forms()));

	clearentries();
	saveids();
	if (!do_not_grab) grab_keyboard(0);
	fl_finish();
	genpwd_exit(0);

	return 0;
}
