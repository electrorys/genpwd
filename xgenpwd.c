#include <stdio.h>
#include <forms.h>
#include "genpwd.h"
#include "defs.h"

static char overwr[128];
static const char *poverwr = overwr;

static FL_FORM *form;
static FL_OBJECT *master, *name, *outbox;
static FL_OBJECT *mkbutton, *copybutton, *clearbutton, *quitbutton;
static int xmaster, xname;

static const unsigned char *_salt = salt;
static size_t _slen = sizeof(salt);

void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(2);
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

	d[0] = fl_get_input(master); d[1] = fl_get_input(name); d[2] = NULL;
	if (!d[1][0]) return;
	output = mkpwd(_salt, _slen, d);

	fl_set_object_label(outbox, output);

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
	FL_OBJECT *called = NULL;

	if (!selftest()) return 1; /* XXX */
	memset(overwr, 0, sizeof(overwr));
	memset(overwr, 'X', sizeof(overwr)-1);

	fl_initialize(&argc, argv, "xgenpwd", NULL, 0);

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
