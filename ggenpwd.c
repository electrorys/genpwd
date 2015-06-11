#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include "mkpwd.h"
#include "defs.h"

#include "icon.h"

#define _strpp(x) #x
#define _istr(x) _strpp(x)
#define SMKPWD_OUTPUT_MAX _istr(MKPWD_OUTPUT_MAX)
#define SMKPWD_ROUNDS_MAX _istr(MKPWD_ROUNDS_MAX)

#define _selftestfail	"Self test failed."
#define _passmismatch	"Passwords don't match"

#define TITLE_SHOW_CHARS 16

static int repeat;
static int hidepass;
static int numopt;
static char data[1024];

static char *progname;

#define windowwidth 250

static GtkWidget *window;
static GtkWidget *fixed;
static GdkPixbufLoader *loader;
static GdkPixbuf *pixbuf;

static GtkWidget *pwlabel;

static GtkWidget *entry[4];

static GtkWidget *hseparator;

static GtkWidget *cpbutton;
static GtkWidget *clbutton;
static GtkWidget *mclbutton;
static GtkWidget *mrclbutton;
static GtkWidget *nclbutton;
static GtkWidget *mkbutton;

static GtkAdjustment *adj[2];
static GtkWidget *spin[2];

static GtkAccelGroup *agrp;

static const unsigned char *_salt = salt;
static size_t _slen = sizeof(salt);

static char *stoi;

static void usage(void)
{
	printf("usage: %s [-rxODX8946mU] [-n PASSES] [-o OFFSET]"
	       	" [-l PASSLEN] [-N NAME] [-s filename/-]\n\n", progname);
	printf("  -r: repeat mode\n");
	printf("  -x: hide password in \"Password:\" field by default\n");
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
	printf("  -N NAME: specify name\n");
	printf("  -n PASSES: set number of PASSES of skein1024 function\n");
	printf("  -o OFFSET: offset from beginning of 'big-passwd' string\n");
	printf("  -l PASSLEN: with offset, sets the region of passwd substring from"
	       	" 'big-passwd' string\n");
	printf("  -s filename: load alternative binary salt from filename"
			" or stdin (if '-')\n\n");
	exit(1);
}

static void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(2);
}

#include "selftest.c"
#include "loadsalt.c"

/* TODO: may I somehow access gtk2 internals here and clear their buffers too? */
static void clearfield(GtkWidget *entry)
{
	gtk_entry_set_text(GTK_ENTRY(entry), "");
}

static void xonexit(void)
{
	memset(data, 0, sizeof(data));
	clearfield(entry[0]);
	clearfield(entry[1]);
	clearfield(entry[2]);
	if (repeat)
		clearfield(entry[3]);

	gtk_main_quit();
}

static int escapequit(GtkWidget *w, GdkEventKey *evt, void *d)
{
	if (evt->keyval == GDK_KEY_Escape) {
		xonexit();
		return 1;
	}
	return 0;
}

static void process_entries(void)
{
	char newtitle[64];
	char *output = NULL, *p;

	const char *buffer[3] = {NULL};
	const char *d[4] = {NULL};

	buffer[0] = gtk_entry_get_text(GTK_ENTRY(entry[0]));
	buffer[1] = gtk_entry_get_text(GTK_ENTRY(entry[1]));
	if (repeat)
		buffer[2] = gtk_entry_get_text(GTK_ENTRY(entry[3]));

	if ((buffer[0] && strlen(buffer[0]))
	|| (buffer[1] && strlen(buffer[1]))
	|| (buffer[2] && strlen(buffer[2]))) {
		gtk_widget_set_sensitive(clbutton, TRUE);

		if (repeat && (strncmp(buffer[0], buffer[2], 256) != 0)) {
			if (hidepass) gtk_entry_set_visibility(GTK_ENTRY(entry[2]), TRUE);
			gtk_entry_set_text(GTK_ENTRY(entry[2]), _passmismatch);
			gtk_widget_set_sensitive(cpbutton, FALSE);
			return;
		}
		else
			if (hidepass) gtk_entry_set_visibility(GTK_ENTRY(entry[2]), FALSE);

		rounds = numrounds;
		offset = offs;
		passlen = plen;
		dechex = numopt;
		d[0] = buffer[0]; d[1] = buffer[1];
		if (numopt >= 0x1001 && numopt <= 0x1006) d[2] = data;
		gtk_widget_set_sensitive(mkbutton, FALSE);
		gtk_widget_queue_draw(mkbutton);
		while (gtk_events_pending()) gtk_main_iteration();
		output = mkpwd(_salt, _slen, d);
		gtk_widget_set_sensitive(mkbutton, TRUE);
		if (!output[0] && output[1]) {
			gtk_entry_set_text(GTK_ENTRY(entry[2]), output+1);
			gtk_widget_set_sensitive(cpbutton, FALSE);
			return;
		}

		gtk_entry_set_text(GTK_ENTRY(entry[2]), output);
		gtk_window_set_focus(GTK_WINDOW(window), entry[2]);
		gtk_widget_set_sensitive(cpbutton, TRUE);
		memset(output, 0, MKPWD_OUTPUT_MAX); output = NULL;
	}
	else {
		gtk_window_set_focus(GTK_WINDOW(window), entry[0]);
		gtk_widget_set_sensitive(clbutton, FALSE);
		return;
	}

	memset(newtitle, 0, sizeof(newtitle));
	memcpy(newtitle+(sizeof(newtitle)-(sizeof(newtitle)/2)), buffer[1], TITLE_SHOW_CHARS);
	if (strlen(buffer[1]) >= TITLE_SHOW_CHARS) p = "%s: %s...";
	else p = "%s: %s";
	snprintf(newtitle, sizeof(newtitle), p, progname,
		newtitle+(sizeof(newtitle)-(sizeof(newtitle)/2)));
	gtk_window_set_title(GTK_WINDOW(window), newtitle);
}

static void resetfield(GtkWidget *X)
{
	int x = 0;

	if (X == mclbutton) x = 0;
	else if (X == mrclbutton && repeat) x = 3;
	else if (X == nclbutton) x = 1;

	clearfield(entry[x]);
	gtk_window_set_focus(GTK_WINDOW(window), entry[x]);
}

static void resetfields(void)
{
	clearfield(entry[0]);
	clearfield(entry[1]);
	clearfield(entry[2]);
	if (repeat)
		clearfield(entry[3]);
	else gtk_widget_set_sensitive(cpbutton, FALSE);
	gtk_widget_set_sensitive(clbutton, FALSE);

	gtk_window_set_focus(GTK_WINDOW(window), entry[0]);
	gtk_window_set_title(GTK_WINDOW(window), progname);
}

static void changeconfig(void)
{
	offs = gtk_spin_button_get_value_as_int((GtkSpinButton *)spin[0]);
	plen = gtk_spin_button_get_value_as_int((GtkSpinButton *)spin[1]);
}

static void clipboardcopy(void *null, int box)
{
	GtkClipboard *clipboard = NULL;
	GtkClipboard *clipprim = NULL;
	const char *txt = NULL;

	txt = gtk_entry_get_text(GTK_ENTRY(entry[2]));

	clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	clipprim = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
	
	gtk_clipboard_set_text(clipboard, txt, -1);
	gtk_clipboard_set_text(clipprim, txt, -1);

	gtk_window_set_focus(GTK_WINDOW(window), entry[2]);
}


int main(int argc, char **argv)
{
	progname = basename(argv[0]);

	int c = 0;

	int sz = 0;
	int x, y;

	int selftestflag = 1;
	if (!selftest()) selftestflag = 0;
	char name[256] = {0};

	if (!selftestflag) fprintf(stderr, "%s Program probably broken.\n", _selftestfail);

	opterr = 0;
	while ((c = getopt(argc, argv, "n:rxo:l:ODX89s:N:4::6::m::U")) != -1) {
		switch (c) {
			case 'r':
				repeat = 1;
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
				hidepass = 1;
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
			case 'N':
				strncpy(name, optarg, sizeof(name)-1);
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
			default:
				usage();
				break;
		}
	}

	gtk_init(&argc, &argv);

	int i; for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW (window), FALSE);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

	gtk_window_set_title(GTK_WINDOW(window), progname);

	gtk_container_set_border_width(GTK_CONTAINER(window), 5);

	loader = gdk_pixbuf_loader_new_with_type("png", NULL);
	gdk_pixbuf_loader_write(loader, icon_png, icon_png_len, NULL);
	gdk_pixbuf_loader_close(loader, NULL);
	pixbuf = gdk_pixbuf_loader_get_pixbuf(loader);
	gtk_window_set_icon(GTK_WINDOW(window), pixbuf);

	agrp = gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(window), agrp);
	
	fixed = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(window), fixed);
	
	pwlabel = gtk_label_new("Password: ");

	entry[0] = gtk_entry_new();
	entry[1] = gtk_entry_new();
	if (name[0]) {
		gtk_entry_set_text(GTK_ENTRY(entry[1]), name);
		memset(name, 0, sizeof(name));
	}
	entry[2] = gtk_entry_new();
	if (repeat)
		entry[3] = gtk_entry_new();

	gtk_widget_modify_font(entry[2], pango_font_description_from_string("monospace"));

	hseparator = gtk_hseparator_new();

	cpbutton = gtk_button_new_with_label("Copy");
	clbutton = gtk_button_new_with_label("Clear");
	mclbutton = gtk_button_new_with_label("Master:");
	if (repeat) mrclbutton = gtk_button_new_with_label("Repeat:");
	nclbutton = gtk_button_new_with_label("Name:");
	mkbutton = gtk_button_new_with_label("Make");

	adj[0] = (GtkAdjustment *)gtk_adjustment_new(offs, 0.0,
		(double)MKPWD_OUTPUT_MAX, 1.0, 0.0, 0.0);
	adj[1] = (GtkAdjustment *)gtk_adjustment_new(plen, 1.0,
		(double)MKPWD_OUTPUT_MAX, 1.0, 0.0, 0.0);
	spin[0] = gtk_spin_button_new(adj[0], 1.0, 0);
	spin[1] = gtk_spin_button_new(adj[1], 1.0, 0);

	if (numopt > 0xfe) {
		gtk_widget_set_sensitive(spin[0], FALSE);
		gtk_widget_set_sensitive(spin[1], FALSE);
	}

	gtk_entry_set_visibility(GTK_ENTRY(entry[0]), FALSE);
	if (hidepass)
		gtk_entry_set_visibility(GTK_ENTRY(entry[2]), FALSE);
	if (repeat)
		gtk_entry_set_visibility(GTK_ENTRY(entry[3]), FALSE);
	gtk_entry_set_editable(GTK_ENTRY(entry[2]), FALSE);
	gtk_widget_set_sensitive(cpbutton, FALSE);
	gtk_widget_set_sensitive(clbutton, FALSE);

	gtk_widget_get_size_request(entry[0], 0, &sz);
	gtk_widget_set_size_request(entry[0], windowwidth, sz);
	gtk_widget_set_size_request(entry[1], windowwidth, sz);
	gtk_widget_set_size_request(entry[2], windowwidth, sz);
	if (repeat)
		gtk_widget_set_size_request(entry[3], windowwidth, sz);

	x = 0; y = 5;

	gtk_fixed_put(GTK_FIXED(fixed), mclbutton, x, y); y += 30;
/*
 * y+1 overrides gtk stupidity about predefined tab order,
 * but this is still limited!
 */
	if (repeat) {
		gtk_fixed_put(GTK_FIXED(fixed), mrclbutton, x, y+1); y += 30;
	}
	gtk_fixed_put(GTK_FIXED(fixed), nclbutton, x, y+1); y += 35;
	gtk_fixed_put(GTK_FIXED(fixed), pwlabel, x, y); y += 30;

	x = 70; y = 5;

	gtk_fixed_put(GTK_FIXED(fixed), entry[0], x, y); y += 30;
	if (repeat) {
		gtk_fixed_put(GTK_FIXED(fixed), entry[3], x, y); y += 30;
	}
	gtk_fixed_put(GTK_FIXED(fixed), entry[1], x, y); y += 30;
	gtk_fixed_put(GTK_FIXED(fixed), entry[2], x, y); y += 30;

	x = 0;

	gtk_fixed_put(GTK_FIXED(fixed), hseparator, x, y); y += 10;

	gtk_fixed_put(GTK_FIXED(fixed), mkbutton, x, y); x += 70;
	gtk_fixed_put(GTK_FIXED(fixed), cpbutton, x, y); x += 70;
	gtk_fixed_put(GTK_FIXED(fixed), clbutton, x, y); x += 70;

	gtk_fixed_put(GTK_FIXED(fixed), spin[0], x, y); x += 55;
	gtk_fixed_put(GTK_FIXED(fixed), spin[1], x, y); x += 55;

	x = 0; y = 0;

	gtk_widget_show(fixed);
	
	gtk_widget_show(pwlabel);
	gtk_widget_show(mclbutton);
	if (repeat) gtk_widget_show(mrclbutton);
	gtk_widget_show(nclbutton);
	gtk_widget_show(mkbutton);
	
	gtk_widget_show(entry[0]);
	gtk_widget_show(entry[1]);
	gtk_widget_show(entry[2]);
	if (repeat)
		gtk_widget_show(entry[3]);

	gtk_widget_show(hseparator);

	gtk_widget_show(cpbutton);
	gtk_widget_show(clbutton);

	gtk_widget_show(spin[0]);
	gtk_widget_show(spin[1]);

	gtk_widget_show(window);

	gtk_window_set_focus(GTK_WINDOW(window), entry[0]);

	sz = 0;

	gtk_window_get_size((GtkWindow* )window, &sz, 0);
	gtk_widget_set_size_request(hseparator, sz - 10, 5);

	gtk_widget_set_size_request(mclbutton, 65, 23);
	if (repeat) gtk_widget_set_size_request(mrclbutton, 65, 23);
	gtk_widget_set_size_request(nclbutton, 65, 23);
	gtk_widget_set_size_request(cpbutton, 65, 23);
	gtk_widget_set_size_request(clbutton, 65, 23);
	gtk_widget_set_size_request(mkbutton, 65, 23);

	sz = 0;
	
	g_signal_connect(window, "destroy",
		G_CALLBACK(xonexit), NULL);

	gtk_widget_add_accelerator(mclbutton, "activate", agrp,
		GDK_t, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	if (repeat) gtk_widget_add_accelerator(mrclbutton, "activate", agrp,
		GDK_y, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	gtk_widget_add_accelerator(nclbutton, "activate", agrp,
		GDK_u, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	gtk_widget_add_accelerator(mkbutton, "activate", agrp,
		GDK_m, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	gtk_widget_add_accelerator(cpbutton, "activate", agrp,
		GDK_b, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	gtk_widget_add_accelerator(clbutton, "activate", agrp,
		GDK_l, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	g_signal_connect(window, "key_press_event", G_CALLBACK(escapequit), NULL);

	g_signal_connect(G_OBJECT(mclbutton), "clicked",
		G_CALLBACK(resetfield), mclbutton);
	if (repeat) g_signal_connect(G_OBJECT(mrclbutton), "clicked",
			G_CALLBACK(resetfield), mrclbutton);
	g_signal_connect(G_OBJECT(nclbutton), "clicked",
		G_CALLBACK(resetfield), nclbutton);

	g_signal_connect(G_OBJECT(mkbutton), "clicked",
		G_CALLBACK(process_entries), NULL);

	g_signal_connect(G_OBJECT(cpbutton), "clicked", 
		G_CALLBACK(clipboardcopy), NULL);
	g_signal_connect(G_OBJECT(clbutton), "clicked", 
		G_CALLBACK(resetfields), NULL);

	g_signal_connect(G_OBJECT(adj[0]), "value_changed",
		G_CALLBACK(changeconfig), NULL);
	g_signal_connect(G_OBJECT(adj[1]), "value_changed",
		G_CALLBACK(changeconfig), NULL);

	if (!selftestflag) {
		gtk_entry_set_text(GTK_ENTRY(entry[2]), _selftestfail);

		gtk_widget_set_sensitive(pwlabel, FALSE);
		gtk_widget_set_sensitive(entry[0], FALSE);
		gtk_widget_set_sensitive(entry[1], FALSE);
		gtk_widget_set_sensitive(entry[2], FALSE);
		if (repeat) {
			gtk_widget_set_sensitive(mrclbutton, FALSE);
			gtk_widget_set_sensitive(entry[3], FALSE);
		}
		gtk_widget_set_sensitive(mclbutton, FALSE);
		gtk_widget_set_sensitive(nclbutton, FALSE);
		gtk_widget_set_sensitive(clbutton, FALSE);
		gtk_widget_set_sensitive(cpbutton, FALSE);
		gtk_widget_set_sensitive(mkbutton, FALSE);
		gtk_widget_set_sensitive(spin[0], FALSE);
		gtk_widget_set_sensitive(spin[1], FALSE);
		gtk_entry_set_visibility(GTK_ENTRY(entry[2]), TRUE);
	}

	gtk_main();
	
	return (selftestflag == 0);
}
