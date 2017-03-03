#include <stdio.h>
#include <forms.h>

void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(2);
}

int main(int argc, char **argv)
{
	FL_FORM *form;
	FL_OBJECT *but, *password1, *password2, *info;
	char str[256];

	fl_initialize(&argc, argv, "FormDemo", NULL, 0);

	form = fl_bgn_form(FL_UP_BOX, 400, 300);

	password1 = fl_add_input(FL_SECRET_INPUT, 140, 40, 160, 40, "Password 1:");
	fl_set_object_return(password1, FL_RETURN_CHANGED);

	password2 = fl_add_input(FL_SECRET_INPUT, 140, 100, 160, 40, "Password 2:");
	fl_set_object_return(password2, FL_RETURN_CHANGED);

	info = fl_add_box(FL_SHADOW_BOX, 20, 160, 360, 60, "");
	but = fl_add_button(FL_NORMAL_BUTTON, 280, 240, 100, 40, "Quit");

	fl_end_form();

	fl_show_form(form, FL_PLACE_MOUSE, FL_FULLBORDER, "Secret Input Demo");

	while (fl_do_forms() != but) {
		snprintf(str, sizeof(str), "Password 1 is: %s\n, Password 2 is: %s", fl_get_input(password1), fl_get_input(password2));
		fl_set_object_label(info, str);
	}

	fl_finish();
	return 0;
}
