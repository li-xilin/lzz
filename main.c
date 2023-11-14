#include "lzz.h"
#include <ax/uchar.h>
#include <ax/log.h>
#include <ax/option.h>
#include <ax/path.h>
#include <stdio.h>
#include <stdlib.h>

void usage(void)
{
	fputs("lzz -c <LZZ_FILE> [FILE...]\n", stderr);
	fputs("lzz -x <LZZ_FILE> [TARGET_PATH]\n", stderr);
	fputs("lzz -t <LZZ_FILE>\n", stderr);
}

int main(int argc, char *argv[])
{
	int index, ch;
	ax_option opt;

	ax_log_set_mode(AX_LM_NOLOC|AX_LM_NOTIME);
	ax_option_init(&opt, argv);
	const ax_option_long optlist[] = {
		{"test", 't', AX_OPT_REQUIRED},
		{"pack", 'c', AX_OPT_REQUIRED},
		{"extract", 'x', AX_OPT_REQUIRED},
		{"target", 'd', AX_OPT_REQUIRED},
		{"help", 'h', AX_OPT_NONE},
		{ NULL },
	};

	bool test = false;
	bool extract = false;
	bool pack = false;

	ax_uchar lzz_file[AX_PATH_MAX] = ax_u(".");

	while ((ch = ax_option_parse_long(&opt, optlist, &index)) != -1) {
		switch (ch) {
			case 't':
				test = true;
				goto parse_optarg;
			case 'x':
				extract = true;
				goto parse_optarg;
			case 'c':
				pack = true;
parse_optarg:
				ax_ustr_from_ansi(lzz_file, sizeof lzz_file, opt.optarg);
				break;
			case 'h':
				usage();
				exit(0);
		}
	}

	if (pack && (extract || test) || extract && (pack || test) || test && (pack || extract)) {
		ax_perror("Invalid command line arguments");
		usage();
		exit(1);
	}

	if (pack) {
		if (argc - opt.optind == 0) {
			ax_perror("Files to pack must be specified");
			usage();
			exit(1);
		}

		ax_uchar buf[AX_PATH_MAX];
		const ax_uchar *files[1024];

		int i = 0;
		for (i = 0; opt.argv[opt.optind + i]; i++) {
			ax_ustr_from_ansi(buf, sizeof buf, opt.argv[opt.optind + i]);
			files[i] = ax_ustrdup(buf);
		}
		files[i] = NULL;

		return lzz_pack(files, lzz_file);
	}
	else if (extract) {
		ax_uchar extpath_buf[AX_PATH_MAX] = ax_u(".");
		if (argc != opt.optind )
			ax_ustr_from_ansi(extpath_buf, sizeof extpath_buf, opt.argv[opt.optind]);
		return lzz_unpack(lzz_file, extpath_buf, false);
	}
	else if (test) {
		if (lzz_unpack(lzz_file, NULL, true))
			puts("LZZ file is OK.");
		else
			puts("LZZ file is broken.");
		exit(0);
	}
	else {
		ax_perror("An operation -c, -e or -t is expected");
		usage();
		exit(1);
	}
}
