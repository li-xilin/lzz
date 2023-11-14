/*
 * Copyright (c) 2023 Li Xilin <lixilin@gmx.com>
 *
 * Permission is hereby granted, free of charge, to one person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "lzz.h"
#include <ax/uchar.h>
#include <ax/log.h>
#include <ax/option.h>
#include <ax/path.h>
#include <stdio.h>
#include <stdlib.h>

void usage(void)
{
	fputs("Portable file packaging tool based on LZNT1 algorithm.\n\n", stderr);
	fputs("Usage:\n", stderr);
	fputs("  lzz -c <LZZ_FILE> FILE...\n", stderr);
	fputs("  lzz -x <LZZ_FILE> [TARGET_PATH]\n", stderr);
	fputs("  lzz -t <LZZ_FILE>\n", stderr);
	fputs("Options:\n", stderr);
	fputs("  -c, --pack     compress and pack FILE(s) into LZZ_FILE\n", stderr);
	fputs("  -x, --extract  decompress and extract LZZ_FILE into TARGET_PATH, default into current path\n", stderr);
	fputs("  -t, --test     test if LZZ_FILE is valid and print the name of all files\n", stderr);
	fputs("  -h, --help     display this usage\n\n", stderr);
	fputs("Project website: https://github.com/li-xilin/lzz\n", stderr);
	fputs("Li Xilin <lixilin@gmx.com>\n", stderr);
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

	if ((pack && (extract || test))
			|| (extract && (pack || test))
			|| (test && (pack || extract))) {
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

		return !!lzz_pack(files, lzz_file);
	}
	else if (extract) {
		ax_uchar extpath_buf[AX_PATH_MAX] = ax_u(".");
		if (argc != opt.optind )
			ax_ustr_from_ansi(extpath_buf, sizeof extpath_buf, opt.argv[opt.optind]);
		return !!lzz_unpack(lzz_file, extpath_buf, false);
	}
	else if (test) {
		if (lzz_unpack(lzz_file, NULL, true))
			puts("The test is completed successfully.");
		else
			puts("Failed to test, LZZ file is broken.");
		exit(0);
	}
	else {
		ax_perror("One of -c, -x or -t option is required");
		usage();
		exit(1);
	}
}
