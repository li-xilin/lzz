#include "lznt1.h"
#include <ax/io.h>
#include <ax/dir.h>
#include <ax/sys.h>
#include <ax/stat.h>
#include <ax/uchar.h>
#include <ax/path.h>
#include <ax/log.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#define TOKEN_FILE 0
#define TOKEN_DIR_BEGIN 1
#define TOKEN_DIR_END 2

#define COMPRESSED_BUF_SIZE 0x1000
#define UNCOMPRESSED_BUF_SIZE 0x1000 - 2

static int write_file_entry(FILE *lzz_fp, const ax_uchar *path, bool is_dir)
{
	int retval = -1;
	uint32_t ftime = 0;
	char utf8_name[AX_FILENAME_MAX];
	uint8_t token = is_dir
		? TOKEN_DIR_BEGIN
		: TOKEN_FILE;

	ax_stat stat;
	if (ax_stat_get(path, &stat)) {
		ax_pwarn("Failed to get time of file `%s': %s", path, strerror(errno));
		ftime = time(NULL);
	}
	else {
		ftime = stat.st_mtim;
	}

	if (ax_ustr_utf8(ax_path_basename(path), utf8_name, sizeof utf8_name) == -1)
		goto out;

	uint8_t name_len = strlen(utf8_name);

	fwrite(&token, sizeof token, 1, lzz_fp);
	fwrite(&ftime, sizeof ftime, 1, lzz_fp);
	fwrite(&name_len, sizeof name_len, 1, lzz_fp);
	fwrite(utf8_name, name_len, 1, lzz_fp);

	if (ferror(lzz_fp)) {
		ax_perror("Failed to write file: %s", strerror(errno));
		goto out;
	}
	retval = 0;
out:
	return retval;
}

static int pack_file(FILE *lzz_fp, ax_uchar *path, size_t path_len)
{
	int retval = -1;
	ax_printf(ax_u("%s\n"), path);
	FILE *src_fp = ax_fopen(path, "r");
	if (!src_fp) {
		ax_pwarn("Failed to open file `%s': %s", path, strerror(errno));
		retval = 0;
		goto out;
	}

	if (write_file_entry(lzz_fp, path, false))
		goto out;

	uint8_t buf[UNCOMPRESSED_BUF_SIZE];
	size_t nbytes_read;
	uint16_t block_size;
	while ((nbytes_read = fread(buf, 1, sizeof buf, src_fp))) {
		uint8_t comp_buf[COMPRESSED_BUF_SIZE];
		size_t comp_size = sizeof comp_buf;
		if (lznt1_compress(buf, nbytes_read, comp_buf, &comp_size)) {
			ax_perror("Compression failed: %s", strerror(errno));
			goto out;
		}

		block_size = comp_size;
		fwrite(&block_size, sizeof block_size, 1, lzz_fp);
		fwrite(comp_buf, block_size, 1, lzz_fp);
	}
	block_size = 0;
	fwrite(&block_size, 1, sizeof block_size, lzz_fp);

	if (ferror(lzz_fp)) {
		ax_perror("Failed to write file: %s", strerror(errno));
		goto out;
	}

	retval = 0;
out:
	if (src_fp)
		fclose(src_fp);
	return retval;
}

static int pack_dir(FILE *lzz_fp, ax_uchar *path, size_t path_len)
{
	int retval = -1;
	ax_dir *dir = NULL;
	ax_dirent *ent1;

	if (!(dir = ax_dir_open(path)))
		goto out;

	if (write_file_entry(lzz_fp, path, true))
		goto out;

	while ((ent1 = ax_dir_read(dir))) {
		if (ax_ustrcmp(ent1->d_name, ax_u(".")) == 0)
			continue;

		if (ax_ustrcmp(ent1->d_name, ax_u("..")) == 0)
			continue;

		ax_ustrcpy(path + path_len, ax_u(AX_PATH_SEP));
		ax_ustrcpy(path + path_len + 1, ent1->d_name);

		char utf8_name[AX_FILENAME_MAX];
		if (ax_ustr_utf8(ent1->d_name, utf8_name, sizeof utf8_name) == -1)
			goto out;

		uint32_t name_len = strlen(utf8_name);
		if (ent1->d_type == AX_DT_DIR) {
			if (pack_dir(lzz_fp, path, path_len + 1 + name_len))
				goto out;
		}
		else if (ent1->d_type == AX_DT_REG) {
			if (pack_file(lzz_fp, path, path_len + 1 + name_len))
				goto out;
		}

	};

	uint8_t token = TOKEN_DIR_END;
	if (!fwrite(&token, sizeof token, 1, lzz_fp)) {
		ax_perror("Failed to write file: %s", strerror(errno));
		goto out;
	}

	retval = 0;
out:
	ax_dir_close(dir);
	return retval;
}


int lzz_pack(const ax_uchar *const files[], const ax_uchar *lzz_filepath)
{
	int retval = -1;
	FILE *lzz_fp = NULL;
	ax_uchar filepath[AX_PATH_MAX];

	if (!(lzz_fp = ax_fopen(lzz_filepath, "wb"))) {
		ax_perror("Failed to open file `%s': %s", lzz_filepath, strerror(errno));
		goto out;
	}
	
	char magic[2] = { 'l', 'z' };
	if (!fwrite(magic, sizeof magic, 1, lzz_fp)) {
		ax_perror("Failed to write lzz file: %s", strerror(errno));
		goto out;
	}


	for (int i = 0; files[i]; i++) {
		if (!ax_path_realize(files[i], filepath, AX_PATH_MAX)) {
			ax_pwarn("Ignored path `%s': %s", files[i], strerror(errno));
			continue;
		}

		ax_stat stat;
		if (ax_stat_get(filepath, &stat)) {
			ax_pwarn("Ignored path `%s': %s", files[i], strerror(errno));
			continue;
		}

		if ((stat.st_mode & AX_S_IFMT) == AX_S_IFDIR) {
			if (pack_dir(lzz_fp, filepath, ax_ustrlen(filepath)))
				goto out;
		}
		if ((stat.st_mode & AX_S_IFMT) == AX_S_IFREG) {
			if (pack_file(lzz_fp, filepath, ax_ustrlen(filepath)))
				goto out;
		}
	}
	if (fflush(lzz_fp)) {
		ax_perror("Failed to write lzz file: %s", strerror(errno));
		goto out;
	}
	retval = 0;
out:
	if (lzz_fp)
		fclose(lzz_fp);
	if (retval)
		ax_sys_unlink(lzz_filepath);
	return retval;
}

static int read_file_entry(FILE *lzz_fp, ax_uchar *name, uint32_t *timp)
{
	int retval = -1;
	if (!fread(timp, sizeof *timp, 1, lzz_fp))
		goto out;

	char utf8_name[AX_FILENAME_MAX];

	uint8_t name_len;
	if (!fread(&name_len, sizeof name_len, 1, lzz_fp)) {
		ax_perror("Failed to read lzz file: %s", strerror(errno));
		goto out;
	}
	
	if (!fread(utf8_name, name_len, 1, lzz_fp)) {
		ax_perror("Failed to read lzz file: %s", strerror(errno));
		goto out;
	}
	utf8_name[name_len] = '\0';

	if (ax_ustr_from_utf8(name, AX_FILENAME_MAX, utf8_name) == -1) {
		ax_perror("Coding convertion failed");
		goto out;
	}

	retval = 0;
out:
	return retval;
}

static int extract_file(FILE *lzz_fp, ax_uchar *extract_filepath, uint32_t tim, bool test)
{
	int retval = -1;
	FILE *dst_fp = NULL;

	ax_printf(ax_u("%s\n"), extract_filepath);

	if (!test && !(dst_fp = fopen(extract_filepath, "wb")))
		goto out;

	uint8_t rd_buf[COMPRESSED_BUF_SIZE];
	uint8_t uncomp_buf[UNCOMPRESSED_BUF_SIZE];
	uint16_t comp_size;
	while (1) {
		if (!fread(&comp_size, sizeof comp_size, 1, lzz_fp))
			goto out;

		if (comp_size == 0)
			break;

		if (!fread(rd_buf, comp_size, 1, lzz_fp))
			goto out;

		size_t uncomp_size = sizeof uncomp_buf;
		if (lznt1_decompress(rd_buf, comp_size, uncomp_buf, &uncomp_size)) {
			ax_perror("Failed to decompress data block, file is broken");
			goto out;
		}

		if (!test && !fwrite(uncomp_buf, uncomp_size, 1, dst_fp))
			goto out;
	}
	if (!test)
		ax_sys_utime(extract_filepath, tim, tim);

	retval = 0;
out:
	if (dst_fp)
		fclose(dst_fp);
	return retval;
}

static int unpack_file(FILE *lzz_fp, ax_uchar *path, size_t path_len, bool test)
{
	int retval = -1;
	uint8_t token;

	while (1) {
		ax_uchar name_buf[AX_FILENAME_MAX];
		uint32_t tim;

		if (!fread(&token, sizeof token, 1, lzz_fp))
			goto out;

		if (token == TOKEN_DIR_END)
			break;

		if (read_file_entry(lzz_fp, name_buf, &tim))
			goto out;

		ax_ustrcpy(path + path_len, ax_u(AX_PATH_SEP));
		ax_ustrcat(path + path_len, name_buf);

		if (token == TOKEN_FILE) {
			if (extract_file(lzz_fp, path, tim, test))
				goto out;
		}
		else if (token == TOKEN_DIR_BEGIN) {
			if (!test && ax_sys_mkdir(path, 0755) && errno != EEXIST) {
				ax_perror("Failed to create directory `%s': %s", path, strerror(errno));
				goto out;
			}
			size_t name_len = ax_ustrlen(name_buf);
			if (unpack_file(lzz_fp, path, path_len + name_len + 1, test))
				goto out;
		}
		else {
			ax_perror("Bad file format");
			goto out;
		}
	}

	retval = 0;
out:
	return retval;
}

int lzz_unpack(const ax_uchar *lzz_filepath, const ax_uchar *target_path, bool test)
{
	int retval = -1;
	FILE *lzz_fp = NULL;

	if (!(lzz_fp = ax_fopen(lzz_filepath, "r")))
		goto out;
	
	char magic[2];
	if (!fread(magic, sizeof magic, 1, lzz_fp)) {
		ax_perror("Read lzz file failed: %s", strerror(errno));
		goto out;
	}

	if (magic[0] != 'l' || magic[1] != 'z')
		goto out;

	ax_uchar filepath[AX_PATH_MAX];

	if (!test && !ax_path_realize(target_path, filepath, AX_PATH_MAX)) {
		ax_perror("Invalid path `%s': %s", target_path, strerror(errno));
		goto out;
	}

	retval = unpack_file(lzz_fp, filepath, ax_ustrlen(filepath), test);
out:
	if (lzz_fp)
		fclose(lzz_fp);
	return retval;
}

