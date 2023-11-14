/*
 * Copyright (C) 2012 Jeffrey Bush <jeff@coderforlife.com>
 * Copyright (c) 2023 Li Xilin <lixilin@gmx.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
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

#include "lznt1.h"
#include <stdbool.h>
#include <endian.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define CHUNK_SIZE 0x1000 // compatible with all known forms of Windows
#define COPY_ROOM 16
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define GET_U16_RAW(x)       (*(const uint16_t*)(x))
#define GET_U32_RAW(x)       (*(const uint32_t*)(x))
#define SET_U16_RAW(x,val)   (*(uint16_t*)(x) = (uint16_t)(val))
#define SET_U32_RAW(x,val)   (*(uint32_t*)(x) = (uint32_t)(val))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define GET_U16(x)           GET_U16_RAW(x)
#define GET_U32(x)           GET_U32_RAW(x)
#define SET_U16(x,val)       SET_U16_RAW(x,val)
#define SET_U32(x,val)       SET_U32_RAW(x,val)
#elif __BYTE_ORDER == __BIG_ENDIAN

inline static uint16_t byte_swap_16(uint16_t x)
{
	return (x<<8) | (x>>8);
}

inline static uint32_t byte_swap_32(uint32_t x)
{
	return (x<<24) | ((x<<8)&0x00FF0000) | ((x>>8)&0x0000FF00) | (x>>24);
}

#define GET_U16(x)           byte_swap_16(*(const uint16_t*)(x))
#define GET_U32(x)           byte_swap_32(*(const uint32_t*)(x))
#define SET_U16(x,val)       (*(uint16_t*)(x) = byte_swap_16((uint16_t)(val)))
#define SET_U32(x,val)       (*(uint32_t*)(x) = byte_swap_32((uint32_t)(val)))
#else
#error Unknown byte order
#endif

#define COPY_4x(out, in) do { (out)[0] = (in)[0], (out)[1] = (in)[1], (out)[2] = (in)[2], (out)[3] = (in)[3]; } while (0)
#define COPY_32(out, in) do { *(uint32_t*)(out) = *(uint32_t*)(in); } while (0)
#define COPY_4x32(out, in)  COPY_4x(((uint32_t*)(out)), ((uint32_t*)(in)))

struct lznt1dir_entry
{
        const uint8_t **pos;
        int16_t cap;
};

struct lznt1dir {
        // 6+ uint8_t (10+ uint8_t on 64-bit systems)
        struct lznt1dir_entry *entries;
        const uint8_t *_data;
        int16_t *sizes;
};

static int lznt1dir_init(struct lznt1dir *dir);
static void lznt1dir_free(struct lznt1dir *dir);
static bool lznt1dir_fill(struct lznt1dir *dir, const uint8_t *data, const int_fast16_t len);
static int_fast16_t lznt1dir_find(struct lznt1dir *dir, const uint8_t *data, const int_fast16_t max_len, int_fast16_t* offset);
static bool lznt1dir_entry_add(struct lznt1dir_entry *entry, const uint8_t *data, const int16_t size);

static int lznt1dir_init(struct lznt1dir *dir)
{
        if (!(dir->entries = malloc(0x100 * 0x100 * sizeof(struct lznt1dir_entry))))
		return -1;
        if (!(dir->sizes = malloc(0x100 * 0x100 * sizeof(int16_t)))) {
		free(dir->entries);
		return -1;
	}
        memset(dir->entries, 0, 0x100 * 0x100 * sizeof(struct lznt1dir_entry));
        return 0;
}

static void lznt1dir_free(struct lznt1dir *dir)
{
        for (uint32_t idx = 0; idx < 0x100*0x100; ++idx)
                free(dir->entries[idx].pos);
        free(dir->entries);
        free(dir->sizes);
}

static bool lznt1dir_fill(struct lznt1dir *dir, const uint8_t *data, const int_fast16_t len)
{
        dir->_data = data;
        struct lznt1dir_entry* entrs = dir->entries;
        int16_t* szs = dir->sizes;
        memset(szs, 0, 0x100*0x100*sizeof(uint16_t));
        uint16_t idx = data[0];
        for (const uint8_t *end = data + len - 2; data < end; ++data) {
                idx = idx << 8 | data[1];
                if (!lznt1dir_entry_add(&entrs[idx], data, szs[idx]++))
                        return false;
        }
        return true;
}

static int_fast16_t lznt1dir_find(struct lznt1dir *dir, const uint8_t *data, const int_fast16_t max_len, int_fast16_t* offset)
{
        if (max_len < 3 || data <= dir->_data)
		// No match found, return 0
		return 0;

	const uint_fast16_t idx = data[0] << 8 | data[1];
	const uint8_t z = data[2];
	const int_fast16_t size = dir->sizes[idx] - 1;
	const uint8_t ** pos = dir->entries[idx].pos;
	int_fast16_t len = 0;
	const uint8_t *found;

	// Do an exhaustive search (with the possible positions)
	for (int_fast16_t j = 0; j < size && pos[j] < data; ++j) {
		const uint8_t *ss = pos[j];
		if (ss[2] == z) {
			int_fast16_t i = 3;
			for (const uint8_t *s = ss+3; i < max_len && data[i] == *s; ++i, ++s);
			if (i > len) {
				found = ss;
				len = i;
				if (len == max_len)
					break;
			}
		}
	}

	// Found a match, return it
	if (len >= 3) {
		*offset = (int_fast16_t)(data-found);
		return len;
	}

        return 0;
}

static bool lznt1dir_entry_add(struct lznt1dir_entry *entry, const uint8_t *data, const int16_t size)
{
        if (size >= entry->cap) {
		entry->cap = entry->cap ? (entry->cap << 1) : 4;
		size_t new_size = entry->cap * sizeof(const uint8_t *);
                const uint8_t **temp = realloc((uint8_t*)entry->pos, new_size);
                if (temp == NULL) {
			return false;
		}
                entry->pos = temp;
        }
        entry->pos[size] = data;
        return true;
}

size_t lznt1_max_compressed_size(size_t in_len)
{
	return in_len + 3 + 2 * ((in_len + CHUNK_SIZE - 1) / CHUNK_SIZE);
}

static uint_fast16_t lznt1_compress_chunk(const uint8_t *in, uint_fast16_t in_len, uint8_t *out, size_t out_len, struct lznt1dir *d)
{
	uint_fast16_t in_pos = 0, out_pos = 0, rem = in_len, pow2 = 0x10, mask3 = 0x1002, shift = 12;

	if (!lznt1dir_fill(d, in, in_len))
		return 0;

	while (out_pos < out_len && rem) {
		// Go through each bit
		// if all are special, then it will fill 16 bytes
		uint8_t i = 0, pos = 0, bits = 0, bytes[16];
		for (; i < 8 && out_pos < out_len && rem; ++i) {
			bits >>= 1;

			while (pow2 < in_pos) {
				pow2 <<= 1;
				mask3 = (mask3>>1) + 1;
				shift--;
			}

			int_fast16_t off, len = lznt1dir_find(d, in+in_pos, MIN(rem, mask3), &off);
			if (len > 0) {
				// Write symbol that is a combination of offset and length
				const uint16_t sym = (uint16_t)(((off-1) << shift) | (len-3));
				SET_U16(bytes+pos, sym);
				pos += 2;
				bits |= 0x80; // set the highest bit
				in_pos += len;
				rem -= len;
			}
			else {
				// Copy directly
				bytes[pos++] = in[in_pos++];
				rem--;
			}
		}
		uint_fast16_t end = out_pos+1+pos;

		// should be uncompressed or insufficient buffer
		if (end >= in_len || end > out_len) {
			return in_len;
		}
		out[out_pos] = (bits >> (8-i)); // finish moving the value over
		memcpy(out+out_pos+1, bytes, pos);
		out_pos += 1 + pos;
	}

	// Return insufficient buffer or the compressed size
	return rem ? in_len : out_pos;
}

int lznt1_compress(const uint8_t *in, size_t in_len, uint8_t *out, size_t* _out_len)
{
	int retval = -1;
	const size_t out_len = *_out_len;
	size_t out_pos = 0, in_pos = 0;
	// requires 512-768 KB of stack space 
	// or  ~24kb of stack space (+ up to ~17kb during Fill())
	struct lznt1dir d;
	if (lznt1dir_init(&d))
		return -1;

	while (out_pos < out_len-1 && in_pos < in_len) {
		// Compress the next chunk
		const uint_fast16_t in_size = (uint_fast16_t)MIN(in_len-in_pos, 0x1000);
		uint_fast16_t out_size = lznt1_compress_chunk(in+in_pos, in_size, out+out_pos+2, out_len-out_pos-2, &d), flags;
		if (out_size == 0) {
			errno = ENOBUFS;
			goto out;
		}

		if (out_size < in_size) {
			flags = 0xB000;
		}
		else {
			// chunk is uncompressed
			if (out_pos+2+in_size > out_len) {
				errno = ENOBUFS;
				goto out;
			}
			out_size = in_size;
			flags = 0x3000;
			memcpy(out+out_pos+2, in+in_pos, out_size);
		}

		// Save header
		const uint16_t header = (uint16_t)(flags | (out_size-1));
		SET_U16(out+out_pos, header);

		// Increment positions
		out_pos += out_size+2;
		in_pos  += in_size;
	}

	// Return insufficient buffer or the compressed size
	if ((in_pos < in_len)) {
		errno = ENOBUFS;
		goto out;
	}
	// https://msdn.microsoft.com/library/jj679084.aspx: If an End_of_buffer terminal is added, the
	// size of the final compressed data is considered not to include the size of the End_of_buffer terminal.
	if (out_len-out_pos >= 2) {
		out[out_pos] = out[out_pos+1] = 0;
	}
	*_out_len = out_pos;
	retval = 0;
out:
	lznt1dir_free(&d);
	return retval;
}

inline static int fast_copy(uint8_t **out, const uint8_t *in, uint_fast16_t *len, size_t off, const uint8_t *near_end)
{
        /* Write up to 3 bytes for close offsets so that we have >=4 bytes to read in all cases */
        switch (off)
        {
        case 1:
		(*out)[0] = (*out)[1] = (*out)[2] = in[0];
		*out += 3;
		*len -= 3;
		break;
        case 2:
		(*out)[0] = in[0];
		(*out)[1] = in[1];
		*out += 2;
		*len -= 2;
		break;
        case 3:
		(*out)[0]=in[0];
		(*out)[1]=in[1];
		(*out)[2]=in[2];
		*out += 3;
		*len -= 3;
		break;
        }
        if (*len) {
		/* now have >=16 bytes that can be read in chunks of 4 bytes */
                COPY_32(*out+0, in+0);
                COPY_32(*out+4, in+4);
                COPY_32(*out+8, in+8);
                if (*len > 12) {
                        *out += 12;
			in += 12;
			*len -= 12;
                        if (*out >= near_end) {
				return -1;
			}
			/* Repeatedly write 16 bytes */
                        while (*len > 16) {
                                COPY_4x32(*out, in);
				*out += 16;
				in += 16;
				*len -= 16;
                                if (*out >= near_end) {
					return -1;
				}
                        }
                        /* Last 16 bytes */
                        COPY_4x32(*out, in);
                }
                *out += *len;
        }
	return 0;
}

static int lznt1_decompress_chunk(const uint8_t *in, const uint8_t *in_end, uint8_t *out, const uint8_t *out_end, size_t* _out_len)
{
	const uint8_t *in_endx  = in_end -0x11; // 1 + 8 * 2 from the end
	const uint8_t *out_start = out, *out_endx = out_end - 8 * COPY_ROOM;
	uint8_t flags, flagged;

	uint_fast16_t pow2 = 0x10, mask = 0xFFF, shift = 12;
	const uint8_t *pow2_target = out_start + 0x10;
	uint_fast16_t len, off;

	// Most of the decompression happens here
	// Very few bounds checks are done but we can only go to near the end and not the end
	while (in < in_endx && out < out_endx) {
		// Handle a fragment
		flagged = (flags = *in++) & 0x01;
		flags = (flags >> 1) | 0x80;
		do {
			if (flagged) {
				// Offset/length symbol
				while (out > pow2_target) {
					// Update the current power of two available bytes
					pow2 <<= 1;
					pow2_target = out_start + pow2;
					mask >>= 1;
					shift--;
				}

				uint16_t sym = GET_U16(in);
				in += 2;
				len = (sym&mask)+3;
				off = (sym>>shift)+1;

				const uint8_t *o = out-off;
				if (o < out_start) {
					errno = EINVAL;
					return -1;
				}
				if (fast_copy(&out, o, &len, off, out_endx)) {
					if (out + len > out_end) {
						errno = (out - out_start) + len > CHUNK_SIZE ? EINVAL : ENOBUFS;
						return -1;
					}
					goto checked_copy;
				}
			}
			else {
				// Copy uint8_t directly
				*out++ = *in++;
			}
			flagged = flags & 0x01;
			flags >>= 1;
		} while (flags);
	}

	// Slower decompression but with full bounds checking
	while (in < in_end) {
		// Handle a fragment
		flagged = (flags = *in++) & 0x01;
		flags = (flags >> 1) | 0x80;
		do {
			if (in == in_end) {
				*_out_len = out - out_start;
				return 0;
			}

			else if (flagged) {
				// Offset/length symbol
				if (in + 2 > in_end) {
					errno = EINVAL;
					return -1;
				}
				while (out > pow2_target) {
					pow2 <<= 1;
					pow2_target = out_start + pow2;
					mask >>= 1;
					shift--;
				}
				// Update the current power of two available bytes
				const uint16_t sym = GET_U16(in);
				off = (sym>>shift)+1;
				len = (sym&mask)+3;

				in += 2;
				if (out - off < out_start) {
					errno = EINVAL;
					return -1;
				}
				if (out + len > out_end) {
					errno = (out - out_start) + len > CHUNK_SIZE ? EINVAL : ENOBUFS;
					return -1;
				}

				// Copy bytes
				if (off == 1) {
					memset(out, out[-1], len);
					out += len;
				}
				else {
					const uint8_t *end;
checked_copy:           	
					for (end = out + len; out < end; ++out)
						*out = *(out-off);
				}
			}
			else {
				// Copy uint8_t directly
				*out++ = *in++;
			} 
			flagged = flags & 0x01;
			flags >>= 1;
		} while (flags);
	}

	if (in != in_end) { 
		errno = EINVAL;
		return -1;
	}
	*_out_len = out - out_start;
	return 0;
}

int lznt1_decompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t* _out_len)
{
        const size_t out_len = *_out_len;
        const uint8_t *in_end  = in  + in_len - 1;
        const uint8_t *out_end = out + out_len, *out_start = out;

        // Go through every chunk
        while (in < in_end && out < out_end) {
                // Read chunk header
                const uint16_t header = GET_U16(in);
                if (header == 0) {
			*_out_len = out - out_start;
			return 0;
		}
                const uint_fast16_t in_size = (header & 0x0FFF) + 1;
                if (in+in_size >= in_end) {
			errno = EINVAL;
			return -1;
		}

                in += 2;

                // Flags:
                //   Highest bit (0x8) means compressed
                // The other bits are always 011 (0x3) and have unknown meaning:
                //   The last two bits are possibly uncompressed chunk size (512, 1024, 2048, or 4096)
                //   However in NT 3.51, NT 4 SP1, XP SP2, Win 7 SP1 the actual chunk size is always 4096
		//   and the unknown flags are always 011 (0x3)

                size_t out_size;
                if (header & 0x8000) {
                        if (lznt1_decompress_chunk(in, in+in_size, out, out_end, &out_size))
				return -1;
                }
                else {
			// read uncompressed chunk
                        out_size = in_size;
                        if (out + out_size > out_end)
				// chunk is longer than the available space
			       break;
                        memcpy(out, in, out_size);
                }
                out += out_size;
                in += in_size;
        }

        // Return insufficient buffer or uncompressed size
        if (in < in_end) {
		errno = ENOBUFS;
		return -1;
	}

        *_out_len = out - out_start;
        return 0;
}

