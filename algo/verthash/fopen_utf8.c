#ifndef H_FOPEN_UTF8
#define H_FOPEN_UTF8

#include "fopen_utf8.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int utf8_char_size(const uint8_t *c)
{
	const uint8_t	m0x	= 0x80, c0x	= 0x00,
	      		m10x	= 0xC0, c10x	= 0x80,
	      		m110x	= 0xE0, c110x	= 0xC0,
	      		m1110x	= 0xF0, c1110x	= 0xE0,
	      		m11110x	= 0xF8, c11110x	= 0xF0;

	if ((c[0] & m0x) == c0x)
		return 1;

	if ((c[0] & m110x) == c110x)
	if ((c[1] & m10x) == c10x)
		return 2;

	if ((c[0] & m1110x) == c1110x)
	if ((c[1] & m10x) == c10x)
	if ((c[2] & m10x) == c10x)
		return 3;

	if ((c[0] & m11110x) == c11110x)
	if ((c[1] & m10x) == c10x)
	if ((c[2] & m10x) == c10x)
	if ((c[3] & m10x) == c10x)
		return 4;

	if ((c[0] & m10x) == c10x)	// not a first UTF-8 byte
		return 0;

	return -1;			// if c[0] is a first byte but the other bytes don't match
}

uint32_t utf8_to_unicode32(const uint8_t *c, size_t *index)
{
	uint32_t v;
	int size;
	const uint8_t m6 = 63, m5 = 31, m4 = 15, m3 = 7;

	if (c==NULL)
		return 0;

	size = utf8_char_size(c);

	if (size > 0 && index)
		*index += size-1;

	switch (size)
	{
		case 1:
			v = c[0];
			break;
		case 2:
			v = c[0] & m5;
			v = v << 6 | (c[1] & m6);
			break;
		case 3:
			v = c[0] & m4;
			v = v << 6 | (c[1] & m6);
			v = v << 6 | (c[2] & m6);
			break;
		case 4:
			v = c[0] & m3;
			v = v << 6 | (c[1] & m6);
			v = v << 6 | (c[2] & m6);
			v = v << 6 | (c[3] & m6);
			break;
		case 0:				// not a first UTF-8 byte
		case -1:			// corrupt UTF-8 letter
		default:
			v = -1;
			break;
	}

	return v;
}

int codepoint_utf16_size(uint32_t c)
{
	if (c < 0x10000) return 1;
	if (c < 0x110000) return 2;

	return 0;
}

uint16_t *sprint_utf16(uint16_t *str, uint32_t c)	// str must be able to hold 1 to 3 entries and will be null-terminated by this function
{
	int c_size;

	if (str==NULL)
		return NULL;

	c_size = codepoint_utf16_size(c);

	switch (c_size)
	{
		case 1:
			str[0] = c;
			if (c > 0)
				str[1] = '\0';
			break;

		case 2:
			c -= 0x10000;
			str[0] = 0xD800 + (c >> 10);
			str[1] = 0xDC00 + (c & 0x3FF);
			str[2] = '\0';
			break;

		default:
			str[0] = '\0';
	}

	return str;
}

size_t strlen_utf8_to_utf16(const uint8_t *str)
{
	size_t i, count;
	uint32_t c;

	for (i=0, count=0; ; i++)
	{
		if (str[i]==0)
			return count;

		c = utf8_to_unicode32(&str[i], &i);
		count += codepoint_utf16_size(c);
	}
}

uint16_t *utf8_to_utf16(const uint8_t *utf8, uint16_t *utf16)
{
	size_t i, j;
	uint32_t c;

	if (utf8==NULL)
		return NULL;

	if (utf16==NULL)
		utf16 = (uint16_t *) calloc(strlen_utf8_to_utf16(utf8) + 1, sizeof(uint16_t));

	for (i=0, j=0, c=1; c; i++)
	{
		c = utf8_to_unicode32(&utf8[i], &i);
		sprint_utf16(&utf16[j], c);
		j += codepoint_utf16_size(c);
	}

	return utf16;
}

FILE *fopen_utf8(const char *path, const char *mode)
{
	#ifdef _WIN32
	wchar_t *wpath, wmode[8];
	FILE *file;

	if (utf8_to_utf16((const uint8_t *) mode, (uint16_t *) wmode)==NULL)
		return NULL;

	wpath = (wchar_t *) utf8_to_utf16((const uint8_t *) path, NULL);
	if (wpath==NULL)
		return NULL;

	file = _wfopen(wpath, wmode);
	free(wpath);
	return file;
	#else
	return fopen(path, mode);
	#endif
}
#endif
