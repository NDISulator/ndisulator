/*-
 * Copyright (c) 2011 Paul B. Mahol
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>

#include "pe_var.h"
#include "loader.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: ndisload -p -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");
	fprintf(stderr, "       ndisload -P -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");
	fprintf(stderr, "       ndisload -u -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");

	exit(1);
}

/*
 * Sections within Windows PE files are defined using virtual
 * and physical address offsets and virtual and physical sizes.
 * The physical values define how the section data is stored in
 * the executable file while the virtual values describe how the
 * sections will look once loaded into memory. It happens that
 * the linker in the Microsoft(r) DDK will tend to generate
 * binaries where the virtual and physical values are identical,
 * which means in most cases we can just transfer the file
 * directly to memory without any fixups. This is not always
 * the case though, so we have to be prepared to handle files
 * where the in-memory section layout differs from the disk file
 * section layout.
 *
 * There are two kinds of variations that can occur: the relative
 * virtual address of the section might be different from the
 * physical file offset, and the virtual section size might be
 * different from the physical size (for example, the physical
 * size of the .data section might be 1024 bytes, but the virtual
 * size might be 1384 bytes, indicating that the data section should
 * actually use up 1384 bytes in RAM and be padded with zeros). What we
 * do is read the original file into memory and then make an in-memory
 * copy with all of the sections relocated, re-sized and zero padded
 * according to the virtual values specified in the section headers.
 * We then emit the fixed up image file for use by the if_ndis driver.
 * This way, we don't have to do the fixups inside the kernel.
 */

#define	ROUND_DOWN(n, align)	(((uintptr_t)n) & ~((align) - 1l))
#define	ROUND_UP(n, align)	ROUND_DOWN(((uintptr_t)n) + (align) - 1l, \
				(align))
static int
insert_padding(void **imgbase, size_t *imglen)
{
	struct image_section_header *sect_hdr;
	struct image_optional_header *opt_hdr;
	int i = 0, sections, curlen = 0, offaccum = 0, oldraddr, oldrlen;
	uint8_t *newimg, *tmp;

	newimg = malloc(*imglen);
	if (newimg == NULL)
		return (ENOMEM);

	bcopy(*imgbase, newimg, *imglen);
	curlen = *imglen;

	if (pe_validate_header((vm_offset_t)newimg))
		return (EINVAL);
	sections = pe_numsections((vm_offset_t)newimg);
	pe_get_optional_header((vm_offset_t)newimg, &opt_hdr);
	pe_get_section_header((vm_offset_t)newimg, &sect_hdr);

	for (i = 0; i < sections; i++) {
		oldraddr = sect_hdr->pointer_to_raw_data;
		oldrlen = sect_hdr->size_of_raw_data;
		sect_hdr->pointer_to_raw_data = sect_hdr->virtual_address;
		offaccum += ROUND_UP(sect_hdr->virtual_address - oldraddr,
		    opt_hdr->file_aligment);
		offaccum += ROUND_UP(sect_hdr->misc.virtual_size,
		    opt_hdr->file_aligment) -
		    ROUND_UP(sect_hdr->size_of_raw_data,
		    opt_hdr->file_aligment);
		tmp = realloc(newimg, *imglen + offaccum);
		if (tmp == NULL) {
			free(newimg);
			return (ENOMEM);
		}
		newimg = tmp;
		pe_get_section_header((vm_offset_t)newimg, &sect_hdr);
		sect_hdr += i;
		bzero(newimg + sect_hdr->pointer_to_raw_data,
		    ROUND_UP(sect_hdr->misc.virtual_size,
		    opt_hdr->file_aligment));
		bcopy((uint8_t *)(*imgbase) + oldraddr,
		    newimg + sect_hdr->pointer_to_raw_data, oldrlen);
		sect_hdr++;
	}

	free(*imgbase);

	*imgbase = newimg;
	*imglen += offaccum;

	return (0);
}

static int
load_file(char *filename, ndis_load_driver_args_t *driver)
{
	FILE *fp;
	size_t size;
	void *image = NULL;

	fp = fopen(filename, "r");
	if (fp == NULL)
		err(-1, "open(%s)", filename);
	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	rewind(fp);
	image = calloc(size, 1);
	fread(image, size, 1, fp);
	fclose(fp);

	if (insert_padding(&image, &size)) {
		fprintf(stderr, "section relocation failed\n");
		return (EINVAL);
	}
	driver->img = image;
	driver->len = size;
	return (0);
}

static void
load_driver(char *filename, ndis_load_driver_args_t *driver)
{
	int fd, error;

	if (load_file(filename, driver))
		err(-1, "failed to load file");
	fd = open("/dev/ndis", O_RDONLY);
	if (fd < 0)
		err(-1, "ndis module not loaded");
	error = ioctl(fd, NDIS_LOAD_DRIVER, driver);
	if (error < 0)
		err(-1, "loading driver failed");
	close(fd);
}

int
main(int argc, char *argv[])
{
	int ch;
	char *sysfile = NULL, *firmfile = NULL;
	char bustype;
	ndis_load_driver_args_t driver;

	bzero(&driver, sizeof(driver));

	while ((ch = getopt(argc, argv, "s:f:pPuv:d:n:")) != -1) {
		switch (ch) {
		case 's':
			sysfile = optarg;
			break;
		case 'f':
			firmfile = optarg;
			break;
		case 'p':
		case 'P':
		case 'u':
			driver.bustype = ch;
			break;
		case 'v':
			driver.vendor = strtol(optarg, NULL, 0);
			break;
		case 'd':
			driver.device = strtol(optarg, NULL, 0);
			break;
		case 'n':
			driver.name = optarg;
			driver.namelen = strlen(optarg);
			break;
		default:
			usage();
		}
	}

	if (sysfile == NULL || driver.bustype == 0 || driver.vendor == 0 || driver.device == 0 || driver.name == NULL)
		usage();

	load_driver(sysfile, &driver);

	return (0);
}
