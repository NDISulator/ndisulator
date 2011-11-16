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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <err.h>
#include <fcntl.h>
#include <ctype.h>

#include "pe_var.h"
#include "loader.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: ndisload -p -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");
	fprintf(stderr, "Usage: ndisload -P -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");
	fprintf(stderr, "Usage: ndisload -u -s <sysfile> -n <devicedescr> -v <vendorid> -d <deviceid> [-f <firmfile>]\n");

	exit(1);
}

static int
load_file(char *filename, ndis_load_driver_args_t *driver)
{
	int file;
	size_t size;
	void *image = NULL;
	struct stat sb;

	file = open(filename, O_RDONLY, 0);
	if (file < 0)
		err(-1, "open(%s)", filename);
	if (fstat(file, &sb) < 0) {
		close(file);
		err(-1, "fstat(%s)", filename);
	}
	size = sb.st_size;
	image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, file, 0);
	if (image == MAP_FAILED) {
		close(file);
		err(-1, "mmap(%s)", filename);
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
