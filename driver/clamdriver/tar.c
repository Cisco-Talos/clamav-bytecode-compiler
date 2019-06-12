/*
 *  A minimalistic tar archiver for sigtool and freshclam.
 *  Copyright (C) 2007 Sourcefire, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "tar.h"

struct tar_header {
    char name[100];  /* File name */
    char mode[8];    /* File mode */
    char uid[8];     /* UID */
    char gid[8];     /* GID */
    char size[12];   /* File size (octal) */
    char mtime[12];  /* Last modification */
    char chksum[8];  /* Header checksum */
    char type[1];    /* File type */
    char lname[100]; /* Linked file name */
    char pad[255];
};
#define TARBLK 512
#ifndef FILEBUFF
#define FILEBUFF 8192
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif
int tar_addfile(int fd, const char *file)
{
    int s, bytes;
    struct tar_header hdr;
    struct stat sb;
    unsigned char buff[FILEBUFF], *pt;
    unsigned int i, chksum = 0;

    if ((s = open(file, O_RDONLY | O_BINARY)) == -1)
        return -1;

    if (fstat(s, &sb) == -1) {
        close(s);
        return -1;
    }

    memset(&hdr, 0, TARBLK);
    strncpy(hdr.name, file, 100);
    hdr.name[99] = '\0';
    snprintf(hdr.size, 12, "%o", (unsigned int)sb.st_size);
    pt = (unsigned char *)&hdr;
    for (i = 0; i < TARBLK; i++)
        chksum += *pt++;
    snprintf(hdr.chksum, 8, "%06o", chksum + 256);

    if (write(fd, &hdr, TARBLK) != TARBLK) {
        close(s);
        return -1;
    }

    while ((bytes = read(s, buff, FILEBUFF)) > 0) {
        if (write(fd, buff, bytes) != bytes) {
            close(s);
            return -1;
        }
    }
    close(s);

    if (sb.st_size % TARBLK) {
        memset(&hdr, 0, TARBLK);
        if (write(fd, &hdr, TARBLK - (sb.st_size % TARBLK)) == -1)
            return -1;
    }

    return 0;
}
