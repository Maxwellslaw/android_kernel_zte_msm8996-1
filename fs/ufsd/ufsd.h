/*
 *  UFSD filesystem mount proxy (I can't believe I had to do this, really ZTE!)
 *
 *  Copyright (C) 2016 James Christopher Adduono.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _UFSD_LINUX_H
#define _UFSD_LINUX_H

#include <linux/fs.h>

#define UFSD_ERRORS_CONT  1
#define UFSD_ERRORS_PANIC 2
#define UFSD_ERRORS_RO    3

struct ufsd_mount_options {
	char *context;
	char *iocharset;
	uid_t uid;
	gid_t gid;
	unsigned short umask;
	unsigned short dmask;
	unsigned short fmask;
	unsigned char nocase;
	unsigned char noatime;
	unsigned char discard;
	unsigned char sys_immutable;
	unsigned char errors;
};

struct ufsd_filesystem {
	const char *name;
	char *(*build_opts) (char *s, const char *end,
			     struct ufsd_mount_options *opts);
};

struct vfsmount *ufsd_vfs_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name,
				void *data);

#endif
