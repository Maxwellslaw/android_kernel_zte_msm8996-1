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

#define pr_fmt(fmt) "%s: %s: " fmt, KBUILD_MODNAME, __func__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/fs_struct.h>

#include "ufsd.h"

#define UFSD_DEBUG 0

#ifdef CONFIG_SECURITY_SELINUX
#define UFSD_DEFAULT_CONTEXT CONFIG_UFSD_PROXY_SELINUX_LABEL
#endif

#define UFSD_OPTS_LEN_MAX  200

#define UFSD_SUPPORT_EXFAT 1
#define UFSD_SUPPORT_VFAT  0
#define UFSD_SUPPORT_NTFS  1
#define UFSD_SUPPORT_F2FS  0
#define UFSD_SUPPORT_EXT4  0

#define no_mask ((unsigned short)-1)
#define no_uid  ((uid_t)-1)
#define no_gid  ((gid_t)-1)

#define mask_valid(mask) (mask < no_mask)
#define uid_valid(uid)   (uid  < no_uid)
#define gid_valid(gid)   (gid  < no_gid)

#define append_fs_opt(opt, ...) \
do { \
	s += scnprintf(s, end - s, opt ",", ##__VA_ARGS__); \
} while(0)

enum {
	Opt_context,
	Opt_iocharset,
	Opt_codepage,
	Opt_nls,
	Opt_uid,
	Opt_gid,
	Opt_umask,
	Opt_dmask,
	Opt_fmask,
	Opt_nocase,
	Opt_noatime,
	Opt_discard,
	Opt_sys_immutable,
	Opt_err_cont,
	Opt_err_panic,
	Opt_err_ro,
/* ignored Paragon mount options */
	Opt_showmeta,
	Opt_bestcompr,
	Opt_nobuf,
	Opt_sparse,
	Opt_force,
	Opt_nohidden,
	Opt_clump,
/* end ignored mount options */
	Opt_err
};

static const match_table_t ufsd_mount_tokens = {
	{Opt_context,       "context=%s"},
	{Opt_iocharset,     "iocharset=%s"},
	{Opt_codepage,      "codepage=%s"},
	{Opt_nls,           "nls=%s"},
	{Opt_uid,           "uid=%u"},
	{Opt_gid,           "gid=%u"},
	{Opt_umask,         "umask=%o"},
	{Opt_dmask,         "dmask=%o"},
	{Opt_fmask,         "fmask=%o"},
	{Opt_nocase,        "nocase"},
	{Opt_noatime,       "noatime"},
	{Opt_discard,       "discard"},
	{Opt_sys_immutable, "sys_immutable"},
	{Opt_err_cont,      "errors=continue"},
	{Opt_err_panic,     "errors=panic"},
	{Opt_err_ro,        "errors=remount-ro"},
/* ignored Paragon mount options */
	{Opt_showmeta,      "showmeta"},
	{Opt_bestcompr,     "bestcompr"},
	{Opt_nobuf,         "nobuf"},
	{Opt_sparse,        "sparse"},
	{Opt_force,         "force"},
	{Opt_nohidden,      "nohidden"},
	{Opt_clump,         "clump=%u"},
/* end ignored mount options */
	{Opt_err, NULL}
};

static int ufsd_parse_opts(char *options, struct ufsd_mount_options *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int val, token;

	opts->uid = no_uid;
	opts->gid = no_gid;
	opts->umask = no_mask;
	opts->dmask = no_mask;
	opts->fmask = no_mask;

	if (!options)
		goto out;

	pr_info("Mount options: %s\n", options);

	while ((p = strsep(&options, ","))) {
		if (!*p)
			continue; /* you should be ashamed of your ,, */

		token = match_token(p, ufsd_mount_tokens, args);
		switch (token) {
		case Opt_context:
			opts->context = match_strdup(&args[0]);
			if (!opts->context)
				return -ENOMEM;
			break;
		case Opt_iocharset:
		case Opt_codepage:
		case Opt_nls:
			opts->iocharset = match_strdup(&args[0]);
			if (!opts->iocharset)
				return -ENOMEM;
			break;
		case Opt_uid:
			if (match_int(&args[0], &val))
				goto invalid;
			opts->uid = val;
			break;
		case Opt_gid:
			if (match_int(&args[0], &val))
				goto invalid;
			opts->gid = val;
			break;
		case Opt_umask:
		case Opt_dmask:
		case Opt_fmask:
			if (match_octal(&args[0], &val))
				goto invalid;
			if (token == Opt_umask)
				opts->umask = val;
			else if (token == Opt_dmask)
				opts->dmask = val;
			else if (token == Opt_fmask)
				opts->fmask = val;
			break;
		case Opt_nocase:
			opts->nocase = 1;
			break;
		case Opt_noatime:
			opts->noatime = 1;
			break;
		case Opt_discard:
			opts->discard = 1;
			break;
		case Opt_sys_immutable:
			opts->sys_immutable = 1;
			break;
		case Opt_err_cont:
			opts->errors = UFSD_ERRORS_CONT;
			break;
		case Opt_err_panic:
			opts->errors = UFSD_ERRORS_PANIC;
			break;
		case Opt_err_ro:
			opts->errors = UFSD_ERRORS_RO;
			break;
		/* ignored options */
		case Opt_showmeta:
		case Opt_bestcompr:
		case Opt_nobuf:
		case Opt_sparse:
		case Opt_force:
		case Opt_nohidden:
		case Opt_clump:
			pr_warn("Ignoring mount option '%s' (unsupported)\n", p);
			break;
		/* end ignored options */
		default:
			pr_err("Unrecognized mount option '%s' or missing value\n", p);
			return -EINVAL;
		}
	}

out:

#if UFSD_DEBUG
	if (opts->context)
		pr_info("opts->context = %s\n", opts->context);
	if (opts->iocharset)
		pr_info("opts->iocharset = %s\n", opts->iocharset);
	pr_info("opts->uid = %u\n", opts->uid);
	pr_info("opts->gid = %u\n", opts->gid);
	pr_info("opts->umask = %04o\n", opts->umask);
	pr_info("opts->dmask = %04o\n", opts->dmask);
	pr_info("opts->fmask = %04o\n", opts->fmask);
	pr_info("opts->nocase = %u\n", opts->nocase);
	pr_info("opts->noatime = %u\n", opts->noatime);
	pr_info("opts->discard = %u\n", opts->discard);
	pr_info("opts->sys_immutable = %u\n", opts->sys_immutable);
	pr_info("opts->errors = %u\n", opts->errors);
#endif

	return 0;

invalid:
	pr_err("Option '%s' has an invalid value\n", p);
	return -EINVAL;
}

#if UFSD_SUPPORT_EXFAT
static char *ufsd_exfat_build_opts(char *s, const char *end,
				   struct ufsd_mount_options *opts)
{
	if (uid_valid(opts->uid))
		append_fs_opt("uid=%u", opts->uid);
	if (gid_valid(opts->gid))
		append_fs_opt("gid=%u", opts->gid);

	if (mask_valid(opts->umask))
		append_fs_opt("umask=%04o", opts->umask);
	if (mask_valid(opts->dmask))
		append_fs_opt("dmask=%04o", opts->dmask);
	if (mask_valid(opts->fmask))
		append_fs_opt("fmask=%04o", opts->fmask);

	if (opts->iocharset)
		append_fs_opt("iocharset=%s", opts->iocharset);

	append_fs_opt("namecase=%u", !opts->nocase);

	if (opts->discard)
		append_fs_opt("discard");

	switch (opts->errors) {
	case UFSD_ERRORS_CONT:
		append_fs_opt("errors=continue");
		break;
	case UFSD_ERRORS_PANIC:
		append_fs_opt("errors=panic");
		break;
	case UFSD_ERRORS_RO:
		append_fs_opt("errors=remount-ro");
		break;
	}

	return s;
}

static struct ufsd_filesystem ufsd_fs_exfat = {
	.name       = "exfat",
	.build_opts = ufsd_exfat_build_opts
};
#endif

#if UFSD_SUPPORT_VFAT
static char *ufsd_vfat_build_opts(char *s, const char *end,
				  struct ufsd_mount_options *opts)
{

	if (uid_valid(opts->uid))
		append_fs_opt("uid=%u", opts->uid);
	if (gid_valid(opts->gid))
		append_fs_opt("gid=%u", opts->gid);

	if (mask_valid(opts->umask))
		append_fs_opt("umask=%04o", opts->umask);
	if (mask_valid(opts->dmask))
		append_fs_opt("dmask=%04o", opts->dmask);
	if (mask_valid(opts->fmask))
		append_fs_opt("fmask=%04o", opts->fmask);

	if (opts->iocharset)
		append_fs_opt("iocharset=%s", opts->iocharset);

	if (opts->nocase)
		append_fs_opt("nocase");

	if (opts->discard)
		append_fs_opt("discard");

	if (opts->sys_immutable)
		append_fs_opt("sys_immutable");

	switch (opts->errors) {
	case UFSD_ERRORS_CONT:
		append_fs_opt("errors=continue");
		break;
	case UFSD_ERRORS_PANIC:
		append_fs_opt("errors=panic");
		break;
	case UFSD_ERRORS_RO:
		append_fs_opt("errors=remount-ro");
		break;
	}

	return s;
}

static struct ufsd_filesystem ufsd_fs_vfat = {
	.name       = "vfat",
	.build_opts = ufsd_vfat_build_opts
};
#endif

#if UFSD_SUPPORT_NTFS
static char *ufsd_ntfs_build_opts(char *s, const char *end,
				  struct ufsd_mount_options *opts)
{
	if (uid_valid(opts->uid))
		append_fs_opt("uid=%u", opts->uid);
	if (gid_valid(opts->gid))
		append_fs_opt("gid=%u", opts->gid);

	if (mask_valid(opts->umask))
		append_fs_opt("umask=%04o", opts->umask);
	if (mask_valid(opts->dmask))
		append_fs_opt("dmask=%04o", opts->dmask);
	if (mask_valid(opts->fmask))
		append_fs_opt("fmask=%04o", opts->fmask);

	if (opts->iocharset)
		append_fs_opt("nls=%s", opts->iocharset);

	append_fs_opt("case_sensitive=%u", !opts->nocase);

	switch (opts->errors) {
	case UFSD_ERRORS_CONT:
		append_fs_opt("errors=continue");
		break;
	case UFSD_ERRORS_PANIC:
		append_fs_opt("errors=panic");
		break;
	case UFSD_ERRORS_RO:
		append_fs_opt("errors=remount-ro");
		break;
	}

	return s;
}

static struct ufsd_filesystem ufsd_fs_ntfs = {
	.name       = "ntfs",
	.build_opts = ufsd_ntfs_build_opts
};
#endif

#if UFSD_SUPPORT_F2FS
static char *ufsd_f2fs_build_opts(char *s, const char *end,
				  struct ufsd_mount_options *opts)
{
	if (opts->discard)
		append_fs_opt("discard");

	/* f2fs has no support for error fallbacks? */

	return s;
}

static struct ufsd_filesystem ufsd_fs_f2fs = {
	.name       = "f2fs",
	.build_opts = ufsd_f2fs_build_opts
};
#endif

#if UFSD_SUPPORT_EXT4
static char *ufsd_ext4_build_opts(char *s, const char *end,
				 struct ufsd_mount_options *opts)
{
	if (opts->discard)
		append_fs_opt("discard");

	switch (opts->errors) {
	case UFSD_ERRORS_CONT:
		append_fs_opt("errors=continue");
		break;
	case UFSD_ERRORS_PANIC:
		append_fs_opt("errors=panic");
		break;
	case UFSD_ERRORS_RO:
		append_fs_opt("errors=remount-ro");
		break;
	}

	return s;
}

static struct ufsd_filesystem ufsd_fs_ext4 = {
	.name       = "ext4",
	.build_opts = ufsd_ext4_build_opts
};
#endif

static char *ufsd_build_opts(struct ufsd_filesystem *fs,
			     struct ufsd_mount_options *opts)
{
	char *str, *s, *end;
	int len = UFSD_OPTS_LEN_MAX;

	str = kzalloc(len, GFP_KERNEL);
	if (!str)
		return ERR_PTR(-ENOMEM);

	s = str;
	end = s + len;

#ifdef CONFIG_SECURITY_SELINUX
	if (!opts->context)
		opts->context = UFSD_DEFAULT_CONTEXT;

	append_fs_opt("context=%s", opts->context);
#endif

	s = fs->build_opts(s, end, opts);

	*(s - 1) = 0; /* replace trailing , with null */

	return str;
}

static struct vfsmount *ufsd_try(struct ufsd_filesystem *fs,
			       struct ufsd_mount_options *ufsd_opts,
			       int flags, const char *dev_name)
{
	char *fs_opts;
	struct vfsmount *mnt;
	struct file_system_type *fs_type;

	fs_type = get_fs_type(fs->name);
	if (IS_ERR(fs_type)) {
		pr_err("Could not find %s filesystem!\n", fs->name);
		return ERR_PTR(-EINVAL);
	}

	fs_opts = ufsd_build_opts(fs, ufsd_opts);
	if (IS_ERR(fs_opts)) {
		pr_err("Failed to build mount options "
		       "for %s filesystem!\n", fs->name);
		mnt = ERR_PTR(-EINVAL);
		goto out;
	}

	pr_info("Attempting mount as %s with options: %s", fs->name, fs_opts);

	mnt = vfs_kern_mount(fs_type, flags, dev_name, fs_opts);
	if (!IS_ERR(mnt))
		pr_info("Successfully mounted '%s' as %s!", dev_name, fs->name);

out:
	kfree(fs_opts);

	return mnt;
}

struct vfsmount *ufsd_vfs_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name,
				void *data)
{
	struct vfsmount *mnt = NULL;
	struct ufsd_mount_options *ufsd_opts;

	ufsd_opts = kzalloc(sizeof(struct ufsd_mount_options), GFP_KERNEL);
	if (!ufsd_opts) {
		pr_err("Could not allocate memory for mount options!\n");
		return ERR_PTR(-ENOMEM);
	}

	if (ufsd_parse_opts(data, ufsd_opts)) {
		pr_err("Failed to parse mount options!\n");
		mnt = ERR_PTR(-EINVAL);
		goto out;
	}

#if UFSD_SUPPORT_EXFAT
	mnt = ufsd_try(&ufsd_fs_exfat, ufsd_opts, flags, dev_name);
	if (!IS_ERR(mnt))
		goto out;
#endif
#if UFSD_SUPPORT_VFAT
	mnt = ufsd_try(&ufsd_fs_vfat, ufsd_opts, flags, dev_name);
	if (!IS_ERR(mnt))
		goto out;
#endif
#if UFSD_SUPPORT_NTFS
	mnt = ufsd_try(&ufsd_fs_ntfs, ufsd_opts, flags, dev_name);
	if (!IS_ERR(mnt))
		goto out;
#endif
#if UFSD_SUPPORT_F2FS
	mnt = ufsd_try(&ufsd_fs_f2fs, ufsd_opts, flags, dev_name);
	if (!IS_ERR(mnt))
		goto out;
#endif
#if UFSD_SUPPORT_EXT4
	mnt = ufsd_try(&ufsd_fs_ext4, ufsd_opts, flags, dev_name);
	if (!IS_ERR(mnt))
		goto out;
#endif

	if (IS_ERR_OR_NULL(mnt)) {
		pr_err("Failed to mount filesystem\n");
		mnt = ERR_PTR(-EINVAL);
	}
out:
	kfree(ufsd_opts);

	return mnt;
}
EXPORT_SYMBOL(ufsd_vfs_mount);

static struct dentry *ufsd_mount(struct file_system_type *fs_type,
				 int flags, const char *dev_name,
				 void *data)
{
	/* ufsd is not an actual filesystem capable of being mounted */
	return ERR_PTR(-EINVAL);
}

static struct file_system_type ufsd_fs_type = {
	.owner       = THIS_MODULE,
	.name        = "ufsd",
	.mount       = ufsd_mount, /* -EINVAL */
	.fs_flags    = FS_REQUIRES_DEV,
};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
MODULE_ALIAS_FS("ufsd");
#endif

static int __init init_ufsd_fs(void)
{
	int err;

	pr_info("UFSD filesystem mount proxy version %s\n", UFSD_VERSION);

	err = register_filesystem(&ufsd_fs_type);
	if (err) {
		pr_err("Unable to register as ufsd (%d)\n", err);
		return err;
	}

	return 0;
}

static void __exit exit_ufsd_fs(void)
{
	unregister_filesystem(&ufsd_fs_type);
}

module_init(init_ufsd_fs);
module_exit(exit_ufsd_fs);

MODULE_AUTHOR("jcadduono");
MODULE_DESCRIPTION("UFSD filesystem mount proxy");
MODULE_LICENSE("GPL");
