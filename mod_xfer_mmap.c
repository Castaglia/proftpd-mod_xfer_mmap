/*
 * ProFTPD: mod_xfer_mmap -- a module for using mmap(2) for downloaded files
 * Copyright (c) 2003-2017 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_xfer_mmap contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * -----DO NOT CHANGE THE LINES BELOW-----
 */

#include "conf.h"

/* NOTE: will require 1.3.5c1 or later */
#if PROFTPD_VERSION_NUMBER < 0x0001030501
# error "ProFTPD 1.3.5rc1 or later required"
#endif

#define MOD_XFER_MMAP_VERSION	"mod_xfer_mmap/0.3"

#ifdef HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

/* Dummy file descriptor */
#define XFER_MMAP_FD	10

module xfer_mmap_module;

static int xfer_mmap_engine = FALSE;
static pr_fs_t *xfer_mmap_fs = NULL;
static pool *xfer_mmap_pool = NULL;

typedef struct {
  const char *path;
  off_t datalen;
  struct stat st;
  void *data;

} xfer_mmap_file_t;

/* For the current mapped file.  It may contain info copied from the list
 * of premapped files, or it may be for a file that was mapped on the fly.
 */
static xfer_mmap_file_t curr_mmap_file;
static int xfer_mmap_premapped;

/* For premapped files. */
static array_header *xfer_mmap_files = NULL;

static const char *trace_channel = "xfer_mmap";

/* Support routines
 */

static void xfer_mmap_unmap_files(void) {
  register unsigned int i;
  xfer_mmap_file_t *files;

  if (xfer_mmap_files == NULL) {
    return;
  }

  files = (xfer_mmap_file_t *) xfer_mmap_files->elts;

  for (i = 0; i < xfer_mmap_files->nelts; i++) {
    if (munmap(files[i].data, files[i].st.st_size) < 0) {
      pr_trace_msg(trace_channel, 7, "error unmapping '%s': %s", files[i].path,
        strerror(errno));
    }

    pr_remove_fs(files[i].path);
  }
}

static int xfer_mmap_get_file(const char *path, int *fdp) {
  int fd, flags = O_RDONLY;
  struct stat st;
  void *data;

#ifdef CYGWIN
  flags |= O_BINARY;
#endif

  fd = open(path, flags, PR_OPEN_MODE);
  if (fd < 0) {
    if (fdp != NULL) {
      *fdp = fd;
    }

    return fd;
  }

  if (fstat(fd, &st) < 0) {
    if (fdp != NULL) {
      *fdp = fd;
    }

    return -1;
  }

  data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error mmapping '%s' (size %lu): %s",
      path, (unsigned long) st.st_size, strerror(xerrno));

    if (fdp != NULL) {
      *fdp = fd;
    }

    errno = xerrno;
    return -1;
  }

  /* Note that once we've mapped the file's contents into memory, we do not
   * need to keep the file descriptor open any more.
   */
  (void) close(fd);

  curr_mmap_file.path = path;
  curr_mmap_file.data = data;
  curr_mmap_file.datalen = 0;
  memcpy(&curr_mmap_file.st, &st, sizeof(struct stat));
 
  if (fdp != NULL) {
    *fdp = XFER_MMAP_FD;
  }
 
  return 0;
}

static int xfer_mmap_set_file(const char *path) {
  register unsigned int i;
  xfer_mmap_file_t *files;

  if (xfer_mmap_files == NULL) {
    errno = EPERM;
    return -1;
  }

  files = (xfer_mmap_file_t *) xfer_mmap_files->elts;

  for (i = 0; i < xfer_mmap_files->nelts; i++) {
    if (strcmp(files[i].path, path) == 0) {
      curr_mmap_file.path = files[i].path;
      curr_mmap_file.data = files[i].data;
      curr_mmap_file.datalen = 0;
      memcpy(&curr_mmap_file.st, &(files[i].st), sizeof(struct stat));

      return 0;
    }
  }
 
  return -1;
}

/* FSIO layer callbacks
 */

static int xfer_mmap_close_cb(pr_fh_t *fh, int fd) {
  if (xfer_mmap_premapped == FALSE) {
    munmap(curr_mmap_file.data, curr_mmap_file.st.st_size);
  }

  /* Reset the offset. */
  curr_mmap_file.datalen = curr_mmap_file.st.st_size;

  return 0;
}

static off_t xfer_mmap_lseek_cb(pr_fh_t *fh, int fd, off_t offset, int whence) {

  /* In this case, we know that mod_xfer will always use a whence of SEEK_SET.
   * So we need do nothing but update the mmap offset, after making sure that
   * the requested offset is valid.
   */

  if (offset > curr_mmap_file.st.st_size) {
    errno = EINVAL;
    return -1;
  }

  curr_mmap_file.datalen = offset;

  return offset;
}

static int xfer_mmap_open_cb(pr_fh_t *fh, const char *path, int flags) {
  int fd;

  /* Check to see if the requested file has already been mapped. */
  if (xfer_mmap_files != NULL) {
    const char *full_path;

    full_path = dir_abs_path(fh->fh_pool, path, TRUE);
    if (xfer_mmap_set_file(full_path) == 0) {
      xfer_mmap_premapped = TRUE;
      pr_trace_msg(trace_channel, 9, "using existing mapping for %s", path);
      return XFER_MMAP_FD;
    }
  }

  xfer_mmap_premapped = FALSE;

  if (xfer_mmap_get_file(path, &fd) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_XFER_MMAP_VERSION ": error mapping '%s': %s",
      path, strerror(errno));

    /* Once a filehandle has been opened with a given filesystem, that
     * filesystem cannot be unregistered.  Instead, use pr_remove_fs() to
     * have the filesystem removed from the map.  Then we'll have to destroy
     * the filesystem handle ourselves later, once the filehandle is closed.
     */
    pr_remove_fs(path);
    pr_fs_clear_cache();

    /* Lookup the next best fs to handle this path. */
    fh->fh_fs = pr_get_fs(path, NULL);
  }

  return fd;
}

static int xfer_mmap_read_cb(pr_fh_t *fh, int fd, char *buf, size_t bufsz) {
  size_t len = bufsz;

  /* Ensure we don't read past the end of the mapped memory. */
  if ((off_t) (curr_mmap_file.datalen + bufsz) >= curr_mmap_file.st.st_size) {
    len = curr_mmap_file.st.st_size - curr_mmap_file.datalen;
  }

  memcpy(buf, (char *) curr_mmap_file.data + curr_mmap_file.datalen, len); 
  curr_mmap_file.datalen += len;

  return (int) len;
}

/* Configuration handlers
 */

/* usage: TransferMMapEngine on|off */
MODRET set_xfermmapengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1); 
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: TransferMMapFile path [path ...] */
MODRET set_xfermmapfile(cmd_rec *cmd) {
  register unsigned int i;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    int fd;
    xfer_mmap_file_t *map;
    const char *path = cmd->argv[i];

    if (*path != '/') {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": absolute paths required: '",
        path, "'", NULL));
    }

    if (xfer_mmap_get_file(path, &fd) < 0) {
      close(fd);
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": error mapping '", path, "': ",
        strerror(errno), NULL));
    }

    if (xfer_mmap_files == NULL) {
      xfer_mmap_files = make_array(xfer_mmap_pool, 1, sizeof(xfer_mmap_file_t));
    }

    map = push_array(xfer_mmap_files);
    map->path = pstrdup(xfer_mmap_pool, path);
    map->data = curr_mmap_file.data;
    map->datalen = curr_mmap_file.datalen;
    memcpy(&map->st, &curr_mmap_file.st, sizeof(struct stat));

    if (xfer_mmap_fs == NULL) {
      xfer_mmap_fs = pr_register_fs(xfer_mmap_pool, "mmap", path);
      if (xfer_mmap_fs == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unable register 'mmap' fs: ",
          strerror(errno), NULL));
      }

      /* Add the custom FSIO callbacks. */
      xfer_mmap_fs->close = xfer_mmap_close_cb;
      xfer_mmap_fs->lseek = xfer_mmap_lseek_cb;
      xfer_mmap_fs->open = xfer_mmap_open_cb;
      xfer_mmap_fs->read = xfer_mmap_read_cb;

    } else {

      /* Insert the already-instantiated FS at the given path.  We don't
       * care if it really succeeds or not.
       */
      pr_insert_fs(xfer_mmap_fs, path);
    }
  }

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET xfer_mmap_pre_retr(cmd_rec *cmd) {
  struct stat st;
  const char *path;

  if (xfer_mmap_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* We do not use mmap() if we are transmitting an ASCII file, or
   * if the file is zero-length.
   */
 
  if (session.sf_flags & (SF_ASCII|SF_ASCII_OVERRIDE)) {
    pr_trace_msg(trace_channel, 9,
      "declining to mmap '%s': ASCII transfer requested", cmd->arg);
    return PR_DECLINED(cmd);
  }
 
  if (lstat(cmd->arg, &st) < 0) {
    pr_log_debug(DEBUG3, MOD_XFER_MMAP_VERSION ": error checking '%s': %s",
      cmd->arg, strerror(errno));
    return PR_DECLINED(cmd);
  }

  if (st.st_size == 0) {
    pr_trace_msg(trace_channel, 9, "declining to mmap '%s': Empty file",
      cmd->arg);
    return PR_DECLINED(cmd);
  }

  if (!S_ISLNK(st.st_mode)) {
    path = session.chroot_path ?
      pdircat(cmd->tmp_pool, pr_fs_getvwd(), cmd->arg, NULL) :
      dir_abs_path(cmd->tmp_pool, cmd->arg, TRUE);

  } else {
    char linkpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

    memset(linkpath, '\0', sizeof(linkpath));

    if (pr_fsio_readlink(cmd->arg, linkpath, sizeof(linkpath)-1) < 0) {
      pr_log_debug(DEBUG3, MOD_XFER_MMAP_VERSION ": declining to mmap '%s': "
        "error reading symlink: %s", cmd->arg, strerror(errno));
      return PR_DECLINED(cmd);
    }

    path = session.chroot_path ?
      pdircat(cmd->tmp_pool, pr_fs_getvwd(), linkpath, NULL) :
      dir_abs_path(cmd->tmp_pool, linkpath, TRUE);
  }

  if (xfer_mmap_fs == NULL) {
    xfer_mmap_fs = pr_register_fs(cmd->server->pool, "mmap", path);
    if (xfer_mmap_fs == NULL) {
      pr_log_debug(DEBUG6, MOD_XFER_MMAP_VERSION ": unable register 'mmap' fs: "
        "%s", strerror(errno));
      return PR_DECLINED(cmd);
    }

    /* Add the custom FSIO callbacks. */
    xfer_mmap_fs->close = xfer_mmap_close_cb;
    xfer_mmap_fs->lseek = xfer_mmap_lseek_cb;
    xfer_mmap_fs->open = xfer_mmap_open_cb;
    xfer_mmap_fs->read = xfer_mmap_read_cb;

  } else {

    /* Insert the already-instantiated FS at the given path.  We don't
     * care if it really succeeds or not.
     */
    pr_insert_fs(xfer_mmap_fs, path);
  }

  return PR_DECLINED(cmd);
}

MODRET xfer_mmap_post_retr(cmd_rec *cmd) {
  if (xfer_mmap_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  memset(&curr_mmap_file, '\0', sizeof(curr_mmap_file));
  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

#if defined(PR_SHARED_MODULE)
static void xfer_mmap_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_xfer_mmap.c", (const char *) event_data) == 0) {
    pr_event_unregister(&xfer_mmap_module, NULL, NULL);

    xfer_mmap_unmap_files();

    if (xfer_mmap_fs != NULL) {
      destroy_pool(xfer_mmap_fs->fs_pool);
      xfer_mmap_fs = NULL;
    }

    if (xfer_mmap_pool != NULL) {
      destroy_pool(xfer_mmap_pool);
      xfer_mmap_pool = NULL;
    }
  }
}
#endif /* PR_SHARED_MODULE */

static void xfer_mmap_restart_ev(const void *event_data, void *user_data) {
  xfer_mmap_unmap_files();

  if (xfer_mmap_fs != NULL) {
    destroy_pool(xfer_mmap_fs->fs_pool);
    xfer_mmap_fs = NULL;
  }

  if (xfer_mmap_pool != NULL) {
    destroy_pool(xfer_mmap_pool);
  }

  xfer_mmap_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(xfer_mmap_pool, MOD_XFER_MMAP_VERSION);
}

/* Initialization functions
 */

static int xfer_mmap_init(void) {
  if (xfer_mmap_pool == NULL) {
    destroy_pool(xfer_mmap_pool);
  }

  xfer_mmap_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(xfer_mmap_pool, MOD_XFER_MMAP_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&xfer_mmap_module, "core.module-unload",
    xfer_mmap_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&xfer_mmap_module, "core.restart", xfer_mmap_restart_ev,
    NULL);

  return 0;
}

static int xfer_mmap_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "TransferMMapEngine", FALSE);
  if (c != NULL) {
    xfer_mmap_engine = *((int *) c->argv[0]);
  }

  if (xfer_mmap_engine == FALSE) {
    xfer_mmap_unmap_files(); 

    if (xfer_mmap_fs != NULL) {
      destroy_pool(xfer_mmap_fs->fs_pool);
      xfer_mmap_fs = NULL;
    }

    destroy_pool(xfer_mmap_pool);
    xfer_mmap_pool = NULL;
  }

  return 0;
}

/* Module API tables
 */

static conftable xfer_mmap_conftab[] = {
  { "TransferMMapEngine",	set_xfermmapengine,	NULL },
  { "TransferMMapFile",		set_xfermmapfile,	NULL },
  { NULL }
};

static cmdtable xfer_mmap_cmdtab[] = {
  { PRE_CMD,		C_RETR, G_NONE, xfer_mmap_pre_retr,	FALSE, FALSE },
  { POST_CMD,		C_RETR, G_NONE, xfer_mmap_post_retr,	FALSE, FALSE },
  { POST_CMD_ERR,	C_RETR, G_NONE, xfer_mmap_post_retr,	FALSE, FALSE },
  { 0, NULL }
};

module xfer_mmap_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "xfer_mmap",

  /* Module configuration handler table */
  xfer_mmap_conftab,

  /* Module command handler table */
  xfer_mmap_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  xfer_mmap_init,

  /* Session initialization function */
  xfer_mmap_sess_init,

  /* Module version */
  MOD_XFER_MMAP_VERSION
};
