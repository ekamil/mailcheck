/* mailcheck.c
 *
 * Copyright 1996, 1997, 1998, 2001 Jefferson E. Noxon <jeff@planetfall.com>
 *           2001 Rob Funk <rfunk@funknet.net>
 *           2003, 2005 Tomas Hoger <thoger@pobox.sk>
 *
 * This file may be copied under the terms of the GNU Public License
 * version 2, incorporated herein by reference.
 */

/* Command line parameters:
 * -s: print "no mail" summary if needed
 * -f: specify alternative rc file location
 * -h: print usage
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#define BUF_SIZE (2048)


/* Global variables */
char *Homedir;			/* Home directory pathname */
unsigned short have_mail= 0;	/* Any mail found? */
struct {
  unsigned short show_summary;		/* see '-s' option */
  char *rcfile_path;			/* see '-f' option */
} Options= {0, NULL};
  

/* Print usage information. */
void 
print_usage(void)
{
  printf("Usage: mailcheck [-hs] [-f rcfile]\n"
         "\n"
         "Options:\n"
         "  -s  - show \"no mail\" summary, if no new mail was found\n"
         "  -f  - specify alternative rcfile location\n"
         "  -h  - show this help screen\n"
         "\n");
}

/* Open an rc file.  Exit with error message, if attempt to open rcfile failed.
 * Otherwise, return valid FILE* .
 */
FILE *
open_rcfile (void)
{
  char namebuf[256];
  FILE *rcfile;

  /* if rcfile path was provided, do not try default locations */
  if (Options.rcfile_path != NULL) {
    if ((rcfile= fopen(Options.rcfile_path, "r")) == NULL) {
      fprintf(stderr, "error: couldn't open rcfile '%s'\n",
	  Options.rcfile_path);
      exit(1);
    }
  }
  else {
    snprintf(namebuf, sizeof (namebuf), "%s/.mailcheckrc", Homedir);
    
    if ((rcfile= fopen(namebuf, "r")) == NULL) {
      if ((rcfile= fopen("/etc/mailcheckrc", "r")) == NULL) {
        fprintf (stderr, "mailcheck: couldn't open /etc/mailcheckrc "
            "nor %s/.mailcheckrc\n", Homedir);
	exit(1);
      }
    }
  }
  
  return rcfile;
}


/* Expand environment variables.  Input buffer must be long enough
 * to hold output.  Nested $()'s don't work.
 */
char *
expand_envstr (char *path)
{
  char *srcptr, *envptr, *tmpptr, *dup, *envname;
  int len;

  srcptr = strstr (path, "$(");
  if (!srcptr)
    return path;

  len = strlen (path);
  if (!len)
    return path;

  dup = malloc (len + 1);
  if (!dup)
    return path;

  strcpy (dup, path);
  envptr = strstr (dup, "$(") + 2;
  tmpptr = strchr (envptr, ')');
  if (!tmpptr)
    {
      free (dup);
      return path;
    }

  *tmpptr = 0;
  *srcptr = 0;
  envname = getenv (envptr);
  if (envname)
    strcat (srcptr, envname);
  strcat (srcptr, tmpptr + 1);

  free (dup);
  return expand_envstr (path);
}

/* Should entry in maildir be ignored? */
inline int
ignore_maildir_entry(const char *dir, const struct dirent *entry) {
  char fname[BUF_SIZE];
  struct stat filestat;
  
  /* *all* dotfiles should be ignored in maildir, not only . and .. ! */
  if (entry->d_name[0] == '.')
    return 1;

  /* also count only regular files
   * use dirent's d_type if possible, otherwise stat file (which is much
   * slower) */
#ifdef _DIRENT_HAVE_D_TYPE
  if (entry->d_type != DT_UNKNOWN) {
    if (entry->d_type != DT_REG)
      return 1;
  }
  else {
#endif /* _DIRENT_HAVE_D_TYPE */
    snprintf(fname, sizeof(fname), "%s/%s", dir, entry->d_name);
    fname[sizeof(fname) - 1]= '\0';

    if (stat(fname, &filestat) != 0) {
      fprintf(stderr, "mailcheck: failed to stat file: %s\n", fname);
      return 1;
    }
    
    if (!S_ISREG(filestat.st_mode))
      return 1;
#ifdef _DIRENT_HAVE_D_TYPE
  }
#endif /* _DIRENT_HAVE_D_TYPE */

  return 0;
}

/* Count files in subdir of maildir (new/cur/tmp). */
int
count_entries (char *path)
{
  DIR *mdir;
  struct dirent *entry;
  int count = 0;

  if ((mdir= opendir(path)) == NULL)
    return -1;

  while ((entry = readdir (mdir))) {
    if (ignore_maildir_entry(path, entry)) 
      continue;
    
    count++;
  }

  closedir(mdir);

  return count;
}

/* Count mails in unix mbox. */
int
check_mbox(const char *path, int *new, int *read, int *unread)
{
  char linebuf[BUF_SIZE];
  FILE *mbox;
  int linelen;
  unsigned short in_header= 0;	/* do we parse mail header or mail body? */

  if ((mbox= fopen(path, "r")) == NULL) {
    fprintf(stderr, "mailcheck: unable to open mbox %s\n", path);
    return -1;
  }

  *new= 0;
  *read= 0;
  *unread= 0;
  
  while (fgets(linebuf, sizeof(linebuf), mbox)) {
    if (!in_header) {
      if (strncmp(linebuf, "From ", 5) == 0) { /* 5 == strlen("From ") */
	in_header= 1;
	(*new)++;
      }
    }
    else {
      if (linebuf[0] == '\n') {
	in_header= 0;
      }
      else if (strncmp(linebuf, "Status: ", 8) == 0) { /* 8 == strlen("Status: ") */
	linelen= strlen(linebuf);
	
	if (linelen >= 10  && 
	    ((linebuf[8] == 'R'  &&  linebuf[9] == 'O')  ||
	     (linebuf[8] == 'O'  &&  linebuf[9] == 'R'))) {
	  (*new)--;
	  (*read)++;
	}
	else if (linelen >= 9  &&  linebuf[8] == 'O') {
	  (*new)--;
	  (*unread)++;
	}
      }
    }
  }

  fclose(mbox);

  return 0;
}

/* Count mails in maildir.  Newer, more sophisticated, but also more time
 * consuming version. */
int
check_maildir(const char *path, int *new, int *read, int *unread) {
  char dir[BUF_SIZE];
  DIR *mdir;
  struct dirent *entry;
  char *pos;

  /* new mail - standard way */
  snprintf(dir, sizeof(dir), "%s/new", path);
  *new= count_entries(dir);
  if (*new == -1)
    return -1;
  
  /* older mail - check also mail status */
  snprintf(dir, sizeof(dir), "%s/cur", path);
  if ((mdir= opendir(dir)) == NULL)
    return -1;

  *read= 0;
  *unread= 0;
  while ((entry = readdir (mdir))) {
    if (ignore_maildir_entry(dir, entry)) 
      continue;

    if ((pos= strchr(entry->d_name, ':')) == NULL) {
      (*unread)++;
    } 
    else if (*(pos + 1) != '2') {
      fprintf(stderr, "mailcheck: ooops, unsupported experimental info "
	  "semantics on %s/%s\n", dir, entry->d_name);
      continue;
    }
    else if (strchr(pos, 'S') == NULL) {
      					/* search for seen ('S') flag */
      (*unread)++;
    }
    else {
      (*read)++;
    }
  }

  closedir(mdir);
  
  return 0;
}


/* Check for mail in given mail path (could be mbox, maildir). */
void
check_for_mail (char *tmppath)
{
  struct stat st;
  char *mailpath;

  /* expand environment variables in path specifier */
  mailpath= expand_envstr (tmppath);
  
  if (!stat (mailpath, &st)) {
    /* Is it regular file? (if yes, it should be mailbox ;) */
    if (S_ISREG (st.st_mode)) {
        int new, read, unread;
        if (check_mbox(mailpath, &new, &read, &unread) == -1)
          return;
	if (new > 0 || unread > 0) {
          printf("%s: %d new and %d unread message(s)\n",
                mailpath, new, unread);
          have_mail= 1;
        }
    }
    /* Is it directory? (if yes, it should be maildir ;) */
    /* for maildir specification, see: http://cr.yp.to/proto/maildir.html */
    else if (S_ISDIR (st.st_mode)) {
	int new, read, unread;

	if (check_maildir(mailpath, &new, &read, &unread) == -1) {
	  fprintf (stderr, 
	      "mailcheck: %s is not a valid maildir -- skipping.\n", mailpath);
	  return;
	}
	if (new > 0 || unread > 0) {
          printf("%s: %d new and %d unread message(s)\n",
                mailpath, new, unread);
          have_mail= 1;
        }
    } else {
      fprintf(stderr, "mailcheck: error, %s is not mbox or maildir\n",
	  mailpath);
      }
  }
  else {
    fprintf(stderr, "mailcheck: invalid line '%s' in rc-file\n", mailpath);
  }
}

/* Process command-line options */
void
process_options (int argc, char *argv[])
{
  int opt;
  
  while ((opt= getopt(argc, argv, "hsf:")) != -1)
    {
      switch (opt)
	{
	case 'h':
	  print_usage();
	  exit(0);
	  break;
	case 's':
	  Options.show_summary= 1;
	  break;
	case 'f':
	  Options.rcfile_path= optarg;
	  break;
	}
    }
}

/* main */
int
main (int argc, char *argv[])
{
  char buf[1024], *ptr;
  FILE *rcfile;

  ptr= getenv ("HOME");
  if (!ptr) {
    fprintf (stderr, "mailcheck: couldn't read environment variable HOME.\n");
    return 1;
  } else {
    Homedir= strdup(ptr);
  }

  process_options (argc, argv);

  rcfile= open_rcfile();

  while (fgets (buf, sizeof (buf), rcfile))
    {
      /* eliminate newline */
      ptr = strchr (buf, '\n');
      if (ptr)
	*ptr = '\0';

      /* If it's not a blank line or comment, look for mail in it */
      if (strlen (buf) && (*buf != '#'))
	check_for_mail (buf);
    }

  if (Options.show_summary  &&  !have_mail) {
      printf("no new mail\n");
    }
  
  fclose(rcfile);
  free(Homedir);

  return 0;
}

/* vim:set ts=8 sw=2: */
