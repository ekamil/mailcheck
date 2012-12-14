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
 * -l: login mode; program exits quietly if ~/.hushlogin exists.
 * -b: brief mode; less verbose output mode
 * -c: use more advanced counting method
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>

#include "netrc.h"

#define BUF_SIZE (2048)

extern int sock_connect (char *hostname, int port);


/* Global variables */
char *Homedir;			/* Home directory pathname */
unsigned short have_mail= 0;	/* Any mail found? */
struct {
  unsigned short login_mode;		/* see '-l' option */
  unsigned short brief_mode;		/* see '-b' option */
  unsigned short advanced_count;	/* see '-c' option */
  unsigned short show_summary;		/* see '-s' option */
  char *rcfile_path;			/* see '-f' option */
} Options= {0, 0, 0, 0, NULL};
  

/* Print usage information. */
void 
print_usage(void)
{
  printf("Usage: mailcheck [-bchls] [-f rcfile]\n"
         "\n"
         "Options:\n"
         "  -b  - brief output mode\n"
         "  -c  - use more advanced counting method for mboxes and maildirs\n"
         "  -l  - login mode, honor ~/.hushlogin file\n"
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

/* Get password for given account on given host from ~/.netrc file. */
char *
getpw (char *host, char *account)
{
  char file[256];
  struct stat sb;
  netrc_entry *head, *a;

  snprintf (file, sizeof (file), "%s/.netrc", Homedir);

  if (stat (file, &sb))
    return 0;

  if (sb.st_mode & 077)
    {
      static int issued_warning = 0;

      if (!issued_warning++)
	fprintf (stderr,
		 "mailcheck: WARNING! %s may be readable by other users.\n"
		 "mailcheck: Type \"chmod 0600 %s\" to correct the permissions.\n",
		 file, file);
    }

  head = parse_netrc (file);
  if (!head)
    {
      static int issued_warning = 0;

      if (!issued_warning++)
	fprintf (stderr,
		 "mailcheck: WARNING! %s could not be read.\n", file);
      return 0;
    }

  if (host && account)
    {
      a = search_netrc (head, host, account);
      if (a && a->password)
	return (a->password);
    }
  return 0;
}

/* returns port number, or zero on error */
/* returns hostname, box, user, and pass through pointers */
int
getnetinfo (const char *path,
	    char *hostname, char *box, char *user, char *pass)
{
  char buf[BUF_SIZE];
  int port = 0;
  char *p, *q, *h, *proto;

  strncpy (buf, path, BUF_SIZE - 1);
  /* first separate "protocol:" part */
  p = strchr (buf, ':');
  if (!p)
    return (0);
  *p = '\0';
  proto = buf;
  h = p + 1;
  if (!strcmp (proto, "pop3"))
    port = 110;
  else if (!strcmp (proto, "imap"))
    port = 143;
  /* handle "pop3://hostname" form */
  while (*h == '/')
    h++;
  /* change "hostname/" or "hostname/something" to "hostname" */
  p = strchr (h, '/');
  if (p)
    {
      *p = '\0';
      p++;
      if (*p != '\0')
	strncpy (box, p, BUF_SIZE - 1);
      else
	strcpy (box, "INBOX");
    }
  else
    strcpy (box, "INBOX");
  /* determine username -- look for user@hostname, else use USER */
  p = strrchr (h, '@');
  if (p)
    {
      *p = '\0';
      p++;
      q = h;
      h = p;
    }
  else
    {
      /* default to getenv("USER") */
      q = getenv ("USER");
      if (!q)
	return (0);
    }
  strncpy (user, q, 127);
  /* check for port specification */
  p = strchr (h, ':');
  if (p)
    {
      *p = '\0';
      p++;
      if (isdigit (*p))
	{
	  int n = atoi (p);
	  if (n > 0)
	    port = n;
	}
    }
  strncpy (hostname, h, 127);

  /* get password for this hostname and username from $HOME/.netrc */
  p = getpw (hostname, user);
  if (p)
    strncpy (pass, p, 127);

  return (port);
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

/* Count mails in maildir.  Slightely modified original Jeff's version.  Just
 * counts files in maildir/new and maildir/cur. */
int
check_maildir_old(const char *path, int *new, int *cur)
{
  char dir[BUF_SIZE];

  snprintf(dir, sizeof(dir), "%s/new", path);
  *new= count_entries(dir);
  snprintf(dir, sizeof(dir), "%s/cur", path);
  *cur= count_entries(dir);
  
  if (*new == -1  ||  *cur == -1)
    return -1;
  else
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
  
/* Count mails in pop3 mailbox. */
int
check_pop3 (char *path, int *new_p, int *cur_p)
{
  int port;
  int fd;
  FILE *fp;
  char buf[BUF_SIZE];
  char hostname[BUF_SIZE];
  char box[BUF_SIZE];		/* not actually used for pop3 */
  char user[128];
  char pass[128];
  int total = 0;

  port = getnetinfo (path, hostname, box, user, pass);

  /* connect to host */
  if ((fd = sock_connect (hostname, port)) == -1)
    return 1;
  fp = fdopen (fd, "r+");
  fgets (buf, BUF_SIZE, fp);
  fflush (fp);
  fprintf (fp, "USER %s\r\n", user);
  fflush (fp);
  fgets (buf, BUF_SIZE, fp);
  if (buf[0] != '+')
    {
      fprintf (stderr, "mailcheck: Invalid User Name '%s@%s:%d'\n",
	       user, hostname, port);
#ifdef DEBUG_POP3
      fprintf (stderr, "%s\n", buf);
#endif
      fprintf (fp, "QUIT\r\n");
      fclose (fp);
      return 1;
    };

  fflush (fp);
  fprintf (fp, "PASS %s\r\n", pass);
  fflush (fp);
  fgets (buf, BUF_SIZE, fp);
  if (buf[0] != '+')
    {
      fprintf (stderr, "mailcheck: Incorrect Password for user '%s@%s:%d'\n",
	       user, hostname, port);
      fprintf (stderr, "mailcheck: Server said %s", buf);
      fprintf (fp, "QUIT\r\n");
      fclose (fp);
      return 1;
    };

  fflush (fp);
  fprintf (fp, "STAT\r\n");
  fflush (fp);
  fgets (buf, BUF_SIZE, fp);
  if (buf[0] != '+')
    {
      fprintf (stderr, "mailcheck: Error Receiving STAT '%s@%s:%d'\n",
	       user, hostname, port);
      return 1;
    }
  else
    {
      sscanf (buf, "+OK %d", &total);
    }

  fflush (fp);
  fprintf (fp, "LAST\r\n");
  fflush (fp);
  fgets (buf, BUF_SIZE, fp);
  if (buf[0] != '+')
    {
      /* Server does not support LAST. Assume total as new */
      *new_p = total;
      *cur_p = 0;
    }
  else
    {
      sscanf (buf, "+OK %d", cur_p);
      *new_p = total - *cur_p;
    }

  fprintf (fp, "QUIT\r\n");
  fclose (fp);

  return 0;
}

/* Count mails in imap mailbox. */
int
check_imap (char *path, int *new_p, int *cur_p)
{
  int port;
  int fd;
  FILE *fp;
  char buf[BUF_SIZE];
  char hostname[BUF_SIZE];
  char box[BUF_SIZE];
  char user[128];
  char pass[128];
  int total = 0;

  port = getnetinfo (path, hostname, box, user, pass);
  if (port == 0)
    {
      fprintf (stderr, "mailcheck: Unable to get login information for %s\n",
	  path);
      return 1;
    }

  if ((fd = sock_connect (hostname, port)) == -1)
    {
      fprintf (stderr, "mailcheck: Not Connected To Server '%s:%d'\n",
	  hostname, port);
      return 1;
    }

  fp = fdopen (fd, "r+");
  fgets (buf, BUF_SIZE, fp);

  /* Login to the server */
  fflush (fp);
  fprintf (fp, "a001 LOGIN %s %s\r\n", user, pass);

  /* Ensure that the buffer is not an informational line */
  do
    {
      fflush (fp);
      fgets (buf, BUF_SIZE, fp);
    }
  while (buf[0] == '*');

  if (buf[5] != 'O')
    {				/* Looking for "a001 OK" */
      fprintf (fp, "a002 LOGOUT\r\n");
      fclose (fp);
      fprintf (stderr, "mailcheck: Unable to check IMAP mailbox '%s@%s:%d'\n",
	       user, hostname, port);
      fprintf (stderr, "mailcheck: Server said %s", buf);
      return 1;
    };

  fflush (fp);
  fprintf (fp, "a003 STATUS %s (MESSAGES UNSEEN)\r\n", box);
  fflush (fp);
  fgets (buf, BUF_SIZE, fp);
  if (buf[0] != '*')
    {				/* Looking for "* STATUS ..." */
      fprintf (stderr, "mailcheck: Error Receiving Stats '%s@%s:%d'\n\t%s\n",
	       user, hostname, port, buf);
      fclose (fp);
      return 1;
    }
  else
    {
      sscanf (buf, "* STATUS %*s (MESSAGES %d UNSEEN %d)", &total, new_p);
#ifdef DEBUG_IMAP4
      fprintf (stderr, "[%s:%d] %s", __FILE__, __LINE__, buf);
#endif
      fgets (buf, BUF_SIZE, fp);
#ifdef DEBUG_IMAP4
      fprintf (stderr, "[%s:%d] %s", __FILE__, __LINE__, buf);
#endif
      *cur_p = total - *new_p;
    }

  fflush (fp);

  fprintf (fp, "a004 LOGOUT\r\n");
  fclose (fp);

  return 0;
}

/* Check for mail in given mail path (could be mbox, maildir, pop3 or imap). */
void
check_for_mail (char *tmppath)
{
  struct stat st;
  char *mailpath;
  int brief_name_offset= 0;

  /* expand environment variables in path specifier */
  mailpath= expand_envstr (tmppath);
  
  /* in brief mode, print relative paths for mailboxes/maildirs inside home
   * directory */
  if (Options.brief_mode  &&  
      strncmp(mailpath, Homedir, strlen(Homedir)) == 0) {
    brief_name_offset= strlen(Homedir) + 1;
  }

  if (!stat (mailpath, &st)) {
    /* Is it regular file? (if yes, it should be mailbox ;) */
    if (S_ISREG (st.st_mode)) {
      /* Use advanced counting? */
      if (!Options.advanced_count) {
	if (st.st_size != 0) {
	  if (!Options.brief_mode) {
	    printf ("You have %smail in %s\n",
		(st.st_mtime > st.st_atime) ? "new " : "", mailpath);
	  } else {
	    printf ("%s: %smail message(s)\n", mailpath + brief_name_offset,
		(st.st_mtime > st.st_atime) ? "new " : "contains saved ");
	  }
	  have_mail= 1;
	}
      } else { /* advanced count */
	int new, read, unread;
	if (check_mbox(mailpath, &new, &read, &unread) == -1)
	  return;

	if (!Options.brief_mode) {
	  if (new > 0  &&  unread > 0) {
	    printf("You have %d new and %d unread messages in %s\n",
		new, unread, mailpath);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf("You have %d new messages in %s\n",
		new, mailpath);
	    have_mail= 1;
	  } else if (unread > 0) {
	    printf("You have %d unread messages in %s\n",
		unread, mailpath);
	    have_mail= 1;
	  }
	}
	else {
	  if (new > 0  &&  unread > 0) {
	    printf("%s: %d new and %d unread message(s)\n",
		mailpath + brief_name_offset, new, unread);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf("%s: %d new message(s)\n",
		mailpath + brief_name_offset, new);
	    have_mail= 1;
	  } else if (unread > 0) {
	    printf("%s: no new mail, %d unread message(s)\n",
		mailpath + brief_name_offset, unread);
	    have_mail= 1;
	  }
	}
      }
    }

    /* Is it directory? (if yes, it should be maildir ;) */
    /* for maildir specification, see: http://cr.yp.to/proto/maildir.html */
    else if (S_ISDIR (st.st_mode)) {
      if (!Options.advanced_count) { /* use old counting method */
	int new, cur;

	if (check_maildir_old(mailpath, &new, &cur) == -1) {
	  fprintf (stderr, 
	      "mailcheck: %s is not a valid maildir -- skipping.\n", mailpath);
	  return;
	}
	
	if (!Options.brief_mode) { /* traditional output */
	  if (cur > 0  &&  new > 0) {
	    printf ("You have %d new and %d saved messages in %s\n",
		new, cur, mailpath);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf ("You have %d new messages in %s\n", new, mailpath);
	    have_mail= 1;
	  } else if (cur > 0) {
	    printf ("You have %d saved messages in %s\n", cur, mailpath);
	    have_mail= 1;
	  }
	} else { /* brief output */
	  if (cur > 0  &&  new > 0) {
	    printf ("%s: %d new and %d saved message(s)\n",
		mailpath + brief_name_offset, new, cur);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf ("%s: %d new message(s)\n",
		mailpath + brief_name_offset, new);
	    have_mail= 1;
	  } else if (cur > 0) {
	    printf ("%s: %d saved message(s)\n",
		mailpath + brief_name_offset, cur);
	    have_mail= 1;
	  }
	}
      } 
      else {	/* new counting method */
	int new, read, unread;

	if (check_maildir(mailpath, &new, &read, &unread) == -1) {
	  fprintf (stderr, 
	      "mailcheck: %s is not a valid maildir -- skipping.\n", mailpath);
	  return;
	}
	
	if (!Options.brief_mode) {
	  if (new > 0  &&  unread > 0) {
	    printf("You have %d new and %d unread messages in %s\n",
		new, unread, mailpath);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf("You have %d new messages in %s\n",
		new, mailpath);
	    have_mail= 1;
	  } else if (unread > 0) {
	    printf("You have %d unread messages in %s\n",
		unread, mailpath);
	    have_mail= 1;
	  }
	}
	else {
	  if (new > 0  &&  unread > 0) {
	    printf("%s: %d new and %d unread message(s)\n",
		mailpath + brief_name_offset, new, unread);
	    have_mail= 1;
	  } else if (new > 0) {
	    printf("%s: %d new message(s)\n",
		mailpath + brief_name_offset, new);
	    have_mail= 1;
	  } else if (unread > 0) {
	    printf("%s: no new mail, %d unread message(s)\n",
		mailpath + brief_name_offset, unread);
	    have_mail= 1;
	  }
	}
      }
    } else {
      fprintf(stderr, "mailcheck: error, %s is not mbox or maildir\n",
	  mailpath);
    }
  }
  else if (strncmp(mailpath, "pop3:", 5) == 0  ||
           strncmp(mailpath, "imap:", 5) == 0) {
    int retval= 1;
    int new= 0, cur= 0;
    
    /* Is it POP3 or IMAP? */
    if (!strncmp (mailpath, "pop3:", 5))
      retval = check_pop3 (mailpath, &new, &cur);
    else
      retval = check_imap (mailpath, &new, &cur);

    if (retval)
      return;
    
    if (!Options.brief_mode) { /* traditional output */
      if (cur > 0  &&  new > 0) {
	printf ("You have %d new and %d saved messages in %s\n",
	    new, cur, mailpath);
	have_mail= 1;
      } else if (new > 0) {
	printf ("You have %d new messages in %s\n", new, mailpath);
	have_mail= 1;
      } else if (cur > 0) {
	printf ("You have %d saved messages in %s\n", cur, mailpath);
	have_mail= 1;
      }
    } else { /* brief output */
      if (cur > 0  &&  new > 0) {
	printf ("%s: %d new and %d saved message(s)\n",
	    mailpath + brief_name_offset, new, cur);
	have_mail= 1;
      } else if (new > 0) {
	printf ("%s: %d new message(s)\n",
	    mailpath + brief_name_offset, new);
	have_mail= 1;
      } else if (cur > 0) {
	printf ("%s: %d saved message(s)\n",
	    mailpath + brief_name_offset, cur);
	have_mail= 1;
      }
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
  
  while ((opt= getopt(argc, argv, "bchlsf:")) != -1)
    {
      switch (opt)
	{
	case 'b':
	  Options.brief_mode= 1;
	  break;
	case 'c':
	  Options.advanced_count= 1;
	  break;
	case 'h':
	  print_usage();
	  exit(0);
	  break;
	case 'l':
	  Options.login_mode= 1;
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
  struct stat st;

  ptr= getenv ("HOME");
  if (!ptr) {
    fprintf (stderr, "mailcheck: couldn't read environment variable HOME.\n");
    return 1;
  } else {
    Homedir= strdup(ptr);
  }

  process_options (argc, argv);

  if (Options.login_mode)
    {
      /* If we can stat .hushlogin successfully and it is regular file, we
       * should exit. */
      snprintf (buf, sizeof (buf), "%s/.hushlogin", Homedir);
      if (!stat (buf, &st)  &&  S_ISREG(st.st_mode))
	return 0;
    }

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
    if (Options.brief_mode) {
      printf("no new mail\n");
    }
    else {
      printf("No new mail.\n");
    }
  }
  
  fclose(rcfile);
  free(Homedir);

  return 0;
}

/* vim:set ts=8 sw=2: */

