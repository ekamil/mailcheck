/* mailcheck.c
 *
 * Copyright 1996, 1997, 1998, 2001 Jefferson E. Noxon <jeff@planetfall.com>
 *
 * This file may be copied under the terms of the GNU Public License
 * version 2, incorporated herein by reference.
 */

/* Command line parameters:
 * -l: login mode; program exits quietly if ~/.hushlogin exists.
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

extern int sock_connect (char *hostname, int port);

/* Global variables */
char *Homedir;			/* Home directory pathname */
int Login_mode;			/* TRUE if the '-l' switch is set */

#define BUF_SIZE (2048)

/* Open an rc file.  Return NULL if we can't find one. */
FILE *
open_rcfile (void)
{
  char namebuf[256];

  snprintf (namebuf, sizeof (namebuf), "%s/.mailcheckrc", Homedir);
  if (!access (namebuf, R_OK))
    return fopen (namebuf, "r");

  return fopen ("/etc/mailcheckrc", "r");
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

int
count_entries (char *path)
{
  DIR *mdir;
  struct dirent *entry;
  int count = 0;

  mdir = opendir (path);
  if (!mdir)
    return -1;

  while ((entry = readdir (mdir)))
    ++count;

  return count - 2;
}


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
  p = strchr (h, '@');
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
      fprintf (stderr, "mailcheck: Error Receiving Stats '%s@%s:%d'\n",
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
      fprintf (stderr, "mailcheck: Error Receiving Stats '%s@%s:%d'\n",
	       user, hostname, port);
      return 1;
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
      fprintf (stderr, "mailcheck: Unable to get login information for %s\n", path);
      return 1;
    }

  if ((fd = sock_connect (hostname, port)) == -1)
    {
      fprintf (stderr, "mailcheck: Not Connected To Server '%s:%d'\n", hostname, port);
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


void
check_for_mail (char *tmppath)
{
  struct stat st;
  char *mailpath = expand_envstr (tmppath);
  char maildir[BUF_SIZE];
  int new = 0, cur = 0;
  int retval = 1;

  if (!stat (mailpath, &st))
    {
      /* Is it a maildir? */
      if (S_ISDIR (st.st_mode))
	{
	  sprintf (maildir, "%s/cur", mailpath);
	  cur = count_entries (maildir);
	  sprintf (maildir, "%s/new", mailpath);
	  new = count_entries (maildir);

	  if ((cur < 0) || (new < 0))
	    {
	      fprintf (stderr,
		       "mailcheck: %s is not a valid maildir -- skipping.\n",
		       mailpath);
	      return;
	    }

	  if (cur && new)
	    {
	      printf ("You have %d new and %d saved messages in %s\n",
		      new, cur, mailpath);
	      return;
	    }

	  if (cur)
	    {
	      printf ("You have %d saved messages in %s\n", cur, mailpath);
	      return;
	    }

	  if (new)
	    {
	      printf ("You have %d new messages in %s\n", new, mailpath);
	      return;
	    }

	}

      /* It's an mbox. */
      else if (st.st_size != 0)
	printf ("You have %smail in %s\n",
		(st.st_mtime > st.st_atime) ? "new " : "", mailpath);
    }
  else
    {
      /* Is it POP3 or IMAP? */
      if (!strncmp (mailpath, "pop3:", 5))
	retval = check_pop3 (mailpath, &new, &cur);
      else if (!strncmp (mailpath, "imap:", 5))
	retval = check_imap (mailpath, &new, &cur);

      if (!retval)
	{
	  if (cur && new)
	    printf ("You have %d new and %d saved messages in %s\n",
		    new, cur, mailpath);
	  else if (cur)
	    printf ("You have %d saved messages in %s\n", cur, mailpath);
	  else if (new)
	    printf ("You have %d new messages in %s\n", new, mailpath);
	}
    }

}

/* Process command-line options */
void
process_options (int argc, char *argv[])
{
  int result;

  while (1)
    {
      result = getopt (argc, argv, "l");

      switch (result)
	{
	case EOF:
	  return;
	case 'l':
	  Login_mode = 1;
	  break;
	}
    }
}

int
main (int argc, char *argv[])
{
  char buf[1024], *ptr;
  FILE *rcfile;
  struct stat st;

  Homedir = getenv ("HOME");
  if (!Homedir)
    {
      fprintf (stderr, "%s: couldn't read environment variable HOME.\n",
	       argv[0]);
      return 1;
    }

  process_options (argc, argv);

  if (Login_mode)
    {
      /* If we can stat .hushlogin successfully, we should exit. */
      snprintf (buf, sizeof (buf), "%s/.hushlogin", Homedir);
      if (!stat (buf, &st))
	return 0;
    }

  rcfile = open_rcfile ();
  if (!rcfile)
    {
      fprintf (stderr, "%s: couldn't open /etc/mailcheckrc "
	       "or %s/.mailcheckrc.\n", argv[0], Homedir);
      return 1;
    }

  while (fgets (buf, sizeof (buf), rcfile))
    {
      /* eliminate newline */
      ptr = strchr (buf, '\n');
      if (ptr)
	*ptr = 0;

      /* If it's not a blank line or comment, look for mail in it */
      if (strlen (buf) && (*buf != '#'))
	check_for_mail (buf);
    }

  return 0;
}
