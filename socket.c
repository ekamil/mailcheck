/* Copyright (C) 1998 Trent Piepho  <xyzzy@u.washington.edu>
 *           (C) 1999 Trent Piepho  <xyzzy@speakeasy.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.  */
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>


int
sock_connect (char *hostname, int port)
{
  struct hostent *host;
  struct sockaddr_in addr;
  int fd, i;

  host = gethostbyname (hostname);
  if (host == NULL)
    {
      herror ("gethostbyname");
      return (-1);
    };

  fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1)
    {
      perror ("Error opening socket");
      return (-1);
    };

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = *(u_long *) host->h_addr_list[0];
  addr.sin_port = htons (port);
  i = connect (fd, (struct sockaddr *) &addr, sizeof (struct sockaddr));
  if (i == -1)
    {
      perror ("Error connecting");
      close (fd);
      return (-1);
    };
  return (fd);
}

/* vim:set ts=4: */
