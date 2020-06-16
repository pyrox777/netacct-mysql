/* 
 * Network accounting
 * utils.c - utility routines *
 * (C) 1994 Ulrich Callmeier
 */

#include <stdio.h>
#include <stdlib.h>
#include "netacct.h"

/* converts integer IP address taken from packet into 
 * x.x.x.x style */
char *intoa(unsigned long addr)
{
	static char buff[18];
	char *p;

	p = (char *) &addr;
	sprintf(buff, "%d.%d.%d.%d",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
	return(buff);
}

static char hex[] = "0123456789abcdef";

/* MAC address conversion (not used for the moment) */
char * etheraddr_string(unsigned char *ep)
{
	unsigned int i, j;
	char *cp, *s;
        
	s = cp = (char *)malloc(sizeof("00:00:00:00:00:00"));

	if ((j = *ep >> 4) != 0)
		*cp++ = hex[j];
		*cp++ = hex[*ep++ & 0xf];
	for (i = 5; (int)--i >= 0;) {
		*cp++ = ':';
		if ((j = *ep >> 4) != 0)
			*cp++ = hex[j];
		*cp++ = hex[*ep++ & 0xf];
	}
	*cp = '\0';
	return (s);
}

/* returns protocol type */
char *ip_proto_name(unsigned char proto)
{
	switch(proto)
	{
		case IPPROTO_ICMP: 
			return "ICMP";
		case IPPROTO_TCP: 
			return "TCP";
		case IPPROTO_UDP: 
			return "UDP";
	}
	return "?";
}
