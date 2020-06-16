/* 
 * Network accounting
 * capture.c - capture raw packets - pcap version
 * (C) 1996 Ulrich Callmeier
 * rewritten experimental pcap interface to netacct
 * to work with linux, bsd ... 
 * geroy
 * added missing ntohs() to srcport, dstport
 * fix to listen to more than 1 interface .. some ideas taken
 * from snort/ntop source
 */

#include "netacct.h"

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#ifdef _Solaris_
/*#include <net/if.h>*/
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_var.h>
#include <netinet/tcpip.h>
#endif

#if defined(_OpenBSD_) || defined(_NetBSD_)
#include <net/ethertypes.h>
#else
#include <net/ethernet.h>
#endif

#if defined(_FreeBSD_) || defined(_OpenBSD_) || defined(_NetBSD_) 
#include <machine/param.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif


#ifdef _OpenBSD_
#include <netinet/if_ether.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_ip(unsigned char buf[], char *devname, char *user);
int *taskids[MAX_INTERFACES]; /* max interfaces (each interface - thread) */
char perrbuff[PCAP_ERRBUF_SIZE];
/* we need header so can determine type and data lenght transmitted in
 * this packet 
 * MEDIA_TYPE_HEADER + (IP_HEADER || IPX_HEADER || SOMETHING_HEADER)
 * example: (ethernet_header + ip_header) we seek in ip_header for tcp/udp/icmp
 * header and then how many bytes are passed */
#define PCAP_SNAPLEN 128
#define PCAP_TMOUT 1000

void handle_frame (unsigned char[], int);

/* prepare interfaces */
void init_capture()
{
	struct promisc_device *p;
	p = cfg -> promisc;
	/* open interfaces via pcap_open_live() */	
	while(p!=NULL) {

		pds[interface_number] = pcap_open_live(p -> name,
							PCAP_SNAPLEN, cfg->sniff, PCAP_TMOUT, perrbuff);

		if(pds[interface_number] == NULL) {
			syslog(LOG_ERR, "can't pcap_open_live: %s\n", perrbuff);
			daemon_stop(0);
		}
			
		interface_number++;
		p = p -> next; /* next interface to listen */
	}
	DEBUG(DBG_MISC, sprintf(dbg, "device %s added\n", p -> name));
}

/* close all promisc interfaces 
 * NEED TO FIX THIS: phtrads problem 
 * pass argument to threads if need to pthread_exit() */
void exit_capture(void)
{
	int i = 0;

	terminating = 1;
	while(pds[i] != NULL) {
		pcap_close(pds[i]);
		i++;
	}
}

inline int onnet(unsigned long int addr, struct ipnetwork *net)
{
	return ((addr & net -> netmask) == net -> netnumber);
}

/* returns 1 if given ip address is in netlist scruct */
int onnetlist(unsigned long int addr, struct ipnetwork *netlist)
{
	while(netlist!=NULL)
	{
		if(onnet(addr, netlist))
		{
			return 1;
		}
		netlist = netlist -> next;
	}
	return 0;
}

/* process single packet. need to lock pthreads until packet is processed 
 * then unlock it */
void do_packet(u_char *usr, const struct pcap_pkthdr *h, const u_char *p)
{
	pthread_mutex_lock(&pt_lock);
	handle_frame((char *)p, h->len);
	pthread_mutex_unlock(&pt_lock);
}

/* Here goes explanation for using select() on BSD, it is from 
 * ethereal source code.
 * 
 * We don't want to do a "select()" on the pcap_t's file descriptor on
 * BSD (because "select()" doesn't work correctly on BPF devices on at
 * least some releases of some flavors of BSD) */
void *packet_loop(void *threadid)
{
	int *id_ptr, taskid;
	fd_set readmask;
	int pcap_fd;

	id_ptr = (int *) threadid;
	taskid = *id_ptr;

	/* BIG MESS HERE .. net to add proper #ifdef for varius OS 
	* like Solaris?!, NetBSD?! don;t know .. also this will never
	* work with win32 because select() is something completly 
	* different! */
	pcap_fd = pcap_fileno(pds[taskid]);
 
	/* infinite cycle and catch one packet with pcap_dispatch()
	 * otherwise capturing will be blocked to other threads */
	while(1) {
#if !defined(_FreeBSD_) && !defined(_OpenBSD_)
		FD_ZERO(&readmask);
		FD_SET(pcap_fd, &readmask);
		if(select(pcap_fd+1, &readmask, NULL, NULL, NULL)>0) {
#endif
			if(pcap_dispatch(pds[taskid], 1, do_packet, NULL) < 0) {
				syslog(LOG_ERR, "pcap_dispatch: %s\n", pcap_geterr(pds[taskid]));
				daemon_stop(0);
			}
#if !defined(_FreeBSD_) && !defined(_OpenBSD_)
		}
#endif
	}
}

/* real analysis of packet */
void handle_frame (unsigned char buf[], int length)
{
	static struct ip tmp_iphdr;
	unsigned short srcport, dstport;
	struct tcphdr tmp_tcphdr;
	struct udphdr tmp_udphdr;
	struct icmp tmp_icmphdr;
	int found = 0, offset = -1;
	struct mon_host_struct *ptr;

	/* NEED TO FIX THIS: proper handle of PPP/SLIP/PPPoE and such 
	 * header offests (from cfg file 'headers') */
	if(buf[12] * 256 + buf[13] == ETHERTYPE_IP)	{
		/* ETHERNET offset - 14 */
		offset = 14;
	} else if(buf[14] * 256 + buf[15] == ETHERTYPE_IP) {
			/* PPTP offset (ppp interface) - 16 */
			offset = 16;
	}
					
	/* if there is ETHERNET header found in package .. process it */
	if(offset != -1) {
		memcpy (&tmp_iphdr, &(buf[offset]), sizeof (tmp_iphdr));
					
		found = 0;
		if(cfg->hostlist) { 
			/* we specified at least one hostlimit tag */
			/* if we don't monitor this IP, bail now - mk */
			for(ptr=cfg->hostlist;ptr && !found;ptr=ptr->next) {
				if(ptr->ipaddr == tmp_iphdr.ip_src.s_addr
				|| ptr->ipaddr == tmp_iphdr.ip_dst.s_addr)
					found = 1;
				if(!found) {
					packets->ignored++;
					continue;
				}
			}
		}
	
		/* if packet matches with ignoremask then don't count it */
		if((tmp_iphdr.ip_src.s_addr & cfg->ignoremask) ==(tmp_iphdr.ip_dst.s_addr & cfg->ignoremask))	{
			packets->local++;
			return;
		}	else {
		/* if packet matches ignoremask and ignorenet options ->
		 * just do nothing */
			if(onnetlist(tmp_iphdr.ip_src.s_addr,cfg->ignorenet) ||
			onnetlist(tmp_iphdr.ip_dst.s_addr, cfg->ignorenet)) {
				if(!(onnetlist(tmp_iphdr.ip_src.s_addr,cfg->dontignore) || onnetlist(tmp_iphdr.ip_dst.s_addr, cfg->dontignore))) {
					if(debug_level & DBG_IGNORE) {
						char tmp[18];
						strcpy(tmp, intoa(tmp_iphdr.ip_src.s_addr));
						DEBUG(DBG_IGNORE, sprintf(dbg, "netignored: %s -> %s\n", tmp,intoa(tmp_iphdr.ip_dst.s_addr)));
					}
					packets->netignored++;
					return;
				}
			}
			packets->ip++;
	 
			/* check which IP protocol we've got 
			 * if we match something copy it header for further
			 * investigation */
			switch(tmp_iphdr.ip_p) {  
				case IPPROTO_UDP:
					packets->ip_udp++;
					memcpy (&tmp_udphdr, &buf[offset + tmp_iphdr.ip_hl * 4], sizeof (tmp_udphdr));
					break;
				case IPPROTO_TCP:
					packets->ip_tcp++;
					memcpy (&tmp_tcphdr, &buf[offset + tmp_iphdr.ip_hl * 4], sizeof (tmp_tcphdr));
					break;
				case IPPROTO_ICMP:
					packets->ip_icmp++;
					memcpy (&tmp_icmphdr, &buf[offset + tmp_iphdr.ip_hl * 4], sizeof (tmp_icmphdr));
					srcport = tmp_icmphdr.icmp_type;
					dstport = tmp_icmphdr.icmp_code;
					break;
				default:
					packets->ip_other++;
					srcport = dstport = 0;
					break;
			}

			/* and call function to count traffic */
			register_packet(tmp_iphdr.ip_src.s_addr,tmp_iphdr.ip_dst.s_addr, ntohs(tmp_iphdr.ip_len), cfg->promisc->name);
		}
	} else {
		/* MUST FIX THIS TO SUPPORT PPP/SLIP/PPPoE .. etc */
		/* ETH_P_ARP, ETH_P_RARP, ETH_P_IPX, etc. 
		 * in the moment all other packets except TCP/UDP/ICMP
		 * are ignored */
		packets -> ignored ++;
	}
}
