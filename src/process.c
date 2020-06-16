/* 
 * Network accounting
 * process.c - process packets
 * (C) 1994, 1995 Ulrich Callmeier
 *
 * -----------------------------
 * here goes main stuff.
 * changes are added by so many people so just see AUTHORS
 * file!
 *
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "netacct.h"

#include <stdlib.h>
#include <unistd.h>

#if defined (_LINUX_)
#include <malloc.h>
#endif

#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <utmp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif
#include <syslog.h>

char *rcs_revision_process_c = "$Revision: 1.47 $";

volatile int running;
struct statistics *packets;

int *taskids[MAX_INTERFACES];

static volatile sig_atomic_t lck;
static volatile sig_atomic_t writing;
static volatile sig_atomic_t dumping;

volatile pid_t writepid;
volatile pid_t dumppid;

volatile int may_write;

int err_delay, max_err_delay;

volatile time_t now;

/* statistics */
unsigned int list_compares, list_lookups;

/* NEED TO FIX THIS: does not close correctly phtreads
 * need to close all interfaces, reread config file and then
 * start again new threads*/
void reopen_socket(void)
{
	int save1, save2;
    
	/* critical section .. synchronization and writing */
	save1 = may_write;
	may_write = 0;
	save2 = lck;
	lck = 1;
	/* end */
    
	exit_capture();
	init_capture();

	lck = save2;
	may_write = save1;
}

/* main loop here 
 * create new threads for each interface.. set each thread to 
 * packet_loop() callback and run infinite while(1) until some signal is
 * received. 
 * */
void do_acct()
{
	int i;
	struct promisc_device *p;
	
	p = cfg -> promisc;

	packets = malloc(sizeof(struct statistics));

	/* not enough memory ?! exit! */
	if(!packets) {
		syslog(LOG_ERR,"out of memory");
		daemon_stop(0);
	}

	/* some of these are not needed and may be removed */	
	packets->ignored=packets->netignored=packets->ip=packets->local=0;
	packets->ip_icmp=packets->ip_tcp=packets->ip_udp=packets->ip_other=0;
	packets->notdev = packets->unenc = 0;

	lck = writing = dumping = 0;

	max_err_delay = cfg -> err_delay;
	err_delay = 0;

	list_lookups = list_compares = 0;

	may_write = 1;

	now = time(NULL);

	alarm(1);
	running=1;

	/* creating pthread mutex */
	pthread_mutex_init(&pt_lock, NULL);
 
	/* we start from first interface */	
	interface_number=0;
	/* each interface get its own thread */

	while(p!=NULL) {
		taskids[interface_number] = (int *) malloc(sizeof(int));
		*taskids[interface_number] = interface_number;
		/* create thread and pass interface number as argument */
		if(pthread_create(&pt[interface_number], NULL, packet_loop, taskids[interface_number])<0) {
			syslog(LOG_DEBUG, "pthread_create() failed");
		}
		/* next phtread number for next interface */
		interface_number++;
		/* and here goes next interface */
		p = p -> next;
	}
 
	/* don't exit just loop forever until some signal is received */
	while(1) {
		sleep(10);
	}

}

/*
 * Check which of IP-s is in compact mode
 * Return values:
 * -1 - for destination IP
 *  0 - if no one IP in compact mode
 *  1 - for source IP
 *
 * function written by Boril Yonchev so quoestions/comment goes to
 * <bashbug@users.sourceforge.net>
 * */
int check_source(unsigned long int src,unsigned long int dst)
{
	int src_flag = 0;
	if(onnetlist(src,cfg->compactnet) || onnetlist(dst,cfg->compactnet)) {
		/* check if it is from compactnet networks */
		if(onnetlist(src,cfg->compactnet)) {
			src_flag=1; /* if it is source IP */
		}	else if(onnetlist(dst,cfg->compactnet))	{
				src_flag=-1; /* if it is destination IP */
		}
		/* Else return 0 we don't log this IP */
	}
	return src_flag;
}

/* Check packet to have peering IP 
 * Return:
 * -1 - Don't log this packet
 *  0 - International
 *  1 - Peering
 *  2 - Direct
 *  3 - Local
 *
 * function written by Boril Yonchev so quoestions/comment goes to
 * <bashbug@users.sourceforge.net>
 * */
int check_peering(unsigned long int src_ip,unsigned long int dst_ip)
{
	unsigned long int src;
	unsigned long int dst;
	int peer_flag;
	int src_flag;

	char spek_src[18];
	char spek_dst[18];

	strncpy(spek_src,intoa(src_ip),16);
	strncpy(spek_dst,intoa(dst_ip),16);
      	
	src_flag = check_source(src_ip,dst_ip);
	
	DEBUG(DBG_STATE,sprintf(dbg,"analyzis for src %s, dst %s, src_flg %d",spek_src,spek_dst,src_flag));
      
	switch (src_flag) {
		case 1:
			src=src_ip;
			dst=dst_ip;
			break;
		case -1:
			src=dst_ip;
			dst=src_ip;
			break;
		default:
			return -1;  /* will don't log this packet */
	}
			  
	if(onnetlist(src, cfg->ournet))	{
		if(onnetlist(dst, cfg->ournet)) {
			peer_flag = 3; /* Local traffic */
		} else if(onnetlist(dst, cfg->direct_peer)) {
				peer_flag = 2; /* Direct peer */
			} else if(onnetlist(dst, pcfg->peering_addr) && !onnetlist(dst, cfg->ournet)) {
					peer_flag = 1; /* Peering traffic */
				} 
		else
		peer_flag = 0;
	}
	
		DEBUG(DBG_STATE,sprintf(dbg,", peer_flg %d\n",peer_flag));
		return peer_flag; 
}
 
/* Store accounted data in memory */	
void register_packet(unsigned long int src,unsigned long int dst, int size, char *devname)
{
	int source;
	if(lck==0) {
		source = check_source(src, dst);
		/* if source == 1 - outgoing */
		if(source == 1) {
			add_host_traffic_info(src, 0, size, check_peering(src,dst));
		}
		if(source == -1) {
			add_host_traffic_info(dst, size, 0 , check_peering(src,dst));
		}
	} else {
		/* this packet is not from networks that we count so de just
		* drop this packet and count it as dropped packet */
		packets->dropped++;
	} 
}

/* 
 * this function will be removed it is here only 
 * for testing
 * */
int do_write_list(FILE *f,  struct ipdata *list[])
{
	struct HOST_DATA* tmpData;

	/* find first collected data and write it to file*/
	tmpData = (struct HOST_DATA*) GetFirstHost();
	fprintf(f, "%s\t%li\t%li\t%i\n", intoa(tmpData->ipAddress), tmpData->nInTrafic, tmpData->nOutTrafic, tmpData->nPeerFlag);
	
	/* write rest of collected data utils tmpData == NULL */
	while(tmpData = (struct HOST_DATA*) GetNextHostData()) {
		fprintf(f, "%s\t%li\t%li\t%i\n", intoa(tmpData->ipAddress), tmpData->nInTrafic, tmpData->nOutTrafic, tmpData->nPeerFlag);
	}

	if(fclose(f)<0)	{
		syslog(LOG_DEBUG,"ERROR writing to file\n");
		return 1;
	}
	return 0;
}

static int pfd1[2], pfd2[2];

/* creating pipe so parent - child (writing) proccess
 * can talk each other */
void TELL_WAIT_INIT(void)
{
	if(pipe(pfd1) < 0 || pipe(pfd2) < 0) {
		syslog(LOG_ERR, "pipe error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"pipe error: %s\n", strerror(errno)));
	}
}

/* close created pipes */
void TELL_WAIT_EXIT(void)
{
	if(close(pfd1[0])!=0) {
		syslog(LOG_ERR, "pipe close error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"pipe close error: %s\n", strerror(errno)));
	}

	if(close(pfd1[1])!=0) {
		syslog(LOG_ERR, "pipe close error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"pipe close error: %s\n", strerror(errno)));
	}

	if(close(pfd2[0])!=0)	{
		syslog(LOG_ERR, "pipe close error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"pipe close error: %s\n", strerror(errno)));
	}

	if(close(pfd2[1])!=0)	{
		syslog(LOG_ERR, "pipe close error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"pipe close error: %s\n", strerror(errno)));
	}
}

/* child write to parent 'c' */
void TELL_PARENT(void)
{
	if(write(pfd2[1], "c", 1) != 1) {
		syslog(LOG_ERR, "write error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"write error: %s\n", strerror(errno)));
	}
}

/* read from parent and wait for 'p'*/
void WAIT_PARENT(void)
{
	char c; int n;
again:
	if((n = read(pfd1[0], &c, 1)) != 1) {
		if((n == -1) && (errno == EINTR)) goto again;
		syslog(LOG_ERR, "read error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"read error: %s\n", strerror(errno)));
	}
	
	if(c!='p') {
		syslog(LOG_ERR, "WAIT_PARENT: incorrect data");
		DEBUG(DBG_ERR, sprintf(dbg,"WAIT_PARENT: incorrect data\n"));
	}
}  

/* tell to child proccess 'p' */
void TELL_CHILD(void)
{
	if(write(pfd1[1], "p", 1) != 1) {
		syslog(LOG_ERR, "write error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"write error: %s\n", strerror(errno)));
	}
}

/* wait to receive from child 'c' */
void WAIT_CHILD(void)
{
	char c; int n;
again:
	if((n = read(pfd2[0], &c, 1)) != 1) {
		if((n == -1) && (errno == EINTR)) goto again;
		syslog(LOG_ERR, "read error: %s", strerror(errno));
		DEBUG(DBG_ERR, sprintf(dbg,"read error: %s\n", strerror(errno)));
	}
      	
	if(c!='c') {
		syslog(LOG_ERR, "WAIT_CHILD: incorrect data");
		DEBUG(DBG_ERR, sprintf(dbg,"WAIT_CHILD: incorrect data\n"));
	}
}  

/* write Linked List in sql and then null all traffic in
 * linked list */
int write_list(void)
{
	FILE *f; 
	int i;

	while( (writepid = fork()) < 0) sleep(1);
	if (writepid!=0) return;
    
	/* Here goes the child , fork() new process, sync with parent
	* by sending 'c' to parent and waiting for 'p' */
	TELL_PARENT();
	WAIT_PARENT();
    
	DEBUG(DBG_STATE, sprintf(dbg, "write child: synchronized with parent\n"));
	openlog("nacctd (write)", 0, LOG_DAEMON);
	DEBUG(DBG_STATE, sprintf(dbg, "* write process %d forked\n", (int) getpid()));
	/* actual writing data to database */
	switch (cfg->dbtype) {
#ifdef HAVE_MYSQL
		case TYPE_MYSQL:
			i=do_write_list_mysql();
			break;
#endif
#ifdef HAVE_ORACLE
		case TYPE_ORACLE:
			i=do_write_list_oracle();
		break;
#endif
		default:
			syslog(LOG_ERR, "unimplememented database type");
			break;
	}

	/* this should never happen at all but ..... */
	if(i) {
		syslog(LOG_ERR, "error writing to database");
		exit(1);
	}
    	
	exit(0);
}

/* NEED TO FIX THIS: this maybe is not needed anymore */
void dump_curr_list(void)
{
	FILE *f;
	int i;

	while( (dumppid = fork()) < 0) sleep(1);
	if (dumppid!=0) return;

	TELL_PARENT();
	WAIT_PARENT();

	DEBUG(DBG_STATE, sprintf(dbg, "dump child: synchronized with parent\n"));
	/* Here goes the child */
	openlog("nacctd (dump)", 0, LOG_DAEMON);
	DEBUG(DBG_STATE, sprintf(dbg, "* dump process %d forked\n", (int) getpid()));
	exit(0);
}

/* Reports what is exit status of child process (writing in sql) */
void child_finished(int sig)
{
	int status;
	pid_t pid;

	write_done = 0;
	DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "-> got signal %d, handling\n", sig));

	while((pid = waitpid((pid_t) -1, &status, WNOHANG)) != 0) {
		DEBUG(DBG_SIGNAL, sprintf(dbg, "  waitpid returned %d, status = %d, errno = %d\n", pid, status, errno));

		if(pid == -1) {
			if(errno == ECHILD)
				DEBUG(DBG_SIGNAL, sprintf(dbg, "waitpid: signaled error: %s\n", strerror(errno)));
				break; /* no child processes */
			}
			if((pid == writepid) || (pid == dumppid)) {
				if(WIFEXITED(status)) {
					if(WEXITSTATUS(status)==0) {
						if(pid == writepid)	{
							writing = 0;
							DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set writing to 0\n"));
						}	else {
							dumping = 0;
							DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set dumping to 0\n"));
						}
					}	else {
							syslog(LOG_ERR, "child %d exited with error status %d.\n", pid, WEXITSTATUS(status));
							write_done = 1;
							if(pid == writepid) {
								err_delay = max_err_delay;
								writing = 0;
								DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set writing to 0, setting err_delay\n"));
							}	else {
								dumping = 0;
								DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set dumping to 0, ignored error condition\n"));
							}
						}
					} else {
						syslog(LOG_ERR,	"Huh? Child %d terminated or stopped by signal (%m)\n",	 pid);
						if(pid == writepid) {
							writing = 0;
							DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set writing to 0, ignored return code\n"));
						}	else {
							dumping = 0;
							DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "  set dumping to 0, ignored return code\n"));
						}
					}
				}	else {
					syslog(LOG_ERR, "Huh? Child (%d) returned, but not the one we expected (%d, %d)!\n", (int) pid, writepid, dumppid);
					DEBUG(DBG_STATE, sprintf(dbg, "  unexpected child %d signaled return (writepid = %d, dumppid = %d\n",(int) pid, writepid, dumppid));
				}
				DEBUG(DBG_STATE, sprintf(dbg, "  child %d signaled return\n",(int) pid));
			}
			DEBUG((DBG_SIGNAL | DBG_STATE), sprintf(dbg, "<- got signal %d, done handling\n", sig));
			
			if((write_done == 0) && (err_delay == 0)) {
				//syslog(LOG_DEBUG, "Child exited normally - clearing counters\n");
				clear_counters();
			} 
}

void alarm_handler(int sig)
{
	static time_t last_check = 0;
	static time_t next_write_log = 0;

	DEBUG( ((sig == SIGALRM) ? DBG_ANNOYING : (DBG_SIGNAL | DBG_STATE)), sprintf(dbg, "got signal %d, handling\n", sig));
	
	now++;

	if((now - last_check) > 60)	{
		time_t nnow;

		nnow = time(NULL);
		if(nnow!=now) {
			if((abs(nnow - now) > 2)) {
				DEBUG(DBG_MISC, sprintf(dbg, "internal clock corrected (off by %d seconds)\n",(int) (nnow-now)));
			}
			now = nnow;
		}
		
		last_check = now;
	}

	if(now >= next_write_log) {
		write_log(0);
		next_write_log = now + cfg -> flush;
	}
	
	alarm(1);
}

/* call write_list() from here and after that clear all collected data
 * from memory */
void write_log(int force)
{
	int i, status;

	DEBUG(DBG_STATE, sprintf(dbg, "write_log called\n"));

	if(err_delay!=0) {
		err_delay--;
		syslog(LOG_INFO,"flushing delayed due to error\n");
		DEBUG(DBG_STATE, sprintf(dbg, "flushing delayed due to error\n"));
	}	else if((writing == 0) && (lck == 0) && (may_write == 1)) {
			/* delay if another write cycle is still in progress */
			DEBUG(DBG_STATISTICS, sprintf(dbg, "ignored: %ld netignored: %ld local:%ld ip:%ld unenc:%ld notdev:%ld dropped:%ld\n", packets->ignored, packets->netignored, packets->local, packets->ip, packets->unenc, packets->notdev, packets->dropped));
			DEBUG(DBG_STATISTICS, sprintf(dbg, "udp: %ld tcp:%ld icmp:%ld other:%ld\n", packets->ip_udp, packets->ip_tcp, packets->ip_icmp, packets->ip_other));
			if(list_lookups != 0)	{
				DEBUG(DBG_STATISTICS, sprintf(dbg, "lookups:%d compares:%d compares/lookup:%f\n", list_lookups, list_compares, ((float) list_compares / (float) list_lookups)));
			}

			DEBUG(DBG_STATE, sprintf(dbg, "lck = 1\n"));

			lck = 1; /* can't update the list now */
    
		writing = 1; /* no further writing 'til this is finished */
		lck = 0;
		DEBUG(DBG_STATE, sprintf(dbg, "lck = 0\n"));
		TELL_WAIT_INIT();
		/* this forks off a child to do the actual writing */
		write_list(); 
		TELL_CHILD();
		WAIT_CHILD();
		DEBUG(DBG_STATE, sprintf(dbg, "parent: synchronized with write child\n"));
		TELL_WAIT_EXIT();

		DEBUG(DBG_STATE, sprintf(dbg, "writepid is %d\n", (int) writepid));
		DEBUG(DBG_STATE, sprintf(dbg, "done freeing\n"));
	}	else {
		DEBUG(DBG_STATE, sprintf(dbg, "flushing delayed (writing == %d, lck == %d, may_write == %d)\n",writing,lck,may_write));
	}
}

/* here SIG handle here */
void signal_debug(int sig)
{

	DEBUG(DBG_SIGNAL, sprintf(dbg, "got signal %d, handling\n", sig));
       
	/* if kill -USR1 - increase debug level */	
	if(sig==SIGUSR1) {
		debug_level++;
	}
	/* if kill -USR2 - turn off debugging */
	else if(sig==SIGUSR2) {
		syslog(LOG_DEBUG, "turning off debugging\n");
		debug_level = 0;
	}
	/* print version running nacctd */
	else if(sig==SIGWINCH) {
		syslog(LOG_DEBUG,"nacctd, revisions:\n%s\n%s\n%s\n%s\n", 
		rcs_revision_main_c, rcs_revision_process_c,
		rcs_revision_config_c, rcs_revision_daemon_c);
	}
	/* disable writing in sql via kill -TSTP */
	else if(sig==SIGTSTP) {
		DEBUG(DBG_STATE, sprintf(dbg, "received SIGTSTP\n"));
		may_write = 0;
		syslog(LOG_DEBUG, "Writing to MySQL database DISABLED\n");
	}
	/* enable writing in sql via kill -CONT */
	else if(sig==SIGCONT) {
		DEBUG(DBG_STATE, sprintf(dbg, "received SIGCONT\n"));
		may_write = 1;
		syslog(LOG_DEBUG, "Writing to MySQL database ENABLED\n");
	}
	/* NEED TO FIX THIS: phtreads problem and reopening threads */
	else if(sig==SIGIOT) {
		DEBUG(DBG_STATE, sprintf(dbg, "reopening socket\n"));
		reopen_socket();
	}
	/* NEED TO FIX THIS: reread cfg file and pthreads problem
	* (release all allocated memory for cfg variables and reread
	* config and peer files again) .. NOTE: need to add rereading
	* nacctpeering (free memory and allocate it again) */

	/* and just for now we will reload only nacctpeering networks 
	* via SIGHUP */
	else if(sig == SIGHUP) {
		struct ipnetwork *ip,*ip_next;
		struct promisc_device *pr,*pr_next;
		struct headerdat *h,*h_next;
		struct mon_host_struct *mh,*mh_next;

		struct ipnetwork *peer;
		DEBUG(DBG_STATE, sprintf(dbg, "received SIGHUP, rereading config\n"));

		syslog(LOG_DEBUG,"Reloading PEERING networks ...");

		if(pcfg) {
			for(ip=pcfg->peering_addr;ip;ip=ip_next) {
				ip_next = ip->next;
				free(ip);
			}
			free(pcfg);
			pcfg = read_peering(pname);
		}
		syslog(LOG_DEBUG,"DONE\n");

		/* this need to be rewritten to fit above FIXME: */

		/*
	  	exit_capture();
	  	if(cfg) 
		{
			free(cfg->dumpname);
			free(cfg->debugname);
			for(ip=cfg->ignorenet;ip;ip=ip_next)
		       	{
		    		ip_next = ip->next;
		    		free(ip);
		
			}
			for(ip=cfg->dontignore;ip;ip=ip_next)
		       	{
		    		ip_next = ip->next;
		    		free(ip);
			}
			for(ip=cfg->excludenamelookup;ip;ip=ip_next)
			{
		    		ip_next = ip->next;
		    		free(ip);
			}
			for(pr=cfg->promisc;pr;pr=pr_next) 
			{
		    		pr_next = pr->next;
		    		free(pr);
			}
			for(pr=cfg->notdev;pr;pr=pr_next) 
			{
		    		pr_next = pr->next;
		    		free(pr);
			}
			for(pr=cfg->iflist;pr;pr=pr_next)
		       	{
		    		pr_next = pr->next;
		    		free(pr);
			}
			for(h=cfg->headers;h;h=h_next) 
			{
		    		h_next = h->next;
		    		free(h);
			}
			for(mh=cfg->hostlist;mh;mh=mh_next) 
			{
		    		mh_next = mh->next;
		    		free(mh);
			}
			free(cfg);
	  	}
	  	cfg = read_config(fname);
	  	init_capture();
		*/

	}	else {
		/* this MUST never happen */
		DEBUG(DBG_SIGNAL, sprintf(dbg, "signal_debug received signal %d, this can't happen\n", sig));
		syslog(LOG_INFO,"signal_debug received signal %d, this can't happen\n", sig);
	}
}

/* If we receive signal that we don't catch just ignore it but
 * report this in syslog */
void signal_ignore(int sig)
{
	DEBUG(DBG_SIGNAL, sprintf(dbg, "got signal %d, ignoring\n", sig));
}
