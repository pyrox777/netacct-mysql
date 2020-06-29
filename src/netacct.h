/* 
 * Network accounting
 * netacct.h - header file *
 * (C) 1994 Ulrich Callmeier
 *
 * Modified by Nikolay Hristov and Boril Yonchev
 * to work with mysql database
 * */

/* top src dir autoconf cofig file */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <limits.h>
#include <pcap.h>

#include <pthread.h>
#if defined(_FreeBSD_) || defined(_OpenBSD_)
#include <netinet/in.h>
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>

/* #include <netinet/in_systm.h> */
/* #include <netinet/ip.h> */
#ifdef _LINUX_ 
#include <linux/if_ether.h>
/* #include <linux/tcp.h> */
#else
#define IP_TCP 6
#endif

#include <config.h>
/* change this if you want to change name of mysql table */
/*#define MYSQL_TABLE     "accounting"*/

/* certain features you can disable or enable */
#undef HUMAN_READABLE_TIME
#undef IGNORE_UNENC
#ifdef _LINUX_
#undef TCP_USER_INFO
#endif

/* paths */
#ifndef _PATH_UTMP
#define _PATH_UTMP "/var/run/utmp"
#endif

/* #define DEF_ACCTTAB "/etc/naccttab" */
/* ---- must be moved in autoconf config.h ---- */
/*#define PEERING_FILE "/etc/nacctpeering"*/

#ifdef _LINUX_
#define PID_FILE "/var/run/nacctd.pid"
#else
#define PID_FILE "/etc/nacctd.pid"
#endif

#ifdef TCP_USER_INFO
#define PATH_PROCNET_TCP	"/proc/net/tcp"
#endif

/* default settings for naccttab */
#define DEFAULT_IGNOREMASK "255.255.255.255"
#define DEFAULT_FLUSH 300
#define DEFAULT_ERR_DELAY 4
#define DEFAULT_FDELAY 60

#define FORCE_STAT_TIME 5

  /****************************************/
 /* no user configurable stuff from here */
/****************************************/

#define MAX_INTERFACES 10

#define MIN_DISABLE 2
#define MAX_DISABLE 12

#define DIS_PROTO 2
#define DIS_SRC 3
#define DIS_SRCPORT 4
#define DIS_DST 5
#define DIS_DSTPORT 6
#define DIS_COUNT 7
#define DIS_BYTES 8
#define DIS_DEV 9
#define DIS_USER 10
#define DIS_DUR 11 /* by geroy, disable duration field */
#define DIS_FLAG 12 /* by geroy, disable peering flag field */

#define BITMASK(bit) (1 << ((bit) % (CHAR_BIT*sizeof(int))))

/* parsing of config file */
#define DBG_CONFIG	(1 << 1) 
#define DBG_STATE	(1 << 2)
#define DBG_UTMP	(1 << 3)
#define DBG_DYNAMIC	(1 << 4)
#define DBG_SYSCALL	(1 << 5)
#define DBG_IGNORE	(1 << 6)
#define DBG_MISC	(1 << 7)
#define DBG_STATISTICS	(1 << 8)
#define DBG_SIGNAL	(1 << 9)
#define DBG_ERR		(1 << 10)
#define DBG_DB		(1 << 11)
#define DBG_ANNOYING	(1 << 30)

static char *DBG_TYPE_STRING[31] = {"NONE ", "CONF ", "STATE", "UTMP ", "DYNA ", "SYS  ", "IGN  ", "MISC ", "STATS", "SIG  ", /* 10 */ "ERROR", "DBG_DB", "", "", "", "", "", "", "", "", /* 20 */ "", "", "", "" ,"", "", "", "", "", "", "ANNOY"};

#define DEBUG(level, msg)\
 if((level) & debug_level)\
 {\
  char dbg[255], DBGtmp[255], DBGtype[255]; int DBGi;\
  time_t DBGcurtime = time(NULL);\
  for(DBGi=1; DBGi<=30; DBGi++) if((1 << DBGi) & level) {strcpy(DBGtype, DBG_TYPE_STRING[DBGi]);break;}\
  strftime(DBGtmp, sizeof(DBGtmp), "%d/%m %H:%M:%S ", localtime(&DBGcurtime));\
  msg; fprintf(dbg_file, "%s[%s] %s",DBGtmp,DBGtype,dbg);\
 }

static int write_done=0;
static terminating = 0;
struct ipnetwork
{
     	unsigned long netnumber, netmask;
    	struct ipnetwork *next;
};

struct promisc_device
{
    	char *name; /* name (e.g. eth0) */
    	int reset; /* do we have to reset it on exit ? */
    	struct ifreq oldifr; /* old settings */
    	struct promisc_device *next;
};

/* structure for linked list of ip addresses to monitor - mk */
struct mon_host_struct
{
    	unsigned long ipaddr;
	struct mon_host_struct *next;
}; 

/* enum for supported datase types, rweber */
typedef enum 
{
    	TYPE_MYSQL,
    	TYPE_ORACLE,
    	TYPE_NONE
} dbtype_t;

struct config
{
      	char *filename;
      	char *dumpname;
      	char *debugname;
      	int flush; /* in seconds */
      	int fdelay; /* in seconds */
      	unsigned long int ignoremask;
      	int err_delay; /* how many cycles to delay on error ? */
      	struct ipnetwork *compactnet; /* patch by Boril */
      	struct ipnetwork *ournet; /*patch by Renegade */
      	struct ipnetwork *direct_peer; /*patch by Renegade */
      	struct ipnetwork *ignorenet;
      	struct ipnetwork *dontignore;
      	struct promisc_device *promisc;
      	struct promisc_device *notdev;
      	struct ipnetwork dynamicnet;
      	struct ipnetwork *excludenamelookup;
      	struct headerdat *headers;
      	struct mon_host_struct *hostlist;
      	struct promisc_device *iflist;
      	char *dynamicip;
      	int disabled; /* disabled output fields (for REMOVING) */
      	char *database; /* by geroy, log in mysql or file */
      	dbtype_t dbtype; /* by rweber, supported database backends */
#ifdef HAVE_MYSQL
      	char *mysql_user; /* by geroy, mysql username in config file */
      	char *mysql_password; /* by geroy, mysql password in config file */
      	char *mysql_host; /* by geroy, mysql hostname in config file */
      	char *mysql_database; /* by geroy, mysql database in config file */
      	char *mysql_table; /* by kad, mysql table in config file */ 
      	unsigned int mysql_port; /* mysql port in config file */ 
#endif
#ifdef HAVE_ORACLE
      	char *oracle_connect; /* by rweber, oracle connect string */
      	char *oracle_home; /* by rweber, oracle home */
#endif
      	unsigned int sniff; /* promisc mode yes/no */
      	char *pid_file; /* by kad, pid file in config file */
};

/* struct for peering IP's (geroy) */
struct peering
{
      	char *perringfile;
      	struct ipnetwork *peering_addr;
};

struct dev2line
{
    	char *netinterface;
    	char *line;
    	struct dev2line *next;
};

struct dynadat
{
    	char *netinterface;
    	unsigned long addr;
	time_t last_stat, mtime;
    	char *user;
	struct dynadat *next;
};

struct headerdat
{
      	char *name;
      	int l;
      	int offset;
      	int type;

      	struct headerdat *next;
};

struct statistics
{
    	unsigned long int unenc;
    	unsigned long int notdev;
    	unsigned long int ignored, netignored, local, ip, dropped;/*sum=total*/
    	unsigned long int ournet, direct_peer;
    	unsigned long int ip_udp, ip_tcp, ip_icmp, ip_other; /*sum=ip*/
};

struct ipdata
{
	unsigned long int src, dst;
    	unsigned char proto;
    	unsigned short srcport, dstport;
    	unsigned long int bytes;
	unsigned count;
    	char *devname;
	char *user;
    	time_t when;
	time_t when_start; /* by kad, duration */
    	struct ipdata *next;
};

extern char *rcs_revision_config_c;
extern char *rcs_revision_daemon_c;
extern char *rcs_revision_capture_c;
extern char *rcs_revision_main_c;

extern char *progname;
extern struct config *cfg;
extern struct peering *pcfg; /* peering file struct (geroy) */
extern FILE *dbg_file;
extern volatile int debug_level;
extern struct dev2line *dev2line;

extern volatile int running;
extern struct statistics *packets;

extern volatile time_t now; /* current time */

extern char *fname;
extern char *pname;

/* capture.c */
void init_capture(void);
void do_acct(void);
void exit_capture(void);
void *packet_loop(void *threadid);

#ifdef TCP_USER_INFO
int get_tcp_info(struct ipdata *ip, uid_t *uid);
#endif

/* process.c */
void register_packet(unsigned long int src,unsigned long int dst, int size, char *devname);
void write_log(int force);
void alarm_handler(int sig);
void child_finished(int sig);
void signal_debug(int sig);
void signal_ignore(int sig);

/* daemon.c */
int daemon_start(void);
void daemon_stop(int sig);

/* config.c */
struct config *read_config(char *fname);
struct peering *read_peering(char *fname); /* peering struct (geroy) */

/* utils.c */
char *ip_proto_name(unsigned char proto);
char *intoa(unsigned long addr);
char * etheraddr_string(unsigned char *ep);

/* collect.c */
typedef unsigned long int IP_TYPE;              /* IP address type */
typedef unsigned long int TRAFFIC_TYPE;         /* type for traffic data size */

/* Data for one host */
static struct HOST_DATA
{
	IP_TYPE         ipAddress;
	TRAFFIC_TYPE    nInTrafic;              /* in traffic in bytes */
	TRAFFIC_TYPE    nOutTrafic;             /* out traffic in bytes */
	int             nPeerFlag;              /* Peering flag */
} HOST_DATA;

static struct HOST_DATA_ITEM
{
	struct HOST_DATA*       m_pHostData;
	struct HOST_DATA_ITEM*  m_pNextItem;
} HOST_DATA_ITEM;

/* root host info item structure */
static struct HOST_DATA_ITEM* sg_pRootHostData = NULL;
static struct HOST_DATA_ITEM* s_pCurrentHostData = NULL;

/* capture.c - threads and interfaces */
pcap_t *pds[MAX_INTERFACES]; /* array of packet descriptors per interface */

pthread_mutex_t pt_lock;
pthread_t pt[MAX_INTERFACES];
static int interface_number = 0;

extern struct HOST_DATA* GetFirstHost();
extern struct HOST_DATA* GetNextHostData();
