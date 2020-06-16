/* 
 * Network accounting
 * config.c - configuration module
 * (C) 1994 Ulrich Callmeier
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "netacct.h"

char *rcs_revision_config_c = "$Revision: 1.27 $";

/* This routine reads all the configuration from the file fname.
 * On success it returns a non-NULL pointer to a struct config.
 * The parser is kind of a hack but it works. */

struct config *read_config(char *fname)
{
	char buff[1024];
	FILE *f;
	int line=0;
	struct config *cfg = malloc(sizeof(struct config));

	if(cfg == NULL) return cfg;

	cfg -> debugname = NULL;
	cfg -> flush = DEFAULT_FLUSH;
	cfg -> ignoremask = inet_addr(DEFAULT_IGNOREMASK);
	cfg -> err_delay = DEFAULT_ERR_DELAY;
	cfg -> ignorenet = NULL;
	cfg -> dontignore = NULL;
	cfg -> promisc = NULL;
	cfg -> notdev = NULL;
	cfg -> fdelay = DEFAULT_FDELAY;
	cfg -> disabled = 0;
	cfg -> dynamicip = NULL;
	cfg -> excludenamelookup = NULL;
	cfg -> headers = NULL;
	cfg -> hostlist = NULL;
	cfg -> iflist = NULL;
	cfg -> compactnet = NULL;
	cfg -> ournet = NULL;
	cfg -> direct_peer = NULL;
	cfg -> database = NULL;
	cfg -> sniff = 0; /* promisc mode yes/no */
#ifdef HAVE_MYSQL
	/* if mysql_port = 0 using socket - d.sadilek@globalview.de */	
	cfg -> mysql_user = NULL; 
	cfg -> mysql_password = NULL;
	cfg -> mysql_host = NULL;
	cfg -> mysql_database = NULL;
	cfg -> mysql_port = 0; 
#endif
#ifdef HAVE_ORACLE
	cfg->oracle_connect = NULL;
	cfg->oracle_home = NULL;
#endif
	cfg->dbtype = TYPE_NONE;
	cfg -> pid_file; /* by kad, pid file in config file */

	debug_level = 0;
	dev2line = NULL;

	f=fopen(fname,"r");

	if(f == NULL) return NULL;

	while(fgets(buff,sizeof(buff),f))	{
		/* remove trailing newline */
		char *cmt = strchr(buff,'\n');
		if(cmt) *cmt = '\0';
		line++;
		/* remove comments */
		cmt = strchr(buff,'#');
		if(cmt) *cmt = '\0';
		/* remove leading whitespace */
		while(isspace(*buff))	{
			memmove(buff,buff+1,strlen(buff));
		}

		/* remove trailing whitespace */
		cmt = strchr(buff,'\0');
		cmt --;

		while(isspace(*cmt)) {
			*cmt = '\0';
			cmt --;
		}

		/* process nonempty lines */
		if(*buff) {
			char *kwd = buff;
			char *value = buff + strcspn(buff," \t");
			*value++ = '\0';
			while(isspace(*value)) value++;
#if DBG		    
			printf("key: \"%s\" value: \"%s\" \n",kwd, value);
#endif
			if(strcasecmp(kwd, "flush")==0)	{
				cfg->flush = atoi(value);
				syslog(LOG_DEBUG,"config: set flushing to %d\n",
						cfg->flush);
			}
			else if(strcasecmp(kwd, "fdelay")==0)	{
				cfg->fdelay = atoi(value);
				syslog(LOG_DEBUG,"config: set fdelay to %d\n",
						cfg->fdelay);
			}
			else if(strcasecmp(kwd, "debugfile")==0) {
				cfg->debugname = strdup(value);
				syslog(LOG_DEBUG,"config: set debug to %s\n",
						cfg->debugname);
			}
			/* ---- WHAT ?! ---- */
			else if(strcasecmp(kwd, "dynamicip")==0) {
				if(value[strlen(value)-1]=='/') 
					value[strlen(value)-1]='\0';
				cfg->dynamicip = strdup(value);
				syslog(LOG_DEBUG,"config: set dynamicip to %s\n",
						cfg->dynamicip);
			}
			else if(strcasecmp(kwd, "ignoremask")==0) {
				cfg->ignoremask = inet_addr(value);
				syslog(LOG_DEBUG,"config: set ignoremask %s\n",
						intoa(cfg->ignoremask));
			}
			else if(strcasecmp(kwd, "debug")==0) {
				debug_level = atoi(value);
				syslog(LOG_DEBUG,"config: debug level %d\n",
						debug_level);
			}
			/* networks that will be counted */
			else if(strcasecmp(kwd, "compactnet")==0)	{
				struct ipnetwork *tmp;
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				while(isspace(*mask)) mask++;

				tmp = malloc(sizeof(struct ipnetwork));
				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> compactnet;
					cfg -> compactnet = tmp;
				}
			}
			/* rweber: write to mysql or oracle or ... */
			else if(strcasecmp(kwd, "database")==0)	{
				cfg->database = strdup(value);
				if(!strcmp(cfg->database, "mysql"))
					cfg->dbtype=TYPE_MYSQL;
				else if(!strcmp(cfg->database, "oracle"))
					cfg->dbtype=TYPE_ORACLE;
				else {
					syslog(LOG_ERR, "config file: bad database keyword specified\n");
					return NULL;
				}
			}
#ifdef HAVE_MYSQL
			/* set mysql user from cfg file */
			else if(strcasecmp(kwd, "mysql_user")==0)	{
				cfg->mysql_user = strdup(value);
				syslog(LOG_DEBUG,"config: mysql_user = %s\n",
						cfg->mysql_user);
			}
			/* set mysql passwd from cfg file */
			else if(strcasecmp(kwd, "mysql_password")==0)	{
				cfg->mysql_password = strdup(value);
				syslog(LOG_DEBUG,"config: password ok!");
			}
			/* set mysql host from cfg file */
			else if(strcasecmp(kwd, "mysql_host")==0)	{
				cfg->mysql_host = strdup(value);
				syslog(LOG_DEBUG,"config: mysql_host = %s\n",
						cfg->mysql_host);
			}
			/* set mysql port from cfg file */
			else if(strcasecmp(kwd, "mysql_database")==0)	{
				cfg->mysql_database = strdup(value);
				syslog(LOG_DEBUG,"config: mysql DB = %s\n",
						cfg->mysql_database);
			}
			/* promisc mode yes/no */
			else if(strcasecmp(kwd, "sniff")==0) {
				cfg->sniff = atoi(value);
				syslog(LOG_DEBUG,"config: sniff set to %d",
						cfg->sniff);
			}
			/* mysql port
			 * by d.sadilek@globalview.de */
			else if(strcasecmp(kwd, "mysql_port")==0)	{
				cfg->mysql_port = atoi(value);
				syslog(LOG_DEBUG,"config: mysql_port = %d\n",
						cfg->mysql_port);
			}
#endif /* HAVE_MYSQL */
/* first of all we need correct env ORACLE_HOME and when nacctd starts
 * it need ORACLE_HOME to be set via setenv() or putenv() */			
#ifdef HAVE_ORACLE
			/* set oracle connect from cfg file */
			else if(strcasecmp(kwd, "oracle_connect")==0) {
				cfg->oracle_connect = strdup(value);
				syslog(LOG_DEBUG,"config: oracle_connect set to [hidden]\n");
			}
			/* set oracle home from cfg file */
			else if(strcasecmp(kwd,"oracle_home")==0 && value != NULL) {
				char *env=malloc(strlen("ORACLE_HOME=")+strlen(value)+1); 
				/* do NOT free this pointer! */
				strcpy(env, "ORACLE_HOME=");
				strcat(env, value);
				putenv(env);
				cfg->oracle_home=strdup(value);
				syslog(LOG_DEBUG,"config: oracle_home = %s\n", env);
			}
#endif /* HAVE_ORACLE */
			else if(strcasecmp(kwd, "pidfile")==0) {
				cfg->pid_file = strdup(value);
				syslog(LOG_DEBUG,"config: pid_file set to %s\n",
						cfg->pid_file);
			}
			else if(strcasecmp(kwd, "ignorenet")==0) {
				struct ipnetwork *tmp;
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				
				while(isspace(*mask)) mask++;

				tmp = malloc(sizeof(struct ipnetwork));

				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> ignorenet;
					cfg -> ignorenet = tmp;
				}
			}

			/* By renegade - added ournet and direct_peer */
			else if(strcasecmp(kwd, "ournet")==0)	{
				struct ipnetwork *tmp;
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';

				while(isspace(*mask)) mask++;
				
				tmp = malloc(sizeof(struct ipnetwork));
			    
				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> ournet;
					cfg -> ournet = tmp;
				}

			}
			else if(strcasecmp(kwd, "direct_peer")==0) {
				struct ipnetwork *tmp;
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				while(isspace(*mask)) mask++;

				tmp = malloc(sizeof(struct ipnetwork));

				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> direct_peer;
					cfg -> direct_peer = tmp;
				}

			}
			/* ---- WHAT ?! ---- */
			else if(strcasecmp(kwd, "exclude-name-lookup")==0) {
				struct ipnetwork *tmp;
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				while(isspace(*mask)) mask++;
				
				tmp = malloc(sizeof(struct ipnetwork));

				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> excludenamelookup;
					cfg -> excludenamelookup = tmp;
				}
			}
			/* ---- WHAT?! ---- */
			else if(strcasecmp(kwd, "dynamicnet")==0)	{
				char *mask;

				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				while(isspace(*mask)) mask++;

				cfg -> dynamicnet.netnumber = inet_addr(value);
				cfg -> dynamicnet.netmask = inet_addr(mask);
			}
			/* ---- WHAT ?! ---- */
			else if(strcasecmp(kwd, "dontignore")==0)	{
				struct ipnetwork *tmp;
				char *mask;
				
				mask  = value + strcspn(value," \t");
				*mask++ = '\0';
				while(isspace(*mask)) mask++;
				tmp = malloc(sizeof(struct ipnetwork));
				if(tmp != NULL)	{
					tmp -> netnumber = inet_addr(value);
					tmp -> netmask = inet_addr(mask);
					tmp -> next = cfg -> dontignore;
					cfg -> dontignore = tmp;
				}
			}
			else if(strcasecmp(kwd, "headers")==0) {
				char *offset;
				char *type;

				struct headerdat *tmp;
				offset  = value + strcspn(value," \t");
				*offset++ = '\0';

				while(isspace(*offset)) offset++;

				type  = offset + strcspn(offset," \t");
				*type++ = '\0';
				while(isspace(*type)) type++;
				
				tmp = malloc(sizeof(struct headerdat));
				if(tmp != NULL)	{
					tmp -> name = strdup(value);
					tmp -> l = strlen(value);
					tmp -> offset = atoi(offset);
					tmp -> type = atoi(type);
					tmp -> next = cfg -> headers;
					cfg -> headers = tmp;
					syslog(LOG_DEBUG, "config: added headerinfo (%s:%d:%d)\n",
							tmp -> name, tmp -> offset, tmp -> type);
				}
			}
			/* devices on which we will listen */
			else if(strcasecmp(kwd, "device")==0)	{
				struct promisc_device *tmp;
				tmp = malloc(sizeof(struct promisc_device));

				if(tmp != NULL)	{
					tmp -> name  = strdup(value);
					tmp -> reset = 0;
					tmp -> next = cfg -> promisc;
					cfg -> promisc = tmp;
					syslog(LOG_DEBUG,"config: added listen device %s\n",
							cfg->promisc->name);
				}
			}
			/* ---- WHAT?! ---- */
			else if(strcasecmp(kwd, "notdev")==0)	{
				struct promisc_device *tmp;
				tmp = malloc(sizeof(struct promisc_device));
				if(tmp != NULL)	{
					tmp -> name  = strdup(value);
					tmp -> next = cfg -> notdev;
					cfg -> notdev = tmp;
					syslog(LOG_DEBUG,"config: added notdevice %s\n",
							cfg->notdev->name);
				}
			}
			/* time between tries to write in sql if an error
			 * occures */
			else if(strcasecmp(kwd, "errdelay")==0)	{
				cfg->err_delay = atoi(value);
				syslog(LOG_DEBUG,"config: set delay on error to %d\n",cfg->err_delay);
			}

			/* ---- WHAT ?! ---- */
			else if(strcasecmp(kwd, "line")==0)	{
				struct dev2line *tmp;
				char *line;
				tmp = malloc(sizeof(struct dev2line));
				line  = value + strcspn(value," \t");
				*line++ = '\0';
				while(isspace(*line)) line++;
				tmp -> netinterface = strdup(value);
				tmp -> line = strdup(line);
				tmp -> next = dev2line;
				dev2line = tmp;
				syslog(LOG_DEBUG,"config: [dev2line:] %s -> %s\n",dev2line->netinterface, dev2line->line);
			}
			/* ---- WHAT?! ---- */	
			else if(strcasecmp(kwd, "hostlimit")==0) {
				unsigned char c1,c2,c3,c4;
				unsigned long ipaddr;
				struct mon_host_struct *tmp;
				c1 = strtol(strtok(value,"."),0,0);
				c2 = strtol(strtok(NULL,"."),0,0);
				c3 = strtol(strtok(NULL,"."),0,0);
				c4 = strtol(strtok(NULL,"."),0,0);
				ipaddr = htonl((c1 << 24) | (c2 << 16) | (c3 << 8) | c4);
				tmp = malloc(sizeof(struct mon_host_struct));
				if(tmp != NULL) {
					tmp->ipaddr = ipaddr;
					tmp->next = cfg->hostlist;
					cfg->hostlist = tmp;
					syslog(LOG_DEBUG,"config: added hostlimit %s\n",intoa(cfg->hostlist->ipaddr));
				}
			}
			/* ---- WHAT ?! ---- */
			else if(strcasecmp(kwd, "iflimit")==0) {
				struct promisc_device *tmp;

				tmp = malloc(sizeof(struct promisc_device));

				if(tmp != NULL)	{
					tmp -> name  = strdup(value);
					tmp -> next = cfg -> iflist;
					cfg -> iflist = tmp;
					syslog(LOG_DEBUG,"config: added iflist %s\n",
							cfg->iflist->name);
				}
			} else {
				syslog(LOG_ERR, "config file: unknown keyword in line %d, Ignoring ... \n",line);
			}
		}
	}

#ifdef linux
	if(cfg->headers == NULL) {
		syslog(LOG_ERR, "FIXME: add header info and use it (dont panic this is just msg-reminder\n");
	}
#endif

#ifdef HAVE_ORACLE
	
	if(cfg->oracle_connect == NULL) {
		syslog(LOG_ERR, "config file: oracle_connect is not set");
		return NULL;
	}
	if(cfg->oracle_home == NULL) {
		syslog(LOG_ERR, "config file: oracle_home is not set");
		return NULL;
	}
#endif
	if(cfg->debugname == NULL) {
		syslog(LOG_INFO, "config file: no debugfile given, using /dev/null\n");
		cfg->debugname = strdup("/dev/null");
	}
	
	fclose(f);
	return cfg;
}

/* reads nacctpeering file 
 * basicly find out what is style of ip networks
 * 1. 1.2.3.4/255.255.255.0
 * or
 * 2. 1.2.3.4/24 
 * everything which begins with # is ignored */
struct peering *read_peering(char *pname)
{
	char buff[1024];
	FILE *peer;
	int line=0;
	int nmask=0;
	struct peering *pcfg = malloc(sizeof(struct peering));
	if(pcfg == NULL) return pcfg;

	pcfg-> peering_addr = NULL;

	peer=fopen(pname,"r");
	if(peer == NULL) return NULL;

	while(fgets(buff,sizeof(buff),peer)) {
		/* remove trailing newline */
		char *cmt = strchr(buff,'\n');
		if(cmt) *cmt = '\0';
		line++;
		/* remove comments */
		cmt = strchr(buff,'#');
		if(cmt) *cmt = '\0';
		/* remove leading whitespace */
		while(isspace(*buff))	{
			memmove(buff,buff+1,strlen(buff));
		}
		/* remove trailing whitespace */
		cmt = strchr(buff,'\0');
		cmt --;
		while(isspace(*cmt)) {
			*cmt = '\0';
			cmt --;
		}
		/* process nonempty lines */
		if(*buff)	{
			struct ipnetwork *tmp;
			char *kwd = buff;
			char *value = buff + strcspn(buff,"/");
			*value++ = '\0';

			while(isspace(*value)) value++;
			/* here must begin reading of peering ip's */
      
			tmp = malloc(sizeof(struct ipnetwork));

			if(tmp != NULL)	{
				/* check what netmask style is current net
				 * if there is dots (.) - it is dot style :) */
				if(!strchr(value, '.'))	{
					/* inverse mask style - /24 or /32 */
					nmask = atoi(value);
					/* actual converting */
					nmask = htonl(0xFFFFFFFF << (32 - nmask));
					tmp -> netnumber = inet_addr(kwd);
					tmp -> netmask = nmask;
					tmp -> next = pcfg -> peering_addr;
					pcfg -> peering_addr = tmp;

				}	else {
					/* dot style format */
					tmp -> netnumber = inet_addr(kwd);
					tmp -> netmask = inet_addr(value);
					tmp -> next = pcfg -> peering_addr;
					pcfg -> peering_addr = tmp;
				}
			}
		}
	}

	fclose(peer);
	return pcfg;
}
