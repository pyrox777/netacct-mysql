/*
 * Network accounting
 * mysql.c - (C) 2002
 * 
 * porting to other SQL database can be easy, just copy this file
 * in new file (anythingsql.c) and change the code for connect/write/exit
 * to sql with proper one. you need to find analog functions of these 
 * 
 *  mysql_connect()
 *  mysql_query()
 *  mysql_store_result()
 *  mysql_num_rows()
 *  mysql_fetch_row()
 *  mysql_close() 
 *  mysql_free_result()
 *
 *  and send it to me :)
 *  Nikolay Hristov <geroy@stemo.bg>
 *  some optimization of mysql code by Valeri Dachev <valery@zonebg.com>
 * */

#include "netacct.h"

#ifdef HAVE_MYSQL

#include <mysql.h>

/* 
 * IN: struct with ip traffic
 *
 * tmpData->ipAddress
 * tmpData->nInTrafic
 * tmpData->nOutTrafic
 * tmpData->nPeerFlag
 *
 * OUT: 0 - success
 *      1 - error
 *
 * function written by Boril Yonchev so any questions goes to
 * <bashbug@users.sourceforge.net>
 * */

int write_mysql(struct HOST_DATA* tmpData, MYSQL mysql_ptr)
{
		MYSQL_RES *result;
		MYSQL_ROW row, r;
		my_ulonglong rows;
		char query[8192];
		char rrd_query[8192];
		unsigned long int input, output, peer_input, peer_output;
		unsigned long int direct_input, direct_output, local_input, local_output;
		int rc;
		char TIME_MASK[] = "DATE_FORMAT(NOW(),'%Y-%m-%d %H:00:00')";
		char spyip[16];

		input=(tmpData->nPeerFlag==0)?tmpData->nInTrafic:0;
		output=(tmpData->nPeerFlag==0)?tmpData->nOutTrafic:0;
		peer_input=(tmpData->nPeerFlag==1)?tmpData->nInTrafic:0;
		peer_output=(tmpData->nPeerFlag==1)?tmpData->nOutTrafic:0;
		direct_input=(tmpData->nPeerFlag==2)?tmpData->nInTrafic:0;
		direct_output=(tmpData->nPeerFlag==2)?tmpData->nOutTrafic:0;
		local_input=(tmpData->nPeerFlag==3)?tmpData->nInTrafic:0;
		local_output=(tmpData->nPeerFlag==3)?tmpData->nOutTrafic:0;


		strncpy(spyip,intoa(tmpData->ipAddress),16);

		sprintf(query, "SELECT `id` FROM `%s` WHERE `ip` = '%s' AND `time` = %s", "traffic", spyip, TIME_MASK);
		
		/* needed for rrdtool graphic generation */
		sprintf(rrd_query, "SELECT input,output,peer_input,peer_output,direct_input,direct_output,local_input,local_output FROM rrd WHERE ip='%s'", spyip);
	
	
		/* check for RRD graphics if there is no line for that IP in
	 	* rrd table -> insert it with current values else update current
	 	* values. crontab perl script will flush all values after that */
		rc = mysql_query(&mysql_ptr, rrd_query);
		
		result = mysql_store_result(&mysql_ptr);
		if(result == NULL) {
			syslog(LOG_INFO, "Error has occured while executing mysql_store_result\n");
			return 1;
		}
	
		rows = mysql_num_rows(result);
		if(rows) {
			r = mysql_fetch_row(result);
			sprintf(rrd_query,"UPDATE rrd SET input='%lu', output='%lu', peer_input='%lu', peer_output='%lu', direct_input='%lu', direct_output='%lu', local_input='%lu',local_output='%lu' WHERE ip='%s'", (tmpData->nPeerFlag==0)?tmpData->nInTrafic:atol(r[0]), (tmpData->nPeerFlag==0)?tmpData->nOutTrafic:atol(r[1]), (tmpData->nPeerFlag==1)?tmpData->nInTrafic:atol(r[2]), (tmpData->nPeerFlag==1)?tmpData->nOutTrafic:atol(r[3]), (tmpData->nPeerFlag==2)?tmpData->nInTrafic:atol(r[4]), (tmpData->nPeerFlag==2)?tmpData->nOutTrafic:atol(r[5]), (tmpData->nPeerFlag==3)?tmpData->nInTrafic:atol(r[6]), (tmpData->nPeerFlag==3)?tmpData->nOutTrafic:atol(r[7]), spyip );
				
		} else {
			sprintf(rrd_query,"INSERT INTO rrd (ip,input,output,peer_input,peer_output,direct_input,direct_output,local_input,local_output) VALUES ( '%s','%lu','%lu','%lu','%lu','%lu','%lu','%lu','%lu')", spyip,(tmpData->nPeerFlag==0)?tmpData->nInTrafic:0, (tmpData->nPeerFlag==0)?tmpData->nOutTrafic:0, (tmpData->nPeerFlag==1)?tmpData->nInTrafic:0, (tmpData->nPeerFlag==1)?tmpData->nOutTrafic:0, (tmpData->nPeerFlag==2)?tmpData->nInTrafic:0, (tmpData->nPeerFlag==2)?tmpData->nOutTrafic:0, (tmpData->nPeerFlag==3)?tmpData->nInTrafic:0, (tmpData->nPeerFlag==3)?tmpData->nOutTrafic:0);
		}

	/* execute query for RRD table */
	rc = mysql_query(&mysql_ptr, rrd_query);
	if(rc != 0) {
		syslog(LOG_INFO, "Something wrong happened while executing mysql_query(): Error: %s", mysql_error(&mysql_ptr));
  }

	mysql_free_result(result);
	
	rc = mysql_query(&mysql_ptr, query);
	if(rc != 0) {
		syslog(LOG_INFO, "Something wrong happened while executing mysql_query(): Error: %s", mysql_error(&mysql_ptr));
	}

	result = mysql_store_result(&mysql_ptr);
	rows = mysql_num_rows(result);
	/* if it is old compact info */
	if (rows) {
		row = mysql_fetch_row(result);
		sprintf(query, "UPDATE `%s` SET input = input + '%lu', output = output + '%lu', "
"peer_input = peer_input + '%lu', peer_output = peer_output + '%lu', "
"direct_input = direct_input + '%lu', direct_output = direct_output + '%lu', "
"local_input = local_input + '%lu', local_output = local_output + '%lu' "
"WHERE `id` = '%s'", "traffic", input, output, peer_input, peer_output, direct_input, direct_output, local_input, local_output, row[0]);
	} else {
		sprintf(query, "INSERT INTO `%s` (ip,time,input,output,peer_input,peer_output,direct_input,direct_output,local_input,local_output) "
"VALUES('%s',%s,'%lu','%lu','%lu','%lu','%lu','%lu','%lu','%lu')",
"traffic", spyip, TIME_MASK,
input, output, peer_input, peer_output, direct_input, direct_output, local_input, local_output);
	}
	
	DEBUG(DBG_STATE, query);

	/* and write data in mysql */
	rc = mysql_query(&mysql_ptr, query);
	if(rc != 0) {
		syslog(LOG_INFO, "Something wrong happened while executing mysql_query(): Error: %s", mysql_error(&mysql_ptr));
		return 1;
	}

	mysql_free_result(result);
}

/* Get all collected data from Linked List and calls write_mysql()
 * to write data to mysql database */
int do_write_list_mysql(void)
{
	struct HOST_DATA* tmpData;
	MYSQL mysql;
	int i = 0;

	/* connect to mysql server */
	mysql_init(&mysql);
	if(!mysql_real_connect(&mysql,cfg->mysql_host,cfg->mysql_user,cfg->mysql_password,cfg->mysql_database,cfg->mysql_port,NULL,0)) {
		syslog(LOG_INFO,"mySQL Error: %s",mysql_error(&mysql));
		return 1;
	}

	/* get first collected data ... */
	tmpData = (struct HOST_DATA*) GetFirstHost();

	/* if there is no data in memory yet just do nothing */
	if(tmpData == 0) {
		return 0;
	}

	/* and write it to mysql*/
	if((tmpData->nInTrafic != 0) || (tmpData->nOutTrafic != 0))
		write_mysql(tmpData, mysql);

	/* get next collected data ... */
	while(tmpData = (struct HOST_DATA*) GetNextHostData()) {
		i++;
		/* and write data to mysql 
		* if IN and OUT traffic are not NULL 
		* if IN and OUT == NULL then this is old allocated
		* memory with no traffic in it so we don't call 
		* write_mysql() */
		if((tmpData->nInTrafic != 0) || (tmpData->nOutTrafic != 0))
			write_mysql(tmpData, mysql);
	}

	/* close mysql connection */
	mysql_close(&mysql);
	return 0;
	/* we don't call clear_counters() here .. we call it in parent process
	 * so it will clear real data not it's copy of child process */
}

#endif 
