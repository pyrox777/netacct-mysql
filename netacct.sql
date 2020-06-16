# if you are upgrading from previous version please use upgrade.sql insted
#
# sql structure file for netacct-mysql 0.78
# added new table rrd for rrdtool statistics
# geroy@stemo.bg
# just use this:
# mysql -u root -p < netacct.sql
#

create database if not exists netacct;
use netacct;
grant usage on netacct.* to acct@localhost ;
grant select,update,insert on netacct.* to acct@localhost ;
SET PASSWORD FOR "acct"@"localhost"=PASSWORD("acct_password");

CREATE TABLE if not exists `rrd` (
  `ip` varchar(15) NOT NULL default '',
  `input` int(20) NOT NULL default '0',
  `output` int(20) NOT NULL default '0',
  `peer_input` int(20) NOT NULL default '0',
  `peer_output` int(20) NOT NULL default '0',
  `direct_input` int(20) NOT NULL default '0',
  `direct_output` int(20) NOT NULL default '0',
  `local_input` int(20) NOT NULL default '0',
  `local_output` int(20) NOT NULL default '0'
) TYPE=MyISAM;

CREATE TABLE if not exists `traffic` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `ip` varchar(15) NOT NULL default '',
  `time` datetime NOT NULL default '0000-00-00 00:00:00',
  `input` int(20) NOT NULL default '0',
  `output` int(20) NOT NULL default '0',
  `peer_input` int(20) NOT NULL default '0',
  `peer_output` int(20) NOT NULL default '0',
  `direct_input` int(20) NOT NULL default '0',
  `direct_output` int(20) NOT NULL default '0',
  `local_input` int(20) NOT NULL default '0',
  `local_output` int(20) NOT NULL default '0',
  PRIMARY KEY  (`id`),
  KEY `ip` (`ip`,`time`)
) TYPE=MyISAM;
