# If you are installing netacct for the first time please use
# netacct.sql instead
#
# netacct 0.78 upgrade script
#

use netacct;

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
