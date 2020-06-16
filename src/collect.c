/*
 * Network accounting
 * collect.c - (C) 2002
 * 
 * Vasil Keremedchiev <vasil@fixoft.com>
 * Nikolay Hristov <geroy@stemo.bg>
 * 
 * Thanx a lot to Vasko for his help :)
 * 
 * */

#include <malloc.h>
#include <sys/wait.h>
#include "netacct.h"

char *rcs_revision_collect_c = "$Revision: 1.4 $";

/* Release memory used by the linked list and all it's host data structures */
void release_linked_list()
{
	/* Get root host data */
	struct HOST_DATA_ITEM* pHostItem = sg_pRootHostData;

	while(pHostItem) {
		struct HOST_DATA_ITEM* pNextItem = pHostItem->m_pNextItem;
		if(pHostItem->m_pHostData) {
			free(pHostItem->m_pHostData);
			pHostItem->m_pHostData = NULL;
		}

		free(pHostItem);
		pHostItem = pNextItem;
	}
}

/*
 * Clear counters of IP traffic
 * should be called after every write to sql
 * */
void clear_counters()
{
	/* Get root host data */
			struct HOST_DATA_ITEM* pHostItem = sg_pRootHostData;
			while((pHostItem) && (pHostItem->m_pHostData)) {
		//syslog(	LOG_DEBUG, "Clearing: ip: %i, host: %i", pHostItem->m_pHostData->ipAddress, pHostItem->m_pHostData->nPeerFlag );
				pHostItem->m_pHostData->nInTrafic = 0;
				pHostItem->m_pHostData->nOutTrafic = 0;
				pHostItem = pHostItem->m_pNextItem;
			}
		syslog(LOG_DEBUG,"clear_counters() called\n");
}

/*
 *    Add host data to the linked list
 *    IN:		pHostData     	- data to add to the list
 *    OUT:	return         	 	NULL if not succeeded
 *    = pHostData if succeeded
 * */

struct HOST_DATA* add_host_info( struct HOST_DATA* pHostData )
{
        struct HOST_DATA* pReturnData = NULL;

        if ( pHostData )
        {
                struct HOST_DATA_ITEM* pNewItem = malloc( sizeof( struct HOST_DATA_ITEM ) );
                if ( pNewItem )
                {
                        pNewItem->m_pHostData = pHostData;
                        pNewItem->m_pNextItem = sg_pRootHostData;

                        sg_pRootHostData = pNewItem;

                        pReturnData = pHostData;
                }
        }

        return pReturnData;
}

/*
 * Find host information by IP address
 *    IN:             ipHost  - host IP to search for
 *    OUT:    return  - pointer to host info structure
 * */
struct HOST_DATA* find_host_info(IP_TYPE ipHost, int nPeer)
{
	/* Get root host data */
	struct HOST_DATA_ITEM* pHostItem = sg_pRootHostData;

	while((pHostItem) && (pHostItem->m_pHostData) && 
		(!((pHostItem->m_pHostData->ipAddress == ipHost) &&
		(pHostItem->m_pHostData->nPeerFlag == nPeer)))) {
					
		pHostItem = pHostItem->m_pNextItem;
	}

	if((pHostItem) && (pHostItem->m_pHostData) && 
		(pHostItem->m_pHostData->ipAddress == ipHost) &&
		(pHostItem->m_pHostData->nPeerFlag == nPeer)) {
		//syslog( LOG_DEBUG, "Matched!\n" );
		return pHostItem->m_pHostData;
	}
	return NULL;
}


/*
 * Get Host by IP from a linked list
 * Note: If host didn't exist then this function creates new and return 
 * a pointer to it
 *    IN:             ipHost  - IP address of the host to search for
 *    OUT:    return  - pointer to structure with host data
 * */
struct HOST_DATA* get_host_info(IP_TYPE ipHost, int nPeer)
{
	/* Search for host info by IP address and return the information */
	struct  HOST_DATA* pHostInfo = find_host_info(ipHost,nPeer);

	if(!pHostInfo) {
		struct HOST_DATA* pNewHostData = malloc(sizeof(struct HOST_DATA));

		if(pNewHostData) {
			pNewHostData->ipAddress		= ipHost;
			pNewHostData->nInTrafic		= 0;
			pNewHostData->nOutTrafic	= 0;
			pNewHostData->nPeerFlag		= nPeer;
			/* Add host info to the linked list */
			pHostInfo = add_host_info(pNewHostData);
		}
	}
	return pHostInfo;
}

/*
 * Add host information for the traffic
 *	IN:             ipHost          - IP address of the host
 *	                nInBytes        - number of bytes newly received to host
 *	                nOutBytes       - number of bytes newly sent by the host
 * */
void add_host_traffic_info(IP_TYPE ipHost, TRAFFIC_TYPE nInBytes,
			TRAFFIC_TYPE nOutBytes, int nPeerFlag)
{
	struct HOST_DATA* pHostData = get_host_info(ipHost, nPeerFlag);

	if(pHostData) {
		pHostData->nInTrafic    += nInBytes;
		pHostData->nOutTrafic   += nOutBytes;
	}
}

/*
 * Get first host data
 * OUT:	return	- pointer to host data, if NULL - no data
 * */
struct HOST_DATA* GetFirstHost()
{
	if(sg_pRootHostData != NULL) {
		s_pCurrentHostData = sg_pRootHostData;
		return s_pCurrentHostData->m_pHostData;
	} else {
		return 0;
	}
}


/*
 * Get next host data
 * OUT:	return	- pointer to next host data, if NULL - no more data
 * */
struct HOST_DATA* GetNextHostData()
{
	struct HOST_DATA* pResult = NULL;

	if(s_pCurrentHostData) {
		/* Turn to next item */
		s_pCurrentHostData = s_pCurrentHostData->m_pNextItem;

		/* If there is next item */
		if(s_pCurrentHostData) {
			pResult = s_pCurrentHostData->m_pHostData;
		}
	}
	return pResult;
}
