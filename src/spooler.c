/* 
**
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "plugbase.h"
#include "pcap_pkthdr32.h"
#include "spooler.h"
#include "input-plugins/spi_unified2.h"
#include "util.h"
#include "unified2.h"
#include "barnyard2.h"
#include "debug.h"



int ProcessContinuous(InputConfig *);
int ProcessContinuousWithWaldo(InputConfig *);
int ProcessBatch(const char *, const char *);
int ProcessWaldoFile(const char *);
int spoolerReadWaldo(Waldo *);

int spoolerOpen(Spooler *,const char *, const char *, uint32_t);
int spoolerClose(Spooler *);
int spoolerReadRecordHeader(Spooler *);
int spoolerReadRecord(Spooler *);
int spoolerProcessRecord(Spooler *,Waldo *, int);
void spoolerFreeRecord(Record *record);

int spoolerWriteWaldo(Waldo *, Spooler *);
int spoolerOpenWaldo(Waldo *);
int spoolerCloseWaldo(Waldo *);


int spoolerPacketCacheAdd(Spooler *, Packet *);
int spoolerPacketCacheClear(Spooler *);
int spoolerEventCachePush(Spooler *, uint32_t, void *);

EventRecordNode * spoolerEventCacheGetByEventID(Spooler *, uint32_t);
EventRecordNode * spoolerEventCacheGetHead(Spooler *);
uint8_t spoolerEventCacheHeadUsed(Spooler *);
int spoolerEventCacheClean(Spooler *);

/* Find the next spool file timestamp extension with a value equal to or 
 * greater than timet.  If extension != NULL, the extension will be 
 * returned.
 *
 * @retval 0    file found
 * @retval -1   error
 * @retval 1    no file found
 *
 * Possible Bugs:  This function assume a 1 character delimeter between the base 
 *                 filename and the extension
 */
static int FindNextExtension(const char *dirpath, const char *filebase, 
        uint32_t timestamp, unsigned long *extension)
{
    DIR *dir = NULL;
    struct dirent *dir_entry;
    
    uint32_t timestamp_min = 0;    
    size_t filebase_len;
    
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Looking in %s for %s\n", dirpath, filebase););
    
    /* peform sanity checks */
    if (dirpath == NULL || filebase == NULL)
    {
        return SPOOLER_EXTENSION_EPARAM;
    }
	
    /* calculate filebase length */
    filebase_len = strlen(filebase);
    
    /* open the directory */
    if ( !(dir=opendir(dirpath)) )
    {
        LogMessage("ERROR: Unable to open directory '%s' (%s)\n", dirpath,
                strerror(errno));
        return SPOOLER_EXTENSION_EOPEN;
    }
    
    /* step through each entry in the directory */
    while ( (dir_entry=readdir(dir)) )
    {
        unsigned long   file_timestamp = 0;
	
	if(dir_entry->d_type == DT_REG)
	{
	    if (strncmp(filebase, dir_entry->d_name, filebase_len) == 0)
	    {
		/* this is a file we may want */
		file_timestamp = strtol(dir_entry->d_name + filebase_len+1, NULL, 10);
		
		if ((errno == ERANGE))
		{
		    LogMessage("WARNING: Can't extract timestamp extension from '%s'"
			       "using base '%s'\n", 
			       dir_entry->d_name, filebase);
		    continue;
		}
		else
		{
		    /* exact match */
		    if ( (timestamp != 0) && 
			 (file_timestamp == timestamp))
		    {
			//timestamp_min = file_timestamp;
			continue;//break;
		    }
		    /* possible overshoot */
		    else if (file_timestamp > timestamp)
		    {
			/*  realign the minimum timestamp threshold */
			if ( (timestamp_min == 0) || 
			     (file_timestamp < timestamp_min) )
			{
			    timestamp_min = file_timestamp;
			}
		    }
		}
	    }
	}
    }
    
    closedir(dir);
    
    /* no newer extensions were found */
    if (timestamp_min == 0) 
    {
        return SPOOLER_EXTENSION_NONE;
    }

    if(extension != NULL)
    {
	*extension = timestamp_min;
    }
    
    return SPOOLER_EXTENSION_FOUND;
}

int spoolerOpen(Spooler *spooler,const char *dirpath, const char *filename, uint32_t extension)
{

    off_t read_size = 0;
    
    void *cache_ptr = NULL;
    void *read_buffer_ptr = NULL;
    
    /* perform sanity checks */
    if ( (spooler == NULL) || 
	 (filename == NULL) ||
	 (dirpath == NULL))
    {
	/* XXX */
	return 1;
    }
    
    /* ELZ: We will need to have a cleaner way to do this :) */
    cache_ptr =(void *)spooler->cacheHead;
    read_buffer_ptr = (void *)spooler->read_buffer;
    read_size = spooler->max_read_size;
    
    memset(spooler,'\0',sizeof(Spooler));
    
    spooler->cacheHead =(EventCacheLeaf *)cache_ptr;
    spooler->read_buffer = (char *)read_buffer_ptr;
    spooler->max_read_size = read_size;
    /* ELZ: We will need to have a cleaner way to do this :) */

    /* build the full filepath */
    /* need to check if we could be smarter about extension being 0 and filepath relation ...process batch kind of issue */
    if (extension == 0)
    {
        if( (SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s", 
			   filename)) != SNORT_SNPRINTF_SUCCESS)
	{
	    spoolerClose(spooler);
	    FatalError("spooler: filepath too long!\n");
	}
    }
    else
    {
        if( (SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s/%s.%u", 
			   dirpath, 
			   filename,
			   extension)) != SNORT_SNPRINTF_SUCCESS)
	{
	    spoolerClose(spooler);
	    FatalError("spooler: filepath too long!\n");
	}
    }

    spooler->timestamp = extension;
    
    LogMessage("Opened spool file '%s'\n", spooler->filepath);
    
    if ( (spooler->fd=open(spooler->filepath, O_RDONLY, 0)) == -1 )
    {
        LogMessage("ERROR: Unable to open log spool file '%s' (%s)\n", 
		   spooler->filepath, strerror(errno));
        spoolerClose(spooler);
	return 1;
    }
    
    if( fstat(spooler->fd,
	      &spooler->spooler_stat) < 0)
    {
	LogMessage("ERROR: Unable to stat spool file '%s' (%s)\n", 
		   spooler->filepath, strerror(errno));
	spoolerClose(spooler);
	return 1;
    }
    
    spooler->file_size = spooler->spooler_stat.st_size;
    
    spooler->ifn = GetInputPlugin("unified2");

    if (spooler->ifn == NULL)
    {
        spoolerClose(spooler);
	FatalError("ERROR: No suitable input plugin found!\n");
    }

    return 0;
}

int spoolerClose(Spooler *spooler)
{
    /* perform sanity checks */
    if (spooler == NULL)
    {
        return 1;
    }
    
    LogMessage("Closing spool file '%s'. Read %d records\n",
               spooler->filepath, spooler->record_idx);
    
    if (spooler->fd != -1)
    {
        close(spooler->fd);
    }
    
    memset(spooler,'\0',sizeof(Spooler));
    spooler->fd = -1;
    
    return 0;
}

int spoolerReadRecordHeader(Spooler *spooler)
{
    if ( spooler == NULL )
    {
        return 1;
    }

    if (spooler->ifn->readRecordHeader)
    { 
        return spooler->ifn->readRecordHeader(spooler);
    }
    else
    {
        LogMessage("WARNING: No function defined to read header.\n");
        return 1;
    }

    return 0;
}

int spoolerReadRecord(Spooler *spooler)
{
    int                 ret;

    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    if (spooler->state != SPOOLER_STATE_HEADER_READ)
    {
        LogMessage("ERROR: Invalid attempt to read record.\n");
        return -1;
    }

    if (spooler->ifn->readRecord)
    { 
        ret = spooler->ifn->readRecord(spooler);

        if (ret != 0)
            return ret;

        spooler->state = SPOOLER_STATE_RECORD_READ;
        spooler->record_idx++;
        spooler->offset = 0;
    }
    else
    {
        LogMessage("WARNING: No function defined to read header.\n");
        return -1;
    }

    return 0;
}


void *EventCacheGetEvent(EventCacheLeaf *eventHead,unsigned long event_id,unsigned long event_time,unsigned short trigger)
{
    unsigned long event_chunk_time = 0;
    
    if(eventHead == NULL)
    {
	return NULL;
    }
    
    event_chunk_time = event_time / EVENT_CACHE_LEAF_TIMESPLIT ;
    
    while(eventHead != NULL)
    {
	if(eventHead->timeChunk == event_chunk_time)
	{
	    if(eventHead->eventArr[event_id] != NULL)
	    {
		if( eventHead->eventArr[event_id]->event_second == event_time)
		{
		    switch(trigger)
		    {
		    case TRIGGER_PACKET:
			eventHead->eventArr[event_id]->event_trigger_packet++;
			break;
			
		    case TRIGGER_EXTRA_DATA:
			eventHead->eventArr[event_id]->event_trigger_extra_data++;
			break;
			
		    default:
			break;
		    }
		    
		    return  (EventCacheNode *)(eventHead->eventArr[event_id])->event_buffer;
		}
		else if( (EventCacheNode *)(eventHead->eventArr[event_id])->mirror_event != NULL)
		{
		    EventCacheNode *subCacheNode = (EventCacheNode *)(eventHead->eventArr[event_id])->mirror_event;
		    while(subCacheNode != NULL)
		    {
			if(subCacheNode->event_second == event_time)
			{
			    switch(trigger)
			    {
			    case TRIGGER_PACKET:
				subCacheNode->event_trigger_packet++;
				break;

			    case TRIGGER_EXTRA_DATA:
				subCacheNode->event_trigger_extra_data++;
				break;

			    default:
				break;
			    }

			    
			    return  subCacheNode->event_buffer;
			}
			subCacheNode = subCacheNode->mirror_event;
		    }
		}
	    }
	}
	
	eventHead = eventHead->next;
    }
    
    return NULL;
}

unsigned int EventCacheDestroy(EventCacheLeaf **eventHead)
{
    EventCacheLeaf *currentLeaf = NULL;
    EventCacheLeaf *nextLeaf = NULL;
    EventCacheNode *cacheNode = NULL;

    int x = 0;

    if(eventHead == NULL)
    {
	/* XXX */
	return 1;
    }
    
    currentLeaf = *eventHead;

    while(currentLeaf != NULL)
    {
	for( x = 0 ; x < (USHRT_MAX + 1) ; x++)
	{
	sub_purge:
	    if(currentLeaf->eventArr[x] != NULL)
	    {
		if(currentLeaf->eventArr[x]->event_buffer != NULL)
		{
		    free(currentLeaf->eventArr[x]->event_buffer);
		    currentLeaf->eventArr[x]->event_buffer = NULL;
		}
		
		cacheNode = currentLeaf->eventArr[x];
		
		if(currentLeaf->eventArr[x]->mirror_event != NULL)
		{
		    currentLeaf->eventArr[x] = currentLeaf->eventArr[x]->mirror_event;
		    free(cacheNode);
		    cacheNode = NULL;
		    goto sub_purge;
		}
		
		free(cacheNode);
		cacheNode = NULL;
	    }
	}
	
	nextLeaf = currentLeaf->next;
	free(currentLeaf);
	currentLeaf = nextLeaf;
    }
    
    *eventHead = NULL;
    return 0;
}

unsigned int EventCacheClean(EventCacheLeaf **eventHead,unsigned long *last_cached_event_timestamp,unsigned long current_event_time)
{
    EventCacheLeaf *currentLeaf = NULL;
    EventCacheLeaf *previousLeaf = NULL;
    EventCacheLeaf *nextLeaf = NULL;
    
    int x = 0;

    if( (last_cached_event_timestamp == NULL) || 
	(*eventHead == NULL))
    {
	/* XXX */
	return 1;
    }
    
    currentLeaf = *eventHead;
    
    while(currentLeaf != NULL)
    {
	if(currentLeaf->timeChunk <= (current_event_time / EVENT_CACHE_LEAF_TIMESPLIT))
	{
	    for( x = 0 ; x < (USHRT_MAX + 1) ; x++)
	    {
		
	    sub_purge:
		if(currentLeaf->eventArr[x] != NULL)
		{
		    if( (currentLeaf->eventArr[x])->event_second <= (current_event_time - TAG_PRUNE_TIME))
		    {
			EventCacheNode *subEvent = NULL;
			
			subEvent = currentLeaf->eventArr[x]->mirror_event;
						
			if(currentLeaf->eventArr[x]->event_buffer != NULL)
			{
			    free(currentLeaf->eventArr[x]->event_buffer);
			}
			
			free(currentLeaf->eventArr[x]);
			currentLeaf->eventArr[x] = subEvent;
			currentLeaf->event_counter--;	
			
			if(subEvent != NULL)
			{
			    goto sub_purge;
			}
		    }
		}
	    }
	}
	
	nextLeaf = currentLeaf->next;
	
	if(currentLeaf->event_counter == 0)
	{
	    free(currentLeaf);
	    
	    if(previousLeaf != NULL)
	    {
		previousLeaf->next = nextLeaf;
	    }
	    
	    if(*eventHead == currentLeaf)
	    {
		*eventHead = nextLeaf;
		currentLeaf = NULL;
	    }
	}
	
	previousLeaf = currentLeaf;
	currentLeaf = nextLeaf;
    }
    
    *last_cached_event_timestamp = current_event_time;

    return 0;
}
				 
unsigned int EventCacheEvent(EventCacheLeaf **eventHead,Unified2EventCommon *inputEvent,unsigned long  event_type,unsigned long event_length)
{
    
    EventCacheLeaf *currentLeaf = NULL;
    EventCacheNode *cacheNode = NULL;
    
    unsigned long unified2EventTime = 0;
    unsigned long event_id = 0;
    
    if( (eventHead == NULL) ||
	(inputEvent == NULL) ||
	(event_length == 0 || event_length > MAX_UNIFIED2_EVENT_LENGTH))
    {
	return 1;
    }
    
    /* This could be adjusted ... */
    unified2EventTime = ntohl(inputEvent->event_second) / EVENT_CACHE_LEAF_TIMESPLIT;
    
    event_id = ntohl(inputEvent->event_id);
    
    currentLeaf = *eventHead;
    
    while(currentLeaf != NULL)
    {
	if(currentLeaf->timeChunk == unified2EventTime)
	{
	    if( (currentLeaf->eventArr[event_id] == NULL))
	    {
		if( (cacheNode =(EventCacheNode *)calloc(1,sizeof(EventCacheNode))) == NULL)
		{
		    /* XXX */
		    return 1;
		}
		
		if( (cacheNode->event_buffer = (void *)calloc(1,event_length)) == NULL)
		{
		    /* XXX */
		    return 1;
		}
		
		currentLeaf->eventArr[event_id] = cacheNode;
		
		cacheNode->event_id = event_id;
		cacheNode->event_second = ntohl(inputEvent->event_second);
		cacheNode->event_type = event_type;
		cacheNode->event_length = event_length;
		
		memcpy(cacheNode->event_buffer,inputEvent,event_length);
		
		cacheNode->event_trigger_count++;
		currentLeaf->event_counter++;
		    
		/* Break of loop */
		return 0;
	    }	       	     		
	    else
	    {
		if( (currentLeaf->eventArr[event_id]->event_second == ntohl(inputEvent->event_second)) &&
		    (currentLeaf->eventArr[event_id]->event_type) == event_type)
		{
		    currentLeaf->eventArr[event_id]->event_duplicata++;
		    return 0;    
		}
		else
		{
		    EventCacheNode *subNode = currentLeaf->eventArr[event_id]->mirror_event;
		    
		    while(subNode != NULL)
		    {
			if( (subNode->event_second == ntohl(inputEvent->event_second)) &&
			    (subNode->event_type == event_type))
			{
			    subNode->event_duplicata++;
			    return 0;
			}
			
			subNode = subNode->mirror_event;
		    }
		    
		    LogMessage("Adding subnode original type[%u] time[%u]  NEW  type[%u] time[%u] \n",
			       currentLeaf->eventArr[event_id]->event_type,
			       currentLeaf->eventArr[event_id]->event_second,
			       event_type,
			       ntohl(inputEvent->event_second));
		    
		    if( (cacheNode =(EventCacheNode *)calloc(1,sizeof(EventCacheNode))) == NULL)
		    {
			/* XXX */
			return 1;
		    }
		    
		    if( (cacheNode->event_buffer = (void *)calloc(1,event_length)) == NULL)
		    {
			/* XXX */
			return 1;
		    }
		    
		    cacheNode->mirror_event = currentLeaf->eventArr[event_id]->mirror_event;
		    currentLeaf->eventArr[event_id]->mirror_event = cacheNode;
		    
		    cacheNode->event_id = event_id;
		    cacheNode->event_second = ntohl(inputEvent->event_second);
		    cacheNode->event_type = event_type;
		    cacheNode->event_length = event_length;
		    
		    memcpy(cacheNode->event_buffer,inputEvent,event_length);

		    currentLeaf->event_counter++;
		    return 0;
		}
	    }
	}
	
	currentLeaf = currentLeaf->next;
    }
    
    
    if( (currentLeaf = (EventCacheLeaf *)calloc(1,sizeof(EventCacheLeaf))) == NULL)
    {
	/* XXX */
	return 1;
    }
    
    currentLeaf->timeChunk = unified2EventTime;
    
    if( (cacheNode =(EventCacheNode *)calloc(1,sizeof(EventCacheNode))) == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if( (cacheNode->event_buffer = (void *)calloc(1,event_length)) == NULL)
    {
	/* XXX */
	return 1;
    }
    
    currentLeaf->eventArr[event_id] = cacheNode;
    
    cacheNode->event_id = event_id;
    cacheNode->event_second = ntohl(inputEvent->event_second);
    cacheNode->event_type = event_type;
    cacheNode->event_length = event_length;
    
    memcpy(cacheNode->event_buffer,inputEvent,event_length);
    
    cacheNode->event_trigger_count++;
    currentLeaf->event_counter++;
    
    currentLeaf->next = *eventHead;
    *eventHead = currentLeaf;
    
    return 0;
}

int ProcessBatch(const char *dirpath, const char *filename)
{
    Spooler             *spooler = NULL;
    int                 ret = 0;
    int                 pb_ret = 0;
    
    
    if( (dirpath == NULL) ||
        (filename == NULL))
    {
	return 1;
    }

    while (exit_signal == 0 && pb_ret == 0)
    {
        switch (spooler->state)
        {
            case SPOOLER_STATE_OPENED:
            case SPOOLER_STATE_RECORD_READ:
                ret = spoolerReadRecordHeader(spooler);

                if (ret == BARNYARD2_READ_EOF)
                {
                    pb_ret = -1;
                }
                else if (ret != 0)
                {
                    LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n", 
                                spooler->filepath, ret);
                    pb_ret = -1;
                }
                break;

            default:
                ret = spoolerReadRecord(spooler);

                if (ret == 0)
                {
                    /* process record, firing output as required */
                    spoolerProcessRecord(spooler,NULL ,1);
                }
                else if (ret == BARNYARD2_READ_EOF)
                {
                    pb_ret = -1;
                }
                else
                {
                    LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n", 
                                spooler->filepath, ret);
                    pb_ret = -1;
                }

                spoolerFreeRecord(&spooler->record);
                break;
        }
    }

    /* we've finished with the spooler so destroy and cleanup */
    spoolerClose(spooler);
    spooler = NULL;

    return pb_ret;
}



unsigned int spoolerProcessWork(Waldo *waldo,Spooler *spooler,off_t offset_target,unsigned short processing_context)
{
    Unified2RecordHeader    *recordHeader = NULL;
    Unified2Packet          *pktptr = NULL;
    
    Unified2EventCommon     *eventCommonPtr = NULL;
    
    Unified2ExtraDataHdr    *extraHeader = NULL;
    Unified2ExtraData       *extraData = NULL;
    
    void *eventPtr = NULL;
    
    Packet decodePkt;
    struct pcap_pkthdr pkth;
    
    int process_context = 0;
    off_t process_offset = 0;
    
    
    process_context = PROCESS_RECORD_HEADER;
    
    while(spooler->current_process_offset < offset_target)
    {
	
    spooler_rebuffer:	
	// Enable for debug mabey.
	//LogMessage("[%s()]: Fast Forwarding to [%u] \n",
	//	   __FUNCTION__,
	//	   waldo->data.last_processed_offset);
	
	if( (spooler->ifn->readBulk(spooler)))
	{
	    /* XXX */
	    return 1;
	}
	
	process_offset = 0;
	
	while(process_offset < spooler->current_read_size)
	{
	    switch(process_context)
	    {
	    case PROCESS_RECORD_HEADER:
		
		recordHeader = (Unified2RecordHeader *)(spooler->read_buffer+process_offset);
		
		if((process_offset + sizeof(Unified2RecordHeader) > spooler->current_read_size))
		{
		    
		    spooler->current_process_offset += process_offset;
		    if( processing_context == SPOOLER_PROCESS_NORMAL)
		    {
			waldo->data.last_processed_offset = spooler->current_process_offset;
		    }
		    
		    spooler->last_read_offset = spooler->current_process_offset;
		    
		    eventPtr = NULL;
		    pktptr = NULL;
		    memset(&pkth,'\0',sizeof(struct pcap_pkthdr));
		    process_context = PROCESS_RECORD_HEADER;

		    if( processing_context == SPOOLER_PROCESS_NORMAL)
		    {
			spoolerWriteWaldo(waldo,spooler);
		    }
		    
		    lseek(spooler->fd,spooler->last_read_offset,SEEK_SET);
		    goto spooler_rebuffer;
		    
		}
		else if( (process_offset + sizeof(Unified2RecordHeader) +  ntohl(recordHeader->length)) > spooler->current_read_size )
		{
		    spooler->current_process_offset += process_offset;

		    if( processing_context == SPOOLER_PROCESS_NORMAL)
                    {
			waldo->data.last_processed_offset = spooler->current_process_offset;
		    }

		    spooler->last_read_offset = spooler->current_process_offset;
		    
		    eventPtr = NULL;
		    pktptr = NULL;
		    memset(&pkth,'\0',sizeof(struct pcap_pkthdr));
		    process_context = PROCESS_RECORD_HEADER;

		    if( processing_context == SPOOLER_PROCESS_NORMAL)
                    {
			spoolerWriteWaldo(waldo,spooler);
		    }
		    
		    lseek(spooler->fd,spooler->last_read_offset,SEEK_SET);
		    goto spooler_rebuffer;
		}
		
		pc.total_records++;
		process_context = PROCESS_RECORD;
		break;
		
	    case PROCESS_RECORD:
		
		switch(ntohl(recordHeader->type))
		{
		    
		case UNIFIED2_IDS_EVENT:
		case UNIFIED2_IDS_EVENT_IPV6:
		case UNIFIED2_IDS_EVENT_VLAN:
		case UNIFIED2_IDS_EVENT_MPLS:
		case UNIFIED2_IDS_EVENT_IPV6_MPLS:
		case UNIFIED2_IDS_EVENT_IPV6_VLAN:

		    eventCommonPtr = (Unified2EventCommon *)(spooler->read_buffer + process_offset + sizeof(Unified2RecordHeader));

		    if( (spooler->current_process_offset == 0) &&
			(ntohl(eventCommonPtr->event_id) == 1))
		    {
			LogMessage("INFO: Destroying [Event cache], detected a unified2 engine re-initialization state \n");
			if( EventCacheDestroy(&spooler->cacheHead))
			{
			    /* XXX */
			    LogMessage("EventCacheDestroy Failed ...\n");
			    return 1;
			}
		    }
		       
		    
		    if( EventCacheEvent(&spooler->cacheHead,eventCommonPtr, ntohl(recordHeader->type),ntohl(recordHeader->length)))
		    {
			LogMessage("EventCacheEvent call failed ... \n");
			return 1;
		    }

		    if(spooler->last_cache_event == 0)
		    {
			spooler->last_cache_event = ntohl(eventCommonPtr->event_second);
		    }
		    
		    if( (spooler->last_cache_event > 0) &&
			(ntohl(eventCommonPtr->event_second) > spooler->last_cache_event) &&
			((ntohl(eventCommonPtr->event_second) - spooler->last_cache_event) >= TAG_PRUNE_TIME))
		    {
			if( (EventCacheClean(&spooler->cacheHead,&spooler->last_cache_event,ntohl(eventCommonPtr->event_second))))
			{
			    /* XXX */
			    LogMessage("EventCacheClean failed \n");
			}
		    }
		    
		    pc.total_events++;
		    break;
		    
		case UNIFIED2_PACKET:
		    pc.total_packets++;
		    
		    pktptr = (Unified2Packet *)(spooler->read_buffer + process_offset + sizeof(Unified2RecordHeader));
		    
		    pkth.ts.tv_sec = ntohl(pktptr->packet_second);
                    pkth.ts.tv_usec = ntohl(pktptr->packet_microsecond);
                    pkth.len = ntohl(pktptr->packet_length);
                    pkth.caplen = pkth.len;
		    
                    DecodePacket(ntohl(pktptr->linktype),
                                 &decodePkt,
                                 &pkth,
                                 pktptr->packet_data);

		    if( processing_context == SPOOLER_PROCESS_NORMAL)
                    {
			eventPtr = EventCacheGetEvent(spooler->cacheHead,ntohl(pktptr->event_id),ntohl(pktptr->event_second),TRIGGER_PACKET);
			
			if( (eventPtr != NULL) &&
			    (pktptr != NULL))
			{
			    CallOutputPlugins(OUTPUT_TYPE__SPECIAL,&decodePkt,eventPtr,UNIFIED2_IDS_EVENT);
			}
			else
			{
			    LogMessage("Orphan packet \n");
			}
		    }
		    
		    break;
		    
		case UNIFIED2_EXTRA_DATA:
		    LogMessage("Unread event [%u] \n",
			       ntohl(recordHeader->type));
		    break;

		default:
		    LogMessage("[%s()]: Unsupported event type -> [%u] of length[%u] current_process_offset[%u] process_offset[%u]\n",
			       __FUNCTION__,
			       ntohl(recordHeader->type),
			       ntohl(recordHeader->length),
			       spooler->current_process_offset,
			       process_offset);
		    return 1;
		    break;
		}
		process_offset += (sizeof(Unified2RecordHeader) + ntohl(recordHeader->length));
		process_context = PROCESS_RECORD_HEADER;
		spooler->record_idx++;

		if( processing_context == SPOOLER_PROCESS_NORMAL)
		{
		    waldo->data.last_processed_offset = spooler->current_process_offset +  process_offset;
		    spoolerWriteWaldo(waldo,spooler);
		}
		
		break;
		
	    default:
		FatalError("Unknown spooler state \n");
		break;
	    }
	}
	
	spooler->current_process_offset += spooler->current_read_size;
    }
    
    return 0;
}


unsigned int spoolerProcess(Waldo *waldo,Spooler *spooler)
{
    if( (waldo == NULL) ||
	(spooler == NULL))
    {
	/* XXX */
	return 1;
    }
    
    /* Check Fd's. */
    if( (spooler->fd < 0) ||
	(waldo->fd < 0))
    {
	/* XXX */
	return 1;
    }
    
spoolerProcess_reevaluate_context:
    if( spooler->current_process_offset < waldo->data.last_processed_offset)
    {
	/* Fast FORWARD */
	if( spoolerProcessWork(waldo,spooler,
			       waldo->data.last_processed_offset,
			       SPOOLER_PROCESS_FASTFORWARD))
	{
	    /* XXX */
	    return 1;
	}

	/* We did fast forward in context, so reset info */
	if(waldo->data.last_processed_offset)
	{
	    memset(spooler->read_buffer,'\0',spooler->current_read_size);
	    
	    if( (lseek(spooler->fd,spooler->current_process_offset,SEEK_SET)) < 0)
	    {
		LogMessage("ERROR: Unable to seek spool file '%s' (%s)\n",
			   spooler->filepath, strerror(errno));
		return 1;
	    }
	    
	    spooler->last_read_offset = spooler->current_process_offset;
	}

	goto spoolerProcess_reevaluate_context;
    }
    else if( spooler->last_read_offset < spooler->spooler_stat.st_size)
    {
	
	if( spoolerProcessWork(waldo,spooler,
			       spooler->spooler_stat.st_size,
			       SPOOLER_PROCESS_NORMAL))
	{
	    /* XXX */
	    return 1;
	}
    }
    
    return 0;
}

/*
** ProcessContinuous(InputConfig *iContext)
**
*/
int ProcessContinuous(InputConfig *iContext)
{
    unsigned long extension = 0;

    unsigned long last_record_count = 0;

    time_t last_print_time = 0;
    time_t current_time = 0;



    Spooler *spooler = NULL;
    Waldo *waldo = NULL;
    
    if(iContext == NULL)
    {
	/* XXX */
	return 1;
    }
    
    /* Set context */
    spooler = &((Unified2InputPluginContext *)iContext->context)->spooler;
    waldo  = &((Unified2InputPluginContext *)iContext->context)->waldo;
    spooler->max_read_size = ((Unified2InputPluginContext *)iContext->context)->read_size;
    spooler->read_buffer = ((Unified2InputPluginContext *)iContext->context)->read_buffer;
    
    while(exit_signal == 0)
    {
	/* Could have other uses? */
	current_time = time(NULL);
	
	/* General entry block when we start */
	
	if( (waldo->data.timestamp != 0) &&
	    (spooler->fd <= 0))
	{
	    /* Open last recorded spool file */
	    if( (spoolerOpen(spooler,
			     waldo->data.spool_dir,
			     waldo->data.spool_filebase,
			     waldo->data.timestamp)))
	    {
		/* XXX */
		return 1;
	    }
	    
	    if(fstat(spooler->fd,
		     &spooler->spooler_stat))
	    {
		LogMessage("ERROR: Unable to stat spool file '%s' (%s)\n",
			   spooler->filepath, strerror(errno));
		return 1;
	    }
	    
	    if( (spoolerProcess(waldo,spooler)))
	    {
		/* XXX */
		return 1;
	    }
	    
	}
	/* 
	   Checking current file, if size changed since last loop, 
	   process, else look for new file 
	*/
	else if( (waldo->data.timestamp != 0) && 
		 (spooler->fd > 0))
	{
	    
	    if(fstat(spooler->fd,
		     &spooler->spooler_stat))
	    {
		LogMessage("ERROR: Unable to stat spool file '%s' (%s)\n",
			   spooler->filepath, strerror(errno));
		return 1;
	    }
	    
	    if((spooler->spooler_stat.st_size == spooler->last_read_offset))
	    {
		if( FindNextExtension(waldo->data.spool_dir,
				      waldo->data.spool_filebase,
				      waldo->data.timestamp,
				      &extension))
		{
		    sleep(1);
		    if( (current_time - last_print_time) > SPOOLER_PRINT_DELAY)
		    {
			last_print_time = current_time;
			LogMessage("Waiting for new data in [%s/%s.%u] or a new unified2 file in [%s/] processed record delta [%u]\n",
				   waldo->data.spool_dir, 
				   waldo->data.spool_filebase,
				   waldo->data.timestamp,
				   waldo->data.spool_dir,
			           (spooler->record_idx - last_record_count));
			
			last_record_count = spooler->record_idx;
		    }
		    continue;
		}
		
		waldo->data.timestamp = extension;		
		spooler->record_idx = 0;
		waldo->data.last_processed_offset = 0;
		last_record_count = 0;
		
		if( (spoolerOpen(spooler,
				 waldo->data.spool_dir,
				 waldo->data.spool_filebase,
				 waldo->data.timestamp)))
		{
		    /* XXX */
		    return 1;
		}
		
		spooler->max_read_size = ((Unified2InputPluginContext *)iContext->context)->read_size;
		spooler->read_buffer = ((Unified2InputPluginContext *)iContext->context)->read_buffer;
		
		if( (spoolerWriteWaldo(waldo, spooler)))
		{
		    /* XXX */
		    return 1;
		}
	    }
	    /* This is where the actual processing occur or data was appended. */
	    else
	    {

		spooler->max_read_size = ((Unified2InputPluginContext *)iContext->context)->read_size;
		spooler->read_buffer = ((Unified2InputPluginContext *)iContext->context)->read_buffer;
		
		if( (spoolerProcess(waldo,spooler)))
		{
		    /* XXX */
		    return 1;
		}
	    }
	}
	/* We have no file */
	else
	{
	    if( FindNextExtension(waldo->data.spool_dir,
				  waldo->data.spool_filebase,
				  waldo->data.timestamp,
				  &extension))
	    {
		sleep(1);
		if( (current_time - last_print_time) > SPOOLER_PRINT_DELAY)
		{
		    last_print_time = current_time;
		    LogMessage("Waiting for a valid unified2 file in [%s/] \n",
			       waldo->data.spool_dir);
		    continue;
		}
	    }
	    
	    waldo->data.timestamp = extension;
	    spooler->record_idx = 0;
	    waldo->data.last_processed_offset = 0;

	    if( (spoolerOpen(spooler,
			     waldo->data.spool_dir,
			     waldo->data.spool_filebase,
			     waldo->data.timestamp)))
	    {
		/* XXX */
		return 1;
	    }
	    
	    spooler->max_read_size = ((Unified2InputPluginContext *)iContext->context)->read_size;
	    spooler->read_buffer = ((Unified2InputPluginContext *)iContext->context)->read_buffer;
	    
	    if( (spoolerWriteWaldo(waldo, spooler)))
	    {
		/* XXX */
		return 1;
	    }
	    
	}
    }
    
    spoolerCloseWaldo(waldo);
    return 0;
}


int ProcessContinuousWithWaldo(InputConfig *iContext)
{
    if (iContext == NULL)
        return -1;
    
    return ProcessContinuous(iContext);
}


/*
** RECORD PROCESSING EVENTS
*/

int spoolerProcessRecord(Spooler *spooler,Waldo *waldo, int fire_output)
{
    struct pcap_pkthdr      pkth;
    uint32_t                type;
    EventRecordNode         *ernCache;

    /* convert type once */
    type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);
    /* increment the stats */
    pc.total_records++;
    
    switch (type)
    {
    case UNIFIED2_PACKET:
	pc.total_packets++;
	break;
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_MPLS:
    case UNIFIED2_IDS_EVENT_IPV6_MPLS:
    case UNIFIED2_IDS_EVENT_VLAN:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
	pc.total_events++;
	break;
    default:
	pc.total_unknown++;
    }

    /* check if it's packet */
    if (type == UNIFIED2_PACKET)
    {
        /* convert event id once */
        uint32_t event_id = ntohl(((Unified2Packet *)spooler->record.data)->event_id);

        /* check if there is a previously cached event that matches this event id */
        ernCache = spoolerEventCacheGetByEventID(spooler, event_id);

        /* allocate space for the packet and construct the packet header */
        spooler->record.pkt = SnortAlloc(sizeof(Packet));

        pkth.caplen = ntohl(((Unified2Packet *)spooler->record.data)->packet_length);
        pkth.len = pkth.caplen;
        pkth.ts.tv_sec = ntohl(((Unified2Packet *)spooler->record.data)->packet_second);
        pkth.ts.tv_usec = ntohl(((Unified2Packet *)spooler->record.data)->packet_microsecond);

        /* decode the packet from the Unified2Packet information */
        datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);
        DecodePacket(datalink, spooler->record.pkt, &pkth, 
                     ((Unified2Packet *)spooler->record.data)->packet_data);

	/* This is a fixup for portscan... */
	if( (spooler->record.pkt->iph == NULL) && 
	    ((spooler->record.pkt->inner_iph != NULL) && (spooler->record.pkt->inner_iph->ip_proto == 255)))
	    {
		spooler->record.pkt->iph = spooler->record.pkt->inner_iph;
	    }

        /* check if it's been re-assembled */
        if (spooler->record.pkt->packet_flags & PKT_REBUILT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Packet has been rebuilt from a stream\n"););
        }

        /* if the packet and cached event share the same id */
        if ( ernCache != NULL )
        {
            /* call output plugins with a "SPECIAL" alert format (both Event and Packet information) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing SPECIAL style (Packet+Event)\n"););

            if ( fire_output && 
                 ((ernCache->used == 0) || BcAlertOnEachPacketInStream()) )
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL, 
                              spooler->record.pkt, 
                              ernCache->data, 
                              ernCache->type);

            /* indicate that the cached event has been used */
            ernCache->used = 1;
        }
        else
        {
            /* fire the event cache head only if not already used (ie dirty) */ 
            if ( spoolerEventCacheHeadUsed(spooler) == 0 )
            {
                ernCache = spoolerEventCacheGetHead(spooler);

                /* call output plugins with an "ALERT" format (cached Event information only) */
                DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

                if (fire_output)
                    CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                                      NULL,
                                      ernCache->data, 
                                      ernCache->type);

                /* set the event cache used flag */
                ernCache->used = 1;
            }

            /* call output plugins with a "LOG" format (Packet information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing LOG style (Packet)\n"););

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                  spooler->record.pkt, 
                                  NULL, 
                                  0);
        }

        /* free the memory allocated in this function */
        free(spooler->record.pkt);
        spooler->record.pkt = NULL;

        /* waldo operations occur after the output plugins are called */
        if ( (fire_output) &&
	     (waldo != NULL))
	{
            if( (spoolerWriteWaldo(waldo, spooler)))
	    {
		/* XXX */
		return 1;
	    }
	}
    }
    /* check if it's an event of known sorts */
    else if(type == UNIFIED2_IDS_EVENT || type == UNIFIED2_IDS_EVENT_IPV6 ||
            type == UNIFIED2_IDS_EVENT_MPLS || type == UNIFIED2_IDS_EVENT_IPV6_MPLS ||
            type == UNIFIED2_IDS_EVENT_VLAN || type == UNIFIED2_IDS_EVENT_IPV6_VLAN)
    {
        /* fire the cached event only if not already used (ie dirty) */ 
        if ( spoolerEventCacheHeadUsed(spooler) == 0 )
        {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                              NULL,
                              ernCache->data, 
                              ernCache->type);

            /* flush the event cache flag */
            ernCache->used = 1;
        }

        /* cache new data */
        spoolerEventCachePush(spooler, type, spooler->record.data);
        spooler->record.data = NULL;

        /* waldo operations occur after the output plugins are called */
        if((fire_output) &&
	   waldo != NULL)
	{
            if( (spoolerWriteWaldo(waldo, spooler)))
	    {
		/* XXX */
		return 1;
	    }
	}
    }
    else if (type == UNIFIED2_EXTRA_DATA)
    {
        /* waldo operations occur after the output plugins are called */
        if((fire_output) &&
	   (waldo != NULL))
	{
            if( (spoolerWriteWaldo(waldo, spooler)))
	    {
		/* XXX */
		return 1;
	    }
	}
    }
    else
    {
        /* fire the cached event only if not already used (ie dirty) */ 
        if ( spoolerEventCacheHeadUsed(spooler) == 0 )
        {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                              NULL,
                              ernCache->data, 
                              ernCache->type);

            /* waldo operations occur after the output plugins are called */
            if( (fire_output) && 
		(waldo != NULL))
	    {
                if( (spoolerWriteWaldo(waldo, spooler)))
		{
		    /* XXX */
		    return 1;
		}
	    }
        }
    }
    
    /* clean the cache out */
    spoolerEventCacheClean(spooler);
    return 0;
}

int spoolerEventCachePush(Spooler *spooler, uint32_t type, void *data)
{
    EventRecordNode     *ernNode;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Caching event...\n"););

    /* allocate memory */
    ernNode = (EventRecordNode *)SnortAlloc(sizeof(EventRecordNode));

    /* create the new node */
    ernNode->used = 0;
    ernNode->type = type;
    ernNode->data = data;

    /* add new events to the front of the cache */
    ernNode->next = spooler->event_cache;

    spooler->event_cache = ernNode;
    spooler->events_cached++;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Cached event: %d\n", spooler->events_cached););

    return 0;
}

EventRecordNode *spoolerEventCacheGetByEventID(Spooler *spooler, uint32_t event_id)
{
    EventRecordNode     *ernCurrent = spooler->event_cache;

    while (ernCurrent != NULL)
    {
        if ( ntohl(((Unified2EventCommon *)ernCurrent->data)->event_id) == event_id )
        {
            return ernCurrent;
        }

        ernCurrent = ernCurrent->next;
    }

    return NULL;
}

EventRecordNode *spoolerEventCacheGetHead(Spooler *spooler)
{
    if ( spooler == NULL )
        return NULL;

    return spooler->event_cache;
}

uint8_t spoolerEventCacheHeadUsed(Spooler *spooler)
{
    if ( spooler == NULL || spooler->event_cache == NULL )
        return 255;

    return spooler->event_cache->used;
}

int spoolerEventCacheClean(Spooler *spooler)
{
    EventRecordNode     *ernCurrent = NULL;
    EventRecordNode     *ernPrev = NULL;
    EventRecordNode     *ernNext = NULL;
    
    if (spooler == NULL || spooler->event_cache == NULL )
        return 1;
    
    ernPrev = spooler->event_cache;
    ernCurrent = spooler->event_cache;
    
    while (ernCurrent != NULL && spooler->events_cached > barnyard2_conf->event_cache_size )
    {
	ernNext = ernCurrent->next;
	
	if ( ernCurrent->used == 1 )
        {
	    /* Delete from list */
	    if (ernCurrent == spooler->event_cache)
	    {
                spooler->event_cache = ernNext;
	    }
            else
	    {
                ernPrev->next = ernNext;
	    }
	    
            spooler->events_cached--;

	    if(ernCurrent->data != NULL)
	    {
		free(ernCurrent->data);
	    }
	    
	    if(ernCurrent != NULL)
	    {
		free(ernCurrent);
	    }
        }
	
	if(ernCurrent != NULL)
	{
	    ernPrev = ernCurrent;
	}
	
	ernCurrent = ernNext;

    }

    return 0;
}

void spoolerFreeRecord(Record *record)
{
    if (record->data)
    {
        free(record->data);
    }
    
    record->data = NULL;
}


/*
** WALDO FILE OPERATIONS
*/

/*
** spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
**
** Description:
**   Open the waldo file, non-blocking, defined in the Waldo structure
*/
int spoolerOpenWaldo(Waldo *waldo)
{

    Spooler mockSpooler = {0}; /* Only used if we create a new waldo file */
    struct stat         waldo_info;
    int                 waldo_file_flags = 0;
    mode_t              waldo_file_mode = 0;
    
    if( (waldo == NULL) )
    {
	/* XXX */
	return 1;
    }
    
    /* check if waldo file is already open and in the correct mode */
    if( !(waldo->state & WALDO_STATE_ENABLED))
    {
	return WALDO_FILE_SUCCESS;
    }
    
    /* stat the file to see it exists */
    if( (stat(waldo->filepath, &waldo_info)))
    {
	/* XXX */
        LogMessage("WARNING: Unable to stat waldo file '%s' (%s)\n", waldo->filepath,
		   strerror(errno));
	
	waldo_file_flags = ( O_CREAT | O_RDWR );	
    }
    else
    {
	waldo_file_flags = ( O_RDWR );
    }
    
    waldo_file_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ) ;
    
    if ( (waldo->fd=open(waldo->filepath, waldo_file_flags, waldo_file_mode)) < 0)
    {
        LogMessage("WARNING: Unable to open waldo file '%s' (%s)\n", waldo->filepath,
		   strerror(errno));
        return WALDO_FILE_EOPEN;
    }
    
    if(waldo_file_flags & O_CREAT)
    {
	if( spoolerWriteWaldo(waldo,&mockSpooler))
	{
	    /* XXX */
	    return 1;
	}
    }

    
    return WALDO_FILE_SUCCESS;
}

/*
** spoolerCloseWaldo(Waldo *waldo)
**
** Description:
**   Open the waldo file, non-blocking, defined in the Waldo structure
**
*/
int spoolerCloseWaldo(Waldo *waldo)
{
    if(waldo == NULL)
    {
	return 1;
    }
    
    /* close the file */
    if(waldo->fd)
    {
	close(waldo->fd);
	waldo->fd = -1;
    }
    
    return 0;
}

/*
** spoolReadWaldo(Waldo *waldo) 
**
** Description:
**   Read the waldo file defined in the Waldo structure and populate all values
** within.
**
*/
int spoolerReadWaldo(Waldo *waldo)
{
    WaldoData wd;
    off_t cur_pos = 0;
    
    if( (waldo == NULL))
    {
	return 1;
    }
    
    /* ensure we are at the beggining since we must be open and in read */
    if( (cur_pos = lseek(waldo->fd, 0, SEEK_SET)) < 0)
    {
	LogMessage("ERROR: lseek() Waldo file '%s' (%s)\n", 
		   waldo->filepath,
		   strerror(errno));
	return 1;
    }
    
    /* read values into temporary WaldoData structure */
    if(read(waldo->fd, &wd, sizeof(WaldoData)) < 0)
    {
	LogMessage("ERROR: Reading Waldo file '%s' (%s)\n", 
		   waldo->filepath,
		   strerror(errno));
	return 1;
    }
    

    if( (cur_pos = lseek(waldo->fd,0,SEEK_CUR)) < 0)
    {
	LogMessage("ERROR: lseek() Waldo file '%s' (%s)\n", 
		   waldo->filepath,
		   strerror(errno));
	return 1;
    }
    
    if ( cur_pos != sizeof(WaldoData) )
    {
	/* XXX */
	LogMessage("ERROR: Waldo file size is incorrect read[%u] expecting[%u] for file [%s] \n"
		   ">>>Delete waldo and restart barnyard2<<<\n\n",
		   cur_pos,
		   sizeof(WaldoData),
		   waldo->filepath);
	return 1;
    }
    
    if( (memcmp(waldo->data.spool_dir,wd.spool_dir,strlen(wd.spool_dir)) != 0) ||
	(memcmp(waldo->data.spool_filebase,wd.spool_filebase,strlen(wd.spool_filebase)) != 0))
    {
	LogMessage("ERROR: Waldo file inconsistency: \n"
		   "[Waldo File]:        Spool Direcyory [%s] - Stored Filebase [%s] \n"
		   "[Barnyard2 runtime]: Spool Directory [%s] - Invoke Filebase [%s] \n"
		   ">>>Delete waldo and restart barnyard2<<<\n\n",
		   wd.spool_dir,wd.spool_filebase,
		   waldo->data.spool_dir,waldo->data.spool_filebase);
	return 1;
    }
    
    /* copy waldo file contents to the directory structure */
    memcpy(&waldo->data, &wd, sizeof(WaldoData));
    
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
			    "Waldo read\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
			    waldo->data.spool_dir, waldo->data.spool_filebase,
			    waldo->data.timestamp, waldo->data.record_idx););
    
    return WALDO_FILE_SUCCESS;
}

/*
** spoolerWriteWaldo(Waldo *waldo)
**
** Description:
**   Write to the waldo file
**
*/
int spoolerWriteWaldo(Waldo *waldo, Spooler *spooler)
{
    if( (waldo == NULL) ||
	(spooler == NULL) )
    {
	/* xxx */
	return 1;
    }
    
    /* check if we are using waldo files */
    if( !(waldo->state & WALDO_STATE_ENABLED))
    {
        return 1;
    }
    
    /* update fields */
    waldo->data.timestamp = spooler->timestamp;
    waldo->data.record_idx = spooler->record_idx;
    
    /* ensure we are at the start since we must be open and in write */
    lseek(waldo->fd, 0, SEEK_SET);
    
    /* write values */
    if( (write(waldo->fd, &waldo->data, sizeof(WaldoData))) != sizeof(WaldoData))
    {
        return WALDO_FILE_ETRUNC;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
        "Waldo write\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
        waldo->data.spool_dir, waldo->data.spool_filebase,
        waldo->data.timestamp, waldo->data.record_idx););

    return WALDO_FILE_SUCCESS;
}

