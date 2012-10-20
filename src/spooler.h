/* 
**
** Copyright (C) 2008-2012 Ian Firns (SecurixLive) <dev@securixlive.com>
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

#ifndef __SPOOLER_H__
#define __SPOOLER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "decode.h"
#include "plugbase.h"
#include "unified2.h"

#define SPOOLER_EXTENSION_FOUND     0
#define SPOOLER_EXTENSION_NONE      1
#define SPOOLER_EXTENSION_EPARAM    2
#define SPOOLER_EXTENSION_EOPEN     3

#define SPOOLER_STATE_OPENED        0
#define SPOOLER_STATE_HEADER_READ   1
#define SPOOLER_STATE_RECORD_READ   2

#define WALDO_STATE_ENABLED         0x01

#define WALDO_MODE_NULL             0
#define WALDO_MODE_READ             1
#define WALDO_MODE_WRITE            2

#define WALDO_FILE_SUCCESS          0
#define WALDO_FILE_EEXIST           1

#define WALDO_FILE_EOPEN            2
#define WALDO_FILE_ETRUNC           3
#define WALDO_FILE_ECORRUPT         4
#define WALDO_STRUCT_EMPTY          10

#define MAX_FILEPATH_BUF    1024

#define PROCESS_RECORD_HEADER 0x00000001
#define PROCESS_RECORD        0x00000002


#define SPOOLER_PROCESS_FASTFORWARD 0x00000001
#define SPOOLER_PROCESS_NORMAL      0x00000002


#define TAG_PRUNE_TIME 301 /* From snort tag.c plus 1 :) */

#define EVENT_CACHE_LEAF_TIMESPLIT 3600

#define SPOOLER_PRINT_DELAY 600 /* 10 minutes */

typedef struct _Record
{
/* raw data */
void                *header;
void                *data;
Packet              *pkt;       /* decoded packet */
} Record;


typedef struct _EventRecordNode
{
uint32_t                type;   /* type of event stored */
void                    *data;  /* unified2 event (eg IPv4, IPV6, MPLS, etc) */
uint8_t                 used;   /* has the event be retrieved */

struct _EventRecordNode *next;  /* reference to next event record */
} EventRecordNode;

typedef struct _PacketRecordNode
{
Packet                  *data;  /* packet information */

struct _PacketRecordNode *next; /* reference to next event record */
} PacketRecordNode;


/* See unified2.h for largest structure */
#define MAX_UNIFIED2_EVENT_LENGTH sizeof(Unified2IDSEventIPv6)
#define TRIGGER_PACKET     0x0001
#define TRIGGER_EXTRA_DATA 0x0002

typedef struct _EventCacheNode
{
    unsigned long event_id;           /* Safety */
    unsigned long event_second;
    unsigned long event_type;
    
    unsigned long event_trigger_count;
    unsigned long event_trigger_packet;
    unsigned long event_trigger_extra_data;
    
    unsigned long event_duplicata;
    unsigned long event_length;
    void *event_buffer;
    
    
    struct _EventCacheNode *mirror_event; 
    
} EventCacheNode;



typedef struct _EventCacheLeaf 
{
    unsigned long timeChunk; /* seconds / 3600 */
    unsigned long event_counter;
    EventCacheNode *eventArr[USHRT_MAX+1]; /* event_id from snort span from 0 to 65535 when considering rollback */
    struct _EventCacheLeaf *next;
} EventCacheLeaf;


typedef struct _WaldoData
{
    char spool_dir[MAX_FILEPATH_BUF];
    char spool_filebase[MAX_FILEPATH_BUF];
    uint32_t timestamp;
    uint32_t record_idx;
    off_t last_processed_offset;
} WaldoData;

typedef struct _Waldo
{
    
    int fd;                          // file descriptor of the waldo
    char filepath[MAX_FILEPATH_BUF]; // filepath to the waldo
    
    int state;

    WaldoData data;    

} Waldo;


typedef struct _Spooler
{
    struct _InputFuncNode *ifn;  // Processing function of input file

    struct stat unified2_stat;
    int fd;
    char filepath[MAX_FILEPATH_BUF];
    u_int32_t timestamp;
    
    int state;
    int offset;
    
    struct stat spooler_stat;
    char *read_buffer;   /* Imported from Unified2InputPluginContext */
    off_t max_read_size; /* Imported from Unified2InputPluginContext */
    
    off_t current_read_size;
    off_t file_size;
    off_t last_read_offset;
    off_t current_process_offset;
    
    unsigned long record_idx;
    Record record;     // data of current Record

    
    EventCacheLeaf *cacheHead;
    unsigned long last_cache_event;
    

    /* Depricated to be deleted */ 
    uint32_t packets_cached;
    uint32_t events_cached;
    PacketRecordNode *packet_cache; // linked list of concurrent packets
    EventRecordNode *event_cache; // linked list of cached events
    /* Depricated to be deleted */
} Spooler;



#endif /* __SPOOLER_H__ */


