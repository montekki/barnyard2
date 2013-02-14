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

#ifndef __SPI_UNIFIED2_H__
#define __SPI_UNIFIED2_H__

#include "spooler.h"

typedef struct _Unified2InputPluginContext 
{
    ssize_t   read_size;
    u_int32_t operation_mode;
    
    Waldo waldo;
    Spooler spooler;
    
    char *read_buffer;

} Unified2InputPluginContext;

#include "decode.h"

#define UNIFIED2_MAX_EVENT_SIZE (sizeof(Unified2RecordHeader) + sizeof(Unified2IDSEventIPv6_legacy) + IP_MAXPACKET)


#define LogContextLOGUNIFIED2   0x000000001
#define LogContextALERTUNIFIED2 0x000000002
#define LogContextUNIFIED2      0x000000004

#define DefaultBlockSize 4096
#define ReadSizeDefault 4



/*
** PROTOTYPES
*/
void * Unified2Init(char *);
Unified2InputPluginContext * parseUnified2InputArgs(char *args);

/* processing functions  */
u_int32_t Unified2GetStat(void *sph);
u_int32_t Unified2Rewind(void *sph);

int Unified2ReadRecordHeader(void *);
int Unified2ReadRecord(void *);

int Unified2ReadEventRecord(void *);
int Unified2ReadEvent6Record(void *);
int Unified2ReadPacketRecord(void *);

void Unified2PrintCommonRecord(Unified2EventCommon *);
void Unified2PrintEventRecord(Unified2IDSEvent_legacy *);
void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *);
void Unified2PrintPacketRecord(Unified2Packet *);

/* restart/shutdown functions */
void Unified2CleanExitFunc(int, void *);
void Unified2RestartFunc(int, void *);


void Unified2PrintEventRecord(Unified2IDSEvent_legacy *);
void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *);

void Unified2Setup(void);

#endif /* __SPI_UNIFIED2_H__ */
