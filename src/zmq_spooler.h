#ifndef ZMQ_SPOOLER_H
#define ZMQ_SPOOLER_H

#define		ZMQ_MAX_PACKETLEN	2048
#define		ZMQ_MAX_NAMELEN		256

#include <stdint.h>
#include "unified2.h"
#include "decode.h"

enum BarnyardZMQMessageType {
    EventMessage,
    SensorInfoMessage,
    HeartBeatMessage,
};

typedef struct _ZMQSensorInfoMessage {
    uint32_t type;
    char sensor_name[ZMQ_MAX_NAMELEN];
    char interface[ZMQ_MAX_NAMELEN];
    char filter[ZMQ_MAX_NAMELEN];
} __attribute__((packed)) ZMQSensorInfoMessage;

typedef struct _ZMQEventMessage {
    uint32_t type;
    Unified2EventCommon event;
    uint32_t sid;
    uint32_t packetlen;
    uint32_t linktype;
    uint32_t event_type;
    uint64_t tv_sec;
    uint64_t tv_usec;

    union {
        uint8_t packet[ZMQ_MAX_PACKETLEN];
        ZMQSensorInfoMessage info;
    } add_info;
} __attribute__((packed)) ZMQEventMessage;

extern int zmq_loop ();

#endif /* ZMQ_SPOOLER_H */
