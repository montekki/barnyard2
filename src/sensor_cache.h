#ifndef SENSOR_CACHE_H
#define SENSOR_CACHE_H

#include "zmq_spooler.h"

typedef struct _SensorInfo {
    char name[ZMQ_MAX_NAMELEN];
    char interface[ZMQ_MAX_NAMELEN];
    char filter[ZMQ_MAX_NAMELEN];
    u_int32_t sid;
    u_int32_t cid;
} SensorInfo;

typedef struct _SensorInfoCache {
    size_t capacity;
    size_t size;
    SensorInfo infoArray[0];
} SensorInfoCache;

u_int32_t SensorInfoToId(ZMQSensorInfoMessage *msg);
u_int32_t GetSensorCid(u_int32_t sid);
u_int32_t UpdateSensorCid(u_int32_t sid, u_int32_t cid);
int AddSensorInfo(ZMQSensorInfoMessage *msg, u_int32_t sid, u_int32_t cid);

int InitSensorCache();
void FreeSensorCache();

#endif /* SENSOR_CACHE_H */
