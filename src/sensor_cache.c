#include <stdlib.h>
#include <string.h>
#include "sensor_cache.h"

SensorInfoCache *cache = 0;

u_int32_t SensorInfoToId(ZMQSensorInfoMessage *msg)
{
    size_t i;

    for (i = 0; i < cache->size; i++) {
        if (!strcmp (msg->sensor_name, cache->infoArray[i].name)
                && !strcmp (msg->interface, cache->infoArray[i].interface)
                && !strcmp (msg->filter, cache->infoArray[i].filter)) {
            return cache->infoArray[i].sid;
        }
    }

    return 0;
}

u_int32_t GetSensorCid(u_int32_t sid)
{
    size_t i;

    for (i = 0; i < cache->size; i++) {
        if (cache->infoArray[i].sid == sid)
            return cache->infoArray[i].cid;
    }

    return 0;
}

u_int32_t UpdateSensorCid(u_int32_t sid, u_int32_t cid)
{
    size_t i;

    for (i = 0; i < cache->size; i++) {
        if (cache->infoArray[i].sid == sid) {
            cache->infoArray[i].cid = cid;
            return 0;
        }
    }

    return 1;
}

int AddSensorInfo(ZMQSensorInfoMessage *msg, u_int32_t sid, u_int32_t cid)
{
    size_t i;

    if (cache->capacity == cache->size) {
        cache = realloc (cache, sizeof(SensorInfoCache) +
                cache->capacity * 2 * sizeof (SensorInfo));
        cache->capacity *= 2;
    }

    for (i = 0; i < cache->size; i++) {
        if (!strcmp (msg->sensor_name, cache->infoArray[i].name)
                && !strcmp (msg->interface, cache->infoArray[i].interface)
                && !strcmp (msg->filter, cache->infoArray[i].filter)) {
                    cache->infoArray[i].sid = sid;
                    cache->infoArray[i].cid = cid;
                    return 0;
        }
    }

    strncpy (cache->infoArray[cache->size].name,
            msg->sensor_name, ZMQ_MAX_NAMELEN);
    strncpy (cache->infoArray[cache->size].interface,
            msg->interface, ZMQ_MAX_NAMELEN);
    strncpy (cache->infoArray[cache->size].filter,
            msg->filter, ZMQ_MAX_NAMELEN);

    cache->infoArray[cache->size].sid = sid;
    cache->infoArray[cache->size].cid = cid;

    cache->size++;

    return 0;
}

int InitSensorCache()
{
    cache = malloc (sizeof (SensorInfoCache) +
            16 * sizeof (SensorInfo));

    cache->capacity = 16;
    cache->size = 0;

    if (cache)
        return 0;

    else
        return -1;
}

void FreeSensorCache()
{
    free (cache);

    return;
}
