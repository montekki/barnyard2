#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include "barnyard2.h"
#include "debug.h"
#include "plugbase.h"
#include "unified2.h"
#include "zmq_spooler.h"
#include "sensor_cache.h"

#include <czmq.h>

void ZMQInit(char *);

typedef struct zmq_server {
    char	*mycertpath;
    char	*endpoint;
    char	*authdir;
    zauth_t	*auth;
    zctx_t	*ctx;
    zcert_t	*mycert;
    void *socket;
} zmq_server_t;


void ZMQSetup(void)
{

    RegisterInputPlugin("zmq", ZMQInit);
}

static zmq_server_t *connection = NULL;

void ZMQInit(char * args)
{
    size_t argsize;
    char *arg_tmp, *delim;

    connection = malloc (sizeof (zmq_server_t));
    memset (connection, 0, sizeof (zmq_server_t));

    arg_tmp = strtok (args, ", ");

    while (arg_tmp) {
        delim = strchr (arg_tmp, '=');

        if (strncmp (arg_tmp, "servercert", strlen ("servercert")) == 0) {
            argsize = strlen (delim);
            connection->mycertpath = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->mycertpath, delim + 1, argsize);
            connection->mycertpath[argsize] = '\0';
        } else if (strncmp (arg_tmp, "authorizedcertsdir",
                    strlen ("authorizedcertsdir")) == 0) {
            argsize = strlen (delim);
            connection->authdir = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->authdir, delim + 1, argsize);
            connection->authdir[argsize] = '\0';
        } else if (strncmp (arg_tmp, "endpoint", strlen ("endpoint")) == 0) {
            argsize = strlen (delim);
            connection->endpoint = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->endpoint, delim + 1, argsize);
            connection->endpoint[argsize] = '\0';
        }

        arg_tmp = strtok (NULL, ", ");
    }

    if (!connection->mycertpath) {
        ErrorMessage ("zmq: server cert path is not specified\n");
        goto out_err;
    }

    if (!connection->authdir) {
        ErrorMessage ("zmq: server authorized certificates dir not specified\n");
        goto out_err;
    }

    if (!connection->endpoint) {
        ErrorMessage ("zmq: server endpoint not specified\n");
        goto out_err;
    }

    connection->ctx = zctx_new ();
    connection->auth = zauth_new (connection->ctx);
    zauth_set_verbose (connection->auth, true);

    zauth_configure_curve (connection->auth, "*", connection->authdir);

    connection->mycert = zcert_load (connection->mycertpath);

    connection->socket = zsocket_new (connection->ctx, ZMQ_REP);

    zcert_apply (connection->mycert, connection->socket);
    zsocket_set_curve_server (connection->socket, 1);

    if (zsocket_bind (connection->socket, "%s", connection->endpoint) == -1) {
        ErrorMessage ("zmq: Failed to bind to socket!\n");
        goto out_err;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: AlertZMQ initialized\n"););
    return;

out_err:
    FatalError ("Exiting...");
}

int zmq_loop ()
{
    int ret;
    Packet p;
    u_int32_t sid;
    zmq_msg_t msg;
    ZMQEventMessage *message;
    struct pcap_pkthdr pkthdr;

    if (!connection)
        return 0;

    zmq_pollitem_t items [] = { {connection->socket, 0, ZMQ_POLLIN, 0 } };

    while (exit_signal == 0) {
        zmq_msg_init (&msg);

        ret = zmq_poll (items, 1, 3 * 2500);

        if (ret < 0) {
            ErrorMessage ("zmq: Failed to call zmq_poll: %s\n", strerror (errno));
            break;
        } else if (!ret) {
            continue;
	} else if (!(items[0].revents & ZMQ_POLLIN)) {
            continue;
	}

        ret = zmq_recvmsg (connection->socket, &msg, 0);

        if (ret == -1)
            break;

        message = zmq_msg_data (&msg);

        if (message->event_type == UNIFIED2_SENSOR_INFO ) {
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "zmq: arrived sensor with name %s\n",
                        message->add_info.info.sensor_name););
            CallOutputPlugins (1, 0, message, message->event_type);

            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "zmq: arrived sensor with name %s\n",
                        message->add_info.info.sensor_name););

            sid = SensorInfoToId (&message->add_info.info);
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "zmq: sid %u\n", sid););

            zmq_msg_close (&msg);
            zmq_msg_init_size (&msg, sizeof (u_int32_t));

            *(u_int32_t*)zmq_msg_data (&msg) = htonl (sid);

            ret = zmq_sendmsg (connection->socket, &msg, 0);

            continue;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "zmq: event sensor id %d event id %d length %d\n",
                ntohl (message->event.sensor_id),
                ntohl (message->event.event_id),
                message->packetlen););

        pkthdr.caplen = pkthdr.len = message->packetlen;
        pkthdr.ts.tv_sec = message->tv_sec;
	pkthdr.ts.tv_usec = message->tv_usec;

        DecodePacket (ntohl (message->linktype), &p, &pkthdr, message->add_info.packet);
        CallOutputPlugins (1, &p, &message->event, message->event_type);

        zmq_msg_close (&msg);
        zstr_send (connection->socket, "OK");
    }

    FatalError ("Shutting down zmq spooler\n");
    return 1;
}
