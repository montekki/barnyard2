/*
** Copyright (C) 2014 Fedor Sakharov <sakharov@group-ib.com>
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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#include <czmq.h>

#include "barnyard2.h"
#include "decode.h"
#include "plugbase.h"
#include "unified2.h"
#include "zmq_spooler.h"
#include "ctype.h"

#define REQUEST_TIMEOUT		2500
#define REQUEST_RETRIES		3

typedef struct zmq_conn {
    char	*mycertpath;
    char	*servercertpath;
    char	*serverendpoint;
    zcert_t	*mycert;
    zcert_t	*servercert;
    zsock_t *socket;
    char	*sensor_name;
    u_int32_t sid;
} zmq_conn_t;

static void AlertZMQInit(char *);
static void AlertZMQCleanup(int signal, void *arg, const char *msg);
static void AlertZMQ(Packet *p, void *event, uint32_t event_type, void *arg);
static void AlertZMQCleanExitFunc(int signal, void *arg);
static void AlertZMQRestartFunc(int signal, void *arg);

static int PollSocket(void *socket, unsigned retries)
{
    int rc;
    zmq_pollitem_t items [] = { {socket, 0, ZMQ_POLLIN, 0 } };

    do {
        rc = zmq_poll (items, 1, REQUEST_TIMEOUT * ZMQ_POLL_MSEC);

        if (rc == -1)
            return rc;

        if (items[0].revents & ZMQ_POLLIN)
            return 1;

    } while (retries--);

    return 0;
}

void AlertZMQSetup(void)
{
    RegisterOutputPlugin("alert_zmq", OUTPUT_TYPE_FLAG__ALERT, AlertZMQInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: AlertZMQ is setup...\n"););
}

static void AlertZMQInit(char *args)
{
    int ret;
    size_t argsize;
    char *arg_tmp, *delim;
    static zmq_conn_t *connection;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: AlertZMQ initialized\n"););

    connection = malloc (sizeof (zmq_conn_t));

    if (!connection) {
        ErrorMessage ("Failed to allocate memory for connection info...\n");
        FatalError ("Exiting...\n");
    }

    memset (connection, 0, sizeof (zmq_conn_t));

    arg_tmp = strtok (args, ", ");

    while (arg_tmp) {
        delim = strchr (arg_tmp, '=');

        if (strncmp (arg_tmp, "clientcert", strlen ("clientcert")) == 0) {
            argsize = strlen (delim);
            connection->mycertpath = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->mycertpath, delim + 1, argsize);
            connection->mycertpath[argsize] = '\0';
        } else if (strncmp (arg_tmp, "servercert", strlen ("servercert")) == 0) {
            argsize = strlen (delim);
            connection->servercertpath = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->servercertpath, delim + 1, argsize);
            connection->servercertpath[argsize] = '\0';
        } else if (strncmp (arg_tmp, "serverendpoint", strlen ("serverendpoint")) == 0) {
            argsize = strlen (delim);
            connection->serverendpoint = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->serverendpoint, delim + 1, argsize);
            connection->serverendpoint[argsize] = '\0';
        } else if (strncmp (arg_tmp, "sensor_name", strlen ("sensor_name")) == 0) {
            argsize = strlen (delim);
            connection->sensor_name = malloc (sizeof (char) * (argsize + 1));
            strncpy (connection->sensor_name, delim + 1, argsize);
            connection->sensor_name[argsize] = '\0';
        }

        arg_tmp = strtok (NULL, ", ");
    }

    if (!connection->mycertpath) {
        ErrorMessage ("alert_zmq: client cert location not specified!");
        goto out_error;
    }

    if (!connection->servercertpath) {
        ErrorMessage ("alert_zmq: servercert location not specified!");
        goto out_error;
    }

    if (!connection->serverendpoint) {
        ErrorMessage ("alert_zmq: serverendpoint location not specified!");
        goto out_error;
    }

    if (!connection->sensor_name) {
        ErrorMessage ("alert_zmq: sensor_name is not specified!");
        goto out_error;
    }

    connection->mycert = zcert_load (connection->mycertpath);

    if (!connection->mycert) {
        ErrorMessage ("alert_zmq: Failed to load my cert from %s\n",
                    connection->mycertpath);
        goto out_error;
    }

    connection->servercert = zcert_load (connection->servercertpath);

    if (!connection->servercert) {
        ErrorMessage ("alert_zmq: Failed to load server public cert from %s\n",
                connection->mycertpath);
        goto out_error;
    }

    connection->socket = zsock_new (ZMQ_REQ);

    zsys_handler_reset ();
    if (!connection->socket) {
        ErrorMessage ("alert_zmq: Failed create ZeroMQ socket!");
        goto out_error;
    }

    zcert_apply (connection->mycert, zsock_resolve (connection->socket));

    printf (">>>>> %s\n", zcert_public_txt (connection->servercert));

    zsocket_set_curve_serverkey (zsock_resolve (connection->socket),
            zcert_public_txt (connection->servercert));

    ret = zsocket_connect (zsock_resolve (connection->socket), "%s",
            connection->serverendpoint);

    if (ret < 0) {
        ErrorMessage ("alert_zmq: Endpoint %s is invalid!",
                connection->serverendpoint);
        goto out_error;
    }

    zmq_msg_t msg;
    ZMQEventMessage message;

    memset (&message, 0, sizeof (message));
    ret = zmq_msg_init_size (&msg, sizeof (ZMQEventMessage));

    if (ret < 0) {
        ErrorMessage ("alert_zmq: Failed to initialize message size!");
        goto out_error;
    }

    message.type = message.event_type = UNIFIED2_SENSOR_INFO;
    strncpy (message.add_info.info.sensor_name,
            connection->sensor_name, ZMQ_MAX_NAMELEN - 1);
    message.add_info.info.sensor_name[ZMQ_MAX_NAMELEN - 1] = '\0';

    memcpy (zmq_msg_data (&msg), &message, sizeof (message));

    ret = zmq_sendmsg (zsock_resolve (connection->socket), &msg, 0);

    if (ret < 0) {
        ErrorMessage ("alert_zmq: Failed to send sensor info!");
        goto out_error;
    }

    zmq_msg_close (&msg);
    zmq_msg_init (&msg);

    ret = PollSocket (zsock_resolve (connection->socket), REQUEST_RETRIES);

    if (ret <= 0) {
        ErrorMessage ("alert_zmq: Server is not responding...\n");
        goto out_error;
    }

    ret = zmq_recvmsg (zsock_resolve (connection->socket), &msg, 0);

    if (ret != sizeof (u_int32_t)) {
        ErrorMessage ("alert_zmq: Received message of unexpected length %d\n", ret);
    } else {
        connection->sid = ntohl (*(u_int32_t*)zmq_msg_data (&msg));
    }

    zmq_msg_close (&msg);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking AlertZMQ functions to call lists...\n"););

    AddFuncToOutputList(AlertZMQ, OUTPUT_TYPE__ALERT, connection);
    AddFuncToCleanExitList(AlertZMQCleanExitFunc, connection);
    AddFuncToRestartList(AlertZMQRestartFunc, connection);

    return;
out_error:

    FatalError ("Exiting...");
}

static int ZMQReconnect(zmq_conn_t *connection)
{
    int ret = 0;

    zsock_destroy (&connection->socket);

    connection->socket = zsock_new (ZMQ_REQ);
    zcert_apply (connection->mycert, zsock_resolve (connection->socket));
    zsocket_set_curve_serverkey (zsock_resolve (connection->socket),
            zcert_public_txt (connection->servercert));

    ret = zsocket_connect (zsock_resolve (connection->socket), "%s",
            connection->serverendpoint);

    if (ret) {
        ErrorMessage ("alert_zmq: Failed to reconnect to %s\n",
                connection->serverendpoint);
    }

    return ret;
}

static void AlertZMQ(Packet *p, void *event, uint32_t event_type, void *arg)
{
    char *a;
    int rc, i, ret;
    zmq_msg_t msg;
    zmq_conn_t *connection = (zmq_conn_t*)arg;
    ZMQEventMessage message;

    memset (&message, 0, sizeof (message));

    rc = zmq_msg_init_size (&msg, sizeof (ZMQEventMessage));

    if (rc < 0) {
        ErrorMessage ("alert_zmq: Failed to allocate memory for event!");
        FatalError ("Exiting...");
    }

    message.type = message.event_type = UNIFIED2_SENSOR_INFO;
    strncpy (message.add_info.info.sensor_name,
            connection->sensor_name, ZMQ_MAX_NAMELEN - 1);
    message.add_info.info.sensor_name[ZMQ_MAX_NAMELEN - 1] = '\0';

    memcpy (zmq_msg_data (&msg), &message, sizeof (message));

    ret = zmq_sendmsg (zsock_resolve (connection->socket), &msg, 0);

    if (ret < 0) {
        FatalError ("alert_zmq: Failed to send sensor info!... Exiting...");
    }

    zmq_msg_close (&msg);
    zmq_msg_init (&msg);

    ret = PollSocket (zsock_resolve (connection->socket), REQUEST_RETRIES);

    if (ret <= 0) {
        FatalError ("alert_zmq: Server is not responding... Exiting...\n");
    }

    ret = zmq_recvmsg (zsock_resolve (connection->socket), &msg, 0);

    if (ret != sizeof (u_int32_t)) {
        FatalError ("alert_zmq: Received message of unexpected length: %d\n, exiting...\n", ret);
    } else {
        connection->sid = ntohl (*(u_int32_t*)zmq_msg_data (&msg));
    }

    zmq_msg_close (&msg);
    zmq_msg_init_size (&msg, sizeof (ZMQEventMessage));

    memcpy (&message.event, event, sizeof (Unified2EventCommon));
    memcpy (&message.add_info.packet, p->pkt, ZMQ_MAX_PACKETLEN >= p->pkth->len ?
            p->pkth->len : ZMQ_MAX_PACKETLEN);
    message.packetlen = p->pkth->len;
    message.event_type = event_type;
    message.tv_sec = p->pkth->ts.tv_sec;
    message.tv_usec = p->pkth->ts.tv_usec;
    message.event.sensor_id = htonl (connection->sid);

    memcpy (zmq_msg_data (&msg), &message, sizeof (message));

    ret = zmq_sendmsg (zsock_resolve (connection->socket), &msg, 0);

    if (ret < 0) {
        ErrorMessage ("alert_zmq: Failed to send message: %d\n", ret);
        for (i = 0; i < 3; i++) {
            if (ZMQReconnect(connection) < 0) {
                ErrorMessage ("Failed to reconnect to server %s\n",
                        connection->serverendpoint);
                if (i == 2)
                    FatalError("Exiting...\n");
            } else {
                ret = zmq_sendmsg (connection->socket, &msg, 0);
                if (ret < 0) {
                    ErrorMessage ("Failed to send message to server %s %d\n",
                            connection->serverendpoint, errno);
                    FatalError ("Exiting...\n");
                }
            }
        }
    }

    ret = PollSocket (zsock_resolve (connection->socket), REQUEST_RETRIES);

    if (ret <= 0) {
        ErrorMessage ("Server is not responding...\n");
        FatalError ("Exiting...\n");
    }

    a = zstr_recv (zsock_resolve (connection->socket));

    if (strcmp (a, "OK")) {
        ErrorMessage ("alert_zmq: Received an unexpected reply from the server: %s\n", a);
        FatalError ("Exiting...");
    }

    zmq_msg_close (&msg);
}

static void AlertZMQCleanup(int signal, void *arg, const char *msg)
{
    zmq_conn_t *conn = (zmq_conn_t *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "%s", msg););

    if (&conn->socket) {
        if (conn->serverendpoint) {
            zsock_disconnect (conn->socket, "%s", conn->serverendpoint);
        }
        zsock_wait (conn->socket);
        zsock_destroy (&conn->socket);
    }

    free (conn->mycertpath);
    free (conn->servercertpath);
    free (conn->serverendpoint);
    free (conn->sensor_name);

    if (conn->mycert) {
        zcert_destroy (&conn->mycert);
    }

    if (conn->servercert) {
        zcert_destroy (&conn->servercert);
    }
}

static void AlertZMQCleanExitFunc(int signal, void *arg)
{
    AlertZMQCleanup(signal, arg, "AlertZMQCleanExitFunc");
}

static void AlertZMQRestartFunc(int signal, void *arg)
{
    AlertZMQCleanup(signal, arg, "AlertZMQRestartFunc");
}
