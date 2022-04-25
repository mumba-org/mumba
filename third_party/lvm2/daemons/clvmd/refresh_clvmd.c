/*
 * Copyright (C) 2002-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2010 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* FIXME Remove duplicated functions from this file. */

/*
 * Send a command to a running clvmd from the command-line
 */

#include "clvmd-common.h"

#include "clvm.h"
#include "refresh_clvmd.h"

#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef struct lvm_response {
	char node[255];
	char *response;
	int status;
	int len;
} lvm_response_t;

/*
 * This gets stuck at the start of memory we allocate so we
 * can sanity-check it at deallocation time
 */
#define LVM_SIGNATURE 0x434C564D

static int _clvmd_sock = -1;

/* Open connection to the clvm daemon */
static int _open_local_sock(void)
{
	int local_socket;
	struct sockaddr_un sockaddr = { .sun_family = AF_UNIX };

	if (!dm_strncpy(sockaddr.sun_path, CLVMD_SOCKNAME, sizeof(sockaddr.sun_path))) {
		fprintf(stderr, "%s: clvmd socket name too long.", CLVMD_SOCKNAME);
		return -1;
	}

	/* Open local socket */
	if ((local_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Local socket creation failed: %s", strerror(errno));
		return -1;
	}

	if (connect(local_socket,(struct sockaddr *) &sockaddr,
		    sizeof(sockaddr))) {
		int saved_errno = errno;

		fprintf(stderr, "connect() failed on local socket: %s\n",
			  strerror(errno));
		if (close(local_socket))
			return -1;

		errno = saved_errno;
		return -1;
	}

	return local_socket;
}

/* Send a request and return the status */
static int _send_request(const char *inbuf, int inlen, char **retbuf, int no_response)
{
	char outbuf[PIPE_BUF];
	struct clvm_header *outheader = (struct clvm_header *) outbuf;
	int len;
	unsigned off;
	int buflen;
	int err;

	/* Send it to CLVMD */
 rewrite:
	if ( (err = write(_clvmd_sock, inbuf, inlen)) != inlen) {
	        if (err == -1 && errno == EINTR)
		        goto rewrite;
		fprintf(stderr, "Error writing data to clvmd: %s", strerror(errno));
		return 0;
	}
	if (no_response)
		return 1;

	/* Get the response */
 reread:
	if ((len = read(_clvmd_sock, outbuf, sizeof(struct clvm_header))) < 0) {
	        if (errno == EINTR)
		        goto reread;
		fprintf(stderr, "Error reading data from clvmd: %s", strerror(errno));
		return 0;
	}

	if (len == 0) {
		fprintf(stderr, "EOF reading CLVMD");
		errno = ENOTCONN;
		return 0;
	}

	/* Allocate buffer */
	buflen = len + outheader->arglen;
	*retbuf = dm_malloc(buflen);
	if (!*retbuf) {
		errno = ENOMEM;
		return 0;
	}

	/* Copy the header */
	memcpy(*retbuf, outbuf, len);
	outheader = (struct clvm_header *) *retbuf;

	/* Read the returned values */
	off = 1;		/* we've already read the first byte */
	while (off <= outheader->arglen && len > 0) {
		len = read(_clvmd_sock, outheader->args + off,
			   buflen - off - offsetof(struct clvm_header, args));
		if (len > 0)
			off += len;
	}

	/* Was it an error ? */
	if (outheader->status != 0) {
		errno = outheader->status;

		/* Only return an error here if there are no node-specific
		   errors present in the message that might have more detail */
		if (!(outheader->flags & CLVMD_FLAG_NODEERRS)) {
			fprintf(stderr, "cluster request failed: %s\n", strerror(errno));
			return 0;
		}

	}

	return 1;
}

/* Build the structure header and parse-out wildcard node names */
static void _build_header(struct clvm_header *head, int cmd, const char *node,
			  unsigned int len)
{
	head->cmd = cmd;
	head->status = 0;
	head->flags = 0;
	head->xid = 0;
	head->clientid = 0;
	if (len)
		/* 1 byte is used from struct clvm_header.args[1], so -> len - 1 */
		head->arglen = len - 1;
	else {
		head->arglen = 0;
		*head->args = '\0';
	}

	/*
	 * Translate special node names.
	 */
	if (!node || !strcmp(node, NODE_ALL))
		head->node[0] = '\0';
	else if (!strcmp(node, NODE_LOCAL)) {
		head->node[0] = '\0';
		head->flags = CLVMD_FLAG_LOCAL;
	} else
		strcpy(head->node, node);
}

/*
 * Send a message to a(or all) node(s) in the cluster and wait for replies
 */
static int _cluster_request(char cmd, const char *node, void *data, int len,
			    lvm_response_t ** response, int *num, int no_response)
{
	char outbuf[sizeof(struct clvm_header) + len + strlen(node) + 1];
	char *inptr;
	char *retbuf = NULL;
	int status;
	int i;
	int num_responses = 0;
	struct clvm_header *head = (struct clvm_header *) outbuf;
	lvm_response_t *rarray;

	*num = 0;

	if (_clvmd_sock == -1)
		_clvmd_sock = _open_local_sock();

	if (_clvmd_sock == -1)
		return 0;

	_build_header(head, cmd, node, len);
	if (len)
		memcpy(head->node + strlen(head->node) + 1, data, len);

	status = _send_request(outbuf, sizeof(struct clvm_header) +
			       strlen(head->node) + len, &retbuf, no_response);
	if (!status || no_response)
		goto out;

	/* Count the number of responses we got */
	head = (struct clvm_header *) retbuf;
	inptr = head->args;
	while (inptr[0]) {
		num_responses++;
		inptr += strlen(inptr) + 1;
		inptr += sizeof(int);
		inptr += strlen(inptr) + 1;
	}

	/*
	 * Allocate response array.
	 * With an extra pair of INTs on the front to sanity
	 * check the pointer when we are given it back to free
	 */
	*response = NULL;
	if (!(rarray = dm_malloc(sizeof(lvm_response_t) * num_responses +
				 sizeof(int) * 2))) {
		errno = ENOMEM;
		status = 0;
		goto out;
	}

	/* Unpack the response into an lvm_response_t array */
	inptr = head->args;
	i = 0;
	while (inptr[0]) {
		strcpy(rarray[i].node, inptr);
		inptr += strlen(inptr) + 1;

		memcpy(&rarray[i].status, inptr, sizeof(int));
		inptr += sizeof(int);

		rarray[i].response = dm_malloc(strlen(inptr) + 1);
		if (rarray[i].response == NULL) {
			/* Free up everything else and return error */
			int j;
			for (j = 0; j < i; j++)
				dm_free(rarray[i].response);
			dm_free(rarray);
			errno = ENOMEM;
			status = 0;
			goto out;
		}

		strcpy(rarray[i].response, inptr);
		rarray[i].len = strlen(inptr);
		inptr += strlen(inptr) + 1;
		i++;
	}
	*num = num_responses;
	*response = rarray;

      out:
	dm_free(retbuf);

	return status;
}

/* Free reply array */
static int _cluster_free_request(lvm_response_t * response, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		dm_free(response[i].response);
	}

	dm_free(response);

	return 1;
}

int refresh_clvmd(int all_nodes)
{
	int num_responses;
	char args[1]; // No args really.
	lvm_response_t *response = NULL;
	int saved_errno;
	int status;
	int i;

	status = _cluster_request(CLVMD_CMD_REFRESH, all_nodes ? NODE_ALL : NODE_LOCAL, args, 0, &response, &num_responses, 0);

	/* If any nodes were down then display them and return an error */
	for (i = 0; i < num_responses; i++) {
		if (response[i].status == EHOSTDOWN) {
			fprintf(stderr, "clvmd not running on node %s",
				  response[i].node);
			status = 0;
			errno = response[i].status;
		} else if (response[i].status) {
			fprintf(stderr, "Error resetting node %s: %s",
				  response[i].node,
				  response[i].response[0] ?
				  	response[i].response :
				  	strerror(response[i].status));
			status = 0;
			errno = response[i].status;
		}
	}

	saved_errno = errno;
	_cluster_free_request(response, num_responses);
	errno = saved_errno;

	return status;
}

int restart_clvmd(int all_nodes)
{
	int dummy, status;

	status = _cluster_request(CLVMD_CMD_RESTART, all_nodes ? NODE_ALL : NODE_LOCAL, NULL, 0, NULL, &dummy, 1);

	/*
	 * FIXME: we cannot receive response, clvmd re-exec before it.
	 *        but also should not close socket too early (the whole rq is dropped then).
	 * FIXME: This should be handled this way:
	 *  - client waits for RESTART ack (and socket close)
	 *  - server restarts
	 *  - client checks that server is ready again (VERSION command?)
	 */
	usleep(500000);

	return status;
}

int debug_clvmd(int level, int clusterwide)
{
	int num_responses;
	char args[1];
	const char *nodes;
	lvm_response_t *response = NULL;
	int saved_errno;
	int status;
	int i;

	args[0] = level;
	if (clusterwide)
		nodes = NODE_ALL;
	else
		nodes = NODE_LOCAL;

	status = _cluster_request(CLVMD_CMD_SET_DEBUG, nodes, args, 1, &response, &num_responses, 0);

	/* If any nodes were down then display them and return an error */
	for (i = 0; i < num_responses; i++) {
		if (response[i].status == EHOSTDOWN) {
			fprintf(stderr, "clvmd not running on node %s",
				  response[i].node);
			status = 0;
			errno = response[i].status;
		} else if (response[i].status) {
			fprintf(stderr, "Error setting debug on node %s: %s",
				  response[i].node,
				  response[i].response[0] ?
				  	response[i].response :
				  	strerror(response[i].status));
			status = 0;
			errno = response[i].status;
		}
	}

	saved_errno = errno;
	_cluster_free_request(response, num_responses);
	errno = saved_errno;

	return status;
}
