/*
 * Copyright (C) 2009-2012 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This provides the interface between clvmd and corosync/DLM as the cluster
 * and lock manager.
 */

#include "clvmd-common.h"

#include <pthread.h>

#include "clvm.h"
#include "clvmd-comms.h"
#include "clvmd.h"
#include "lvm-functions.h"

#include "locking.h"

#include <corosync/cpg.h>
#include <corosync/quorum.h>

#ifdef HAVE_COROSYNC_CONFDB_H
#  include <corosync/confdb.h>
#elif defined HAVE_COROSYNC_CMAP_H
#  include <corosync/cmap.h>
#else
#  error "Either HAVE_COROSYNC_CONFDB_H or HAVE_COROSYNC_CMAP_H must be defined."
#endif

#include <libdlm.h>

#include <syslog.h>

/* Timeout value for several corosync calls */
#define LOCKSPACE_NAME "clvmd"

static void corosync_cpg_deliver_callback (cpg_handle_t handle,
				  const struct cpg_name *groupName,
				  uint32_t nodeid,
				  uint32_t pid,
				  void *msg,
				  size_t msg_len);
static void corosync_cpg_confchg_callback(cpg_handle_t handle,
				 const struct cpg_name *groupName,
				 const struct cpg_address *member_list, size_t member_list_entries,
				 const struct cpg_address *left_list, size_t left_list_entries,
				 const struct cpg_address *joined_list, size_t joined_list_entries);
static void _cluster_closedown(void);

/* Hash list of nodes in the cluster */
static struct dm_hash_table *node_hash;

/* Number of active nodes */
static int num_nodes;
static unsigned int our_nodeid;

static struct local_client *cluster_client;

/* Corosync handles */
static cpg_handle_t cpg_handle;
static quorum_handle_t quorum_handle;

/* DLM Handle */
static dlm_lshandle_t *lockspace;

static struct cpg_name cpg_group_name;

/* Corosync callback structs */
cpg_callbacks_t corosync_cpg_callbacks = {
	.cpg_deliver_fn =            corosync_cpg_deliver_callback,
	.cpg_confchg_fn =            corosync_cpg_confchg_callback,
};

quorum_callbacks_t quorum_callbacks = {
	.quorum_notify_fn = NULL,
};

struct node_info
{
	enum {NODE_DOWN, NODE_CLVMD} state;
	int nodeid;
};


/* Set errno to something approximating the right value and return 0 or -1 */
static int cs_to_errno(cs_error_t err)
{
	switch(err)
	{
	case CS_OK:
		return 0;
        case CS_ERR_LIBRARY:
		errno = EINVAL;
		break;
        case CS_ERR_VERSION:
		errno = EINVAL;
		break;
        case CS_ERR_INIT:
		errno = EINVAL;
		break;
        case CS_ERR_TIMEOUT:
		errno = ETIME;
		break;
        case CS_ERR_TRY_AGAIN:
		errno = EAGAIN;
		break;
        case CS_ERR_INVALID_PARAM:
		errno = EINVAL;
		break;
        case CS_ERR_NO_MEMORY:
		errno = ENOMEM;
		break;
        case CS_ERR_BAD_HANDLE:
		errno = EINVAL;
		break;
        case CS_ERR_BUSY:
		errno = EBUSY;
		break;
        case CS_ERR_ACCESS:
		errno = EPERM;
		break;
        case CS_ERR_NOT_EXIST:
		errno = ENOENT;
		break;
        case CS_ERR_NAME_TOO_LONG:
		errno = ENAMETOOLONG;
		break;
        case CS_ERR_EXIST:
		errno = EEXIST;
		break;
        case CS_ERR_NO_SPACE:
		errno = ENOSPC;
		break;
        case CS_ERR_INTERRUPT:
		errno = EINTR;
		break;
	case CS_ERR_NAME_NOT_FOUND:
		errno = ENOENT;
		break;
        case CS_ERR_NO_RESOURCES:
		errno = ENOMEM;
		break;
        case CS_ERR_NOT_SUPPORTED:
		errno = EOPNOTSUPP;
		break;
        case CS_ERR_BAD_OPERATION:
		errno = EINVAL;
		break;
        case CS_ERR_FAILED_OPERATION:
		errno = EIO;
		break;
        case CS_ERR_MESSAGE_ERROR:
		errno = EIO;
		break;
        case CS_ERR_QUEUE_FULL:
		errno = EXFULL;
		break;
        case CS_ERR_QUEUE_NOT_AVAILABLE:
		errno = EINVAL;
		break;
        case CS_ERR_BAD_FLAGS:
		errno = EINVAL;
		break;
        case CS_ERR_TOO_BIG:
		errno = E2BIG;
		break;
        case CS_ERR_NO_SECTIONS:
		errno = ENOMEM;
		break;
	default:
		errno = EINVAL;
		break;
	}
	return -1;
}

static char *print_corosync_csid(const char *csid)
{
	static char buf[128];
	int id;

	memcpy(&id, csid, sizeof(int));
	sprintf(buf, "%d", id);
	return buf;
}

static void corosync_cpg_deliver_callback (cpg_handle_t handle,
				  const struct cpg_name *groupName,
				  uint32_t nodeid,
				  uint32_t pid,
				  void *msg,
				  size_t msg_len)
{
	int target_nodeid;

	memcpy(&target_nodeid, msg, COROSYNC_CSID_LEN);

	DEBUGLOG("%u got message from nodeid %d for %d. len %zd\n",
		 our_nodeid, nodeid, target_nodeid, msg_len-4);

	if (nodeid != our_nodeid)
		if (target_nodeid == our_nodeid || target_nodeid == 0)
			process_message(cluster_client, (char *)msg+COROSYNC_CSID_LEN,
					msg_len-COROSYNC_CSID_LEN, (char*)&nodeid);
}

static void corosync_cpg_confchg_callback(cpg_handle_t handle,
				 const struct cpg_name *groupName,
				 const struct cpg_address *member_list, size_t member_list_entries,
				 const struct cpg_address *left_list, size_t left_list_entries,
				 const struct cpg_address *joined_list, size_t joined_list_entries)
{
	int i;
	struct node_info *ninfo;

	DEBUGLOG("confchg callback. %zd joined, %zd left, %zd members\n",
		 joined_list_entries, left_list_entries, member_list_entries);

	for (i=0; i<joined_list_entries; i++) {
		ninfo = dm_hash_lookup_binary(node_hash,
					      (char *)&joined_list[i].nodeid,
					      COROSYNC_CSID_LEN);
		if (!ninfo) {
			ninfo = malloc(sizeof(struct node_info));
			if (!ninfo) {
				break;
			}
			else {
				ninfo->nodeid = joined_list[i].nodeid;
				dm_hash_insert_binary(node_hash,
						      (char *)&ninfo->nodeid,
						      COROSYNC_CSID_LEN, ninfo);
			}
		}
		ninfo->state = NODE_CLVMD;
	}

	for (i=0; i<left_list_entries; i++) {
		ninfo = dm_hash_lookup_binary(node_hash,
					      (char *)&left_list[i].nodeid,
					      COROSYNC_CSID_LEN);
		if (ninfo)
			ninfo->state = NODE_DOWN;
	}

	num_nodes = member_list_entries;
}

static int _init_cluster(void)
{
	cs_error_t err;

#ifdef QUORUM_SET	/* corosync/quorum.h */
	uint32_t quorum_type;
#endif

	node_hash = dm_hash_create(100);

	err = cpg_initialize(&cpg_handle,
			     &corosync_cpg_callbacks);
	if (err != CS_OK) {
		syslog(LOG_ERR, "Cannot initialise Corosync CPG service: %d",
		       err);
		DEBUGLOG("Cannot initialise Corosync CPG service: %d", err);
		return cs_to_errno(err);
	}

#ifdef QUORUM_SET
	err = quorum_initialize(&quorum_handle,
				&quorum_callbacks,
				&quorum_type);

	if (quorum_type != QUORUM_SET) {
		syslog(LOG_ERR, "Corosync quorum service is not configured");
		DEBUGLOG("Corosync quorum service is not configured");
		return EINVAL;
	}
#else
	err = quorum_initialize(&quorum_handle,
				&quorum_callbacks);
#endif

	if (err != CS_OK) {
		syslog(LOG_ERR, "Cannot initialise Corosync quorum service: %d",
		       err);
		DEBUGLOG("Cannot initialise Corosync quorum service: %d", err);
		return cs_to_errno(err);
	}

	/* Create a lockspace for LV & VG locks to live in */
	lockspace = dlm_open_lockspace(LOCKSPACE_NAME);
	if (!lockspace) {
		lockspace = dlm_create_lockspace(LOCKSPACE_NAME, 0600);
		if (!lockspace) {
			syslog(LOG_ERR, "Unable to create DLM lockspace for CLVM: %m");
			return -1;
		}
		DEBUGLOG("Created DLM lockspace for CLVMD.\n");
	} else
		DEBUGLOG("Opened existing DLM lockspace for CLVMD.\n");

	dlm_ls_pthread_init(lockspace);
	DEBUGLOG("DLM initialisation complete\n");

	/* Connect to the clvmd group */
	strcpy((char *)cpg_group_name.value, "clvmd");
	cpg_group_name.length = strlen((char *)cpg_group_name.value);
	err = cpg_join(cpg_handle, &cpg_group_name);
	if (err != CS_OK) {
		cpg_finalize(cpg_handle);
		quorum_finalize(quorum_handle);
		dlm_release_lockspace(LOCKSPACE_NAME, lockspace, 1);
		syslog(LOG_ERR, "Cannot join clvmd process group");
		DEBUGLOG("Cannot join clvmd process group: %d\n", err);
		return cs_to_errno(err);
	}

	err = cpg_local_get(cpg_handle,
			    &our_nodeid);
	if (err != CS_OK) {
		cpg_finalize(cpg_handle);
		quorum_finalize(quorum_handle);
		dlm_release_lockspace(LOCKSPACE_NAME, lockspace, 1);
		syslog(LOG_ERR, "Cannot get local node id\n");
		return cs_to_errno(err);
	}
	DEBUGLOG("Our local node id is %d\n", our_nodeid);

	DEBUGLOG("Connected to Corosync\n");

	return 0;
}

static void _cluster_closedown(void)
{
	dlm_release_lockspace(LOCKSPACE_NAME, lockspace, 1);
	cpg_finalize(cpg_handle);
	quorum_finalize(quorum_handle);
}

static void _get_our_csid(char *csid)
{
	memcpy(csid, &our_nodeid, sizeof(int));
}

/* Corosync doesn't really have nmode names so we
   just use the node ID in hex instead */
static int _csid_from_name(char *csid, const char *name)
{
	int nodeid;
	struct node_info *ninfo;

	if (sscanf(name, "%x", &nodeid) == 1) {
		ninfo = dm_hash_lookup_binary(node_hash, csid, COROSYNC_CSID_LEN);
		if (ninfo)
			return nodeid;
	}
	return -1;
}

static int _name_from_csid(const char *csid, char *name)
{
	struct node_info *ninfo;

	ninfo = dm_hash_lookup_binary(node_hash, csid, COROSYNC_CSID_LEN);
	if (!ninfo)
	{
		sprintf(name, "UNKNOWN %s", print_corosync_csid(csid));
		return -1;
	}

	sprintf(name, "%x", ninfo->nodeid);
	return 0;
}

static int _get_num_nodes(void)
{
	DEBUGLOG("num_nodes = %d\n", num_nodes);
	return num_nodes;
}

/* Node is now known to be running a clvmd */
static void _add_up_node(const char *csid)
{
	struct node_info *ninfo;

	ninfo = dm_hash_lookup_binary(node_hash, csid, COROSYNC_CSID_LEN);
	if (!ninfo) {
		DEBUGLOG("corosync_add_up_node no node_hash entry for csid %s\n",
			 print_corosync_csid(csid));
		return;
	}

	DEBUGLOG("corosync_add_up_node %d\n", ninfo->nodeid);

	ninfo->state = NODE_CLVMD;

	return;
}

/* Call a callback for each node, so the caller knows whether it's up or down */
static int _cluster_do_node_callback(struct local_client *master_client,
				     void (*callback)(struct local_client *,
						      const char *csid, int node_up))
{
	struct dm_hash_node *hn;
	struct node_info *ninfo;

	dm_hash_iterate(hn, node_hash)
	{
		char csid[COROSYNC_CSID_LEN];

		ninfo = dm_hash_get_data(node_hash, hn);
		memcpy(csid, dm_hash_get_key(node_hash, hn), COROSYNC_CSID_LEN);

		DEBUGLOG("down_callback. node %d, state = %d\n", ninfo->nodeid,
			 ninfo->state);

		if (ninfo->state == NODE_CLVMD)
			callback(master_client, csid, 1);
	}
	return 0;
}

/* Real locking */
static int _lock_resource(const char *resource, int mode, int flags, int *lockid)
{
	struct dlm_lksb lksb;
	int err;

	DEBUGLOG("lock_resource '%s', flags=%d, mode=%d\n", resource, flags, mode);

	if (flags & LKF_CONVERT)
		lksb.sb_lkid = *lockid;

	err = dlm_ls_lock_wait(lockspace,
			       mode,
			       &lksb,
			       flags,
			       resource,
			       strlen(resource),
			       0,
			       NULL, NULL, NULL);

	if (err != 0)
	{
		DEBUGLOG("dlm_ls_lock returned %d\n", errno);
		return err;
	}
	if (lksb.sb_status != 0)
	{
		DEBUGLOG("dlm_ls_lock returns lksb.sb_status %d\n", lksb.sb_status);
		errno = lksb.sb_status;
		return -1;
	}

	DEBUGLOG("lock_resource returning %d, lock_id=%x\n", err, lksb.sb_lkid);

	*lockid = lksb.sb_lkid;

	return 0;
}


static int _unlock_resource(const char *resource, int lockid)
{
	struct dlm_lksb lksb;
	int err;

	DEBUGLOG("unlock_resource: %s lockid: %x\n", resource, lockid);
	lksb.sb_lkid = lockid;

	err = dlm_ls_unlock_wait(lockspace,
				 lockid,
				 0,
				 &lksb);
	if (err != 0)
	{
		DEBUGLOG("Unlock returned %d\n", err);
		return err;
	}
	if (lksb.sb_status != EUNLOCK)
	{
		DEBUGLOG("dlm_ls_unlock_wait returns lksb.sb_status: %d\n", lksb.sb_status);
		errno = lksb.sb_status;
		return -1;
	}   


	return 0;
}

static int _is_quorate(void)
{
	int quorate;
	if (quorum_getquorate(quorum_handle, &quorate) == CS_OK)
		return quorate;
	else
		return 0;
}

static int _get_main_cluster_fd(void)
{
	int select_fd;

	cpg_fd_get(cpg_handle, &select_fd);
	return select_fd;
}

static int _cluster_fd_callback(struct local_client *fd, char *buf, int len,
				const char *csid,
				struct local_client **new_client)
{
	cluster_client = fd;
	*new_client = NULL;
	cpg_dispatch(cpg_handle, CS_DISPATCH_ONE);
	return 1;
}

static int _cluster_send_message(const void *buf, int msglen, const char *csid,
				 const char *errtext)
{
	struct iovec iov[2];
	cs_error_t err;
	int target_node;

	if (csid)
		memcpy(&target_node, csid, COROSYNC_CSID_LEN);
	else
		target_node = 0;

	iov[0].iov_base = &target_node;
	iov[0].iov_len = sizeof(int);
	iov[1].iov_base = (char *)buf;
	iov[1].iov_len = msglen;

	err = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, 2);
	return cs_to_errno(err);
}

#ifdef HAVE_COROSYNC_CONFDB_H
/*
 * We are not necessarily connected to a Red Hat Cluster system,
 * but if we are, this returns the cluster name from cluster.conf.
 * I've used confdb rather than ccs to reduce the inter-package
 * dependancies as well as to allow people to set a cluster name
 * for themselves even if they are not running on RH cluster.
 */
static int _get_cluster_name(char *buf, int buflen)
{
	confdb_handle_t handle;
	int result;
	size_t namelen = buflen;
	hdb_handle_t cluster_handle;
	confdb_callbacks_t callbacks = {
		.confdb_key_change_notify_fn = NULL,
		.confdb_object_create_change_notify_fn = NULL,
		.confdb_object_delete_change_notify_fn = NULL
	};

	/* This is a default in case everything else fails */
	strncpy(buf, "Corosync", buflen);

	/* Look for a cluster name in confdb */
	result = confdb_initialize (&handle, &callbacks);
        if (result != CS_OK)
		return 0;

        result = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (result != CS_OK)
		goto out;

        result = confdb_object_find(handle, OBJECT_PARENT_HANDLE, (void *)"cluster", strlen("cluster"), &cluster_handle);
        if (result != CS_OK)
		goto out;

        result = confdb_key_get(handle, cluster_handle, (void *)"name", strlen("name"), buf, &namelen);
        if (result != CS_OK)
		goto out;

	buf[namelen] = '\0';

out:
	confdb_finalize(handle);
	return 0;
}

#elif defined HAVE_COROSYNC_CMAP_H

static int _get_cluster_name(char *buf, int buflen)
{
	cmap_handle_t cmap_handle = 0;
	int result;
	char *name = NULL;

	/* This is a default in case everything else fails */
	strncpy(buf, "Corosync", buflen);

	/* Look for a cluster name in cmap */
	result = cmap_initialize(&cmap_handle);
	if (result != CS_OK)
		return 0;

	result = cmap_get_string(cmap_handle, "totem.cluster_name", &name);
	if (result != CS_OK)
		goto out;

	memset(buf, 0, buflen);
	strncpy(buf, name, buflen - 1);

out:
	if (name)
		free(name);
	cmap_finalize(cmap_handle);
	return 0;
}

#endif

static struct cluster_ops _cluster_corosync_ops = {
	.name                     = "corosync",
	.cluster_init_completed   = NULL,
	.cluster_send_message     = _cluster_send_message,
	.name_from_csid           = _name_from_csid,
	.csid_from_name           = _csid_from_name,
	.get_num_nodes            = _get_num_nodes,
	.cluster_fd_callback      = _cluster_fd_callback,
	.get_main_cluster_fd      = _get_main_cluster_fd,
	.cluster_do_node_callback = _cluster_do_node_callback,
	.is_quorate               = _is_quorate,
	.get_our_csid             = _get_our_csid,
	.add_up_node              = _add_up_node,
	.reread_config            = NULL,
	.cluster_closedown        = _cluster_closedown,
	.get_cluster_name         = _get_cluster_name,
	.sync_lock                = _lock_resource,
	.sync_unlock              = _unlock_resource,
};

struct cluster_ops *init_corosync_cluster(void)
{
	if (!_init_cluster())
		return &_cluster_corosync_ops;
	else
		return NULL;
}
