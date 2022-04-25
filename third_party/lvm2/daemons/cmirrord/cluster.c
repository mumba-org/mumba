/*
 * Copyright (C) 2004-2009 Red Hat, Inc. All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "logging.h"
#include "cluster.h"
#include "common.h"
#include "compat.h"
#include "functions.h"
#include "link_mon.h"
#include "local.h"
#include "xlate.h"

#include <corosync/cpg.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#if CMIRROR_HAS_CHECKPOINT
#include <openais/saAis.h>
#include <openais/saCkpt.h>

/* Open AIS error codes */
#define str_ais_error(x)						\
	((x) == SA_AIS_OK) ? "SA_AIS_OK" :				\
	((x) == SA_AIS_ERR_LIBRARY) ? "SA_AIS_ERR_LIBRARY" :		\
	((x) == SA_AIS_ERR_VERSION) ? "SA_AIS_ERR_VERSION" :		\
	((x) == SA_AIS_ERR_INIT) ? "SA_AIS_ERR_INIT" :			\
	((x) == SA_AIS_ERR_TIMEOUT) ? "SA_AIS_ERR_TIMEOUT" :		\
	((x) == SA_AIS_ERR_TRY_AGAIN) ? "SA_AIS_ERR_TRY_AGAIN" :	\
	((x) == SA_AIS_ERR_INVALID_PARAM) ? "SA_AIS_ERR_INVALID_PARAM" : \
	((x) == SA_AIS_ERR_NO_MEMORY) ? "SA_AIS_ERR_NO_MEMORY" :	\
	((x) == SA_AIS_ERR_BAD_HANDLE) ? "SA_AIS_ERR_BAD_HANDLE" :	\
	((x) == SA_AIS_ERR_BUSY) ? "SA_AIS_ERR_BUSY" :			\
	((x) == SA_AIS_ERR_ACCESS) ? "SA_AIS_ERR_ACCESS" :		\
	((x) == SA_AIS_ERR_NOT_EXIST) ? "SA_AIS_ERR_NOT_EXIST" :	\
	((x) == SA_AIS_ERR_NAME_TOO_LONG) ? "SA_AIS_ERR_NAME_TOO_LONG" : \
	((x) == SA_AIS_ERR_EXIST) ? "SA_AIS_ERR_EXIST" :		\
	((x) == SA_AIS_ERR_NO_SPACE) ? "SA_AIS_ERR_NO_SPACE" :		\
	((x) == SA_AIS_ERR_INTERRUPT) ? "SA_AIS_ERR_INTERRUPT" :	\
	((x) == SA_AIS_ERR_NAME_NOT_FOUND) ? "SA_AIS_ERR_NAME_NOT_FOUND" : \
	((x) == SA_AIS_ERR_NO_RESOURCES) ? "SA_AIS_ERR_NO_RESOURCES" :	\
	((x) == SA_AIS_ERR_NOT_SUPPORTED) ? "SA_AIS_ERR_NOT_SUPPORTED" : \
	((x) == SA_AIS_ERR_BAD_OPERATION) ? "SA_AIS_ERR_BAD_OPERATION" : \
	((x) == SA_AIS_ERR_FAILED_OPERATION) ? "SA_AIS_ERR_FAILED_OPERATION" : \
	((x) == SA_AIS_ERR_MESSAGE_ERROR) ? "SA_AIS_ERR_MESSAGE_ERROR" : \
	((x) == SA_AIS_ERR_QUEUE_FULL) ? "SA_AIS_ERR_QUEUE_FULL" :	\
	((x) == SA_AIS_ERR_QUEUE_NOT_AVAILABLE) ? "SA_AIS_ERR_QUEUE_NOT_AVAILABLE" : \
	((x) == SA_AIS_ERR_BAD_FLAGS) ? "SA_AIS_ERR_BAD_FLAGS" :	\
	((x) == SA_AIS_ERR_TOO_BIG) ? "SA_AIS_ERR_TOO_BIG" :		\
	((x) == SA_AIS_ERR_NO_SECTIONS) ? "SA_AIS_ERR_NO_SECTIONS" :	\
	"ais_error_unknown"
#else
#define str_ais_error(x)						\
	((x) == CS_OK) ? "CS_OK" :				\
	((x) == CS_ERR_LIBRARY) ? "CS_ERR_LIBRARY" :		\
	((x) == CS_ERR_VERSION) ? "CS_ERR_VERSION" :		\
	((x) == CS_ERR_INIT) ? "CS_ERR_INIT" :			\
	((x) == CS_ERR_TIMEOUT) ? "CS_ERR_TIMEOUT" :		\
	((x) == CS_ERR_TRY_AGAIN) ? "CS_ERR_TRY_AGAIN" :	\
	((x) == CS_ERR_INVALID_PARAM) ? "CS_ERR_INVALID_PARAM" : \
	((x) == CS_ERR_NO_MEMORY) ? "CS_ERR_NO_MEMORY" :	\
	((x) == CS_ERR_BAD_HANDLE) ? "CS_ERR_BAD_HANDLE" :	\
	((x) == CS_ERR_BUSY) ? "CS_ERR_BUSY" :			\
	((x) == CS_ERR_ACCESS) ? "CS_ERR_ACCESS" :		\
	((x) == CS_ERR_NOT_EXIST) ? "CS_ERR_NOT_EXIST" :	\
	((x) == CS_ERR_NAME_TOO_LONG) ? "CS_ERR_NAME_TOO_LONG" : \
	((x) == CS_ERR_EXIST) ? "CS_ERR_EXIST" :		\
	((x) == CS_ERR_NO_SPACE) ? "CS_ERR_NO_SPACE" :		\
	((x) == CS_ERR_INTERRUPT) ? "CS_ERR_INTERRUPT" :	\
	((x) == CS_ERR_NAME_NOT_FOUND) ? "CS_ERR_NAME_NOT_FOUND" : \
	((x) == CS_ERR_NO_RESOURCES) ? "CS_ERR_NO_RESOURCES" :	\
	((x) == CS_ERR_NOT_SUPPORTED) ? "CS_ERR_NOT_SUPPORTED" : \
	((x) == CS_ERR_BAD_OPERATION) ? "CS_ERR_BAD_OPERATION" : \
	((x) == CS_ERR_FAILED_OPERATION) ? "CS_ERR_FAILED_OPERATION" : \
	((x) == CS_ERR_MESSAGE_ERROR) ? "CS_ERR_MESSAGE_ERROR" : \
	((x) == CS_ERR_QUEUE_FULL) ? "CS_ERR_QUEUE_FULL" :	\
	((x) == CS_ERR_QUEUE_NOT_AVAILABLE) ? "CS_ERR_QUEUE_NOT_AVAILABLE" : \
	((x) == CS_ERR_BAD_FLAGS) ? "CS_ERR_BAD_FLAGS" :	\
	((x) == CS_ERR_TOO_BIG) ? "CS_ERR_TOO_BIG" :		\
	((x) == CS_ERR_NO_SECTIONS) ? "CS_ERR_NO_SECTIONS" :	\
	((x) == CS_ERR_CONTEXT_NOT_FOUND) ? "CS_ERR_CONTEXT_NOT_FOUND" : \
	((x) == CS_ERR_TOO_MANY_GROUPS) ? "CS_ERR_TOO_MANY_GROUPS" : \
	((x) == CS_ERR_SECURITY) ? "CS_ERR_SECURITY" : \
	"cs_error_unknown"
#endif

#define _RQ_TYPE(x)							\
	((x) == DM_ULOG_CHECKPOINT_READY) ? "DM_ULOG_CHECKPOINT_READY": \
	((x) == DM_ULOG_MEMBER_JOIN) ? "DM_ULOG_MEMBER_JOIN":		\
	RQ_TYPE((x) & ~DM_ULOG_RESPONSE)

static uint32_t my_cluster_id = 0xDEAD;
#if CMIRROR_HAS_CHECKPOINT
static SaCkptHandleT ckpt_handle = 0;
static SaCkptCallbacksT callbacks = { 0, 0 };
static SaVersionT version = { 'B', 1, 1 };
#endif

#define DEBUGGING_HISTORY 100
#define DEBUGGING_BUFLEN 128
#define LOG_SPRINT(cc, f, arg...) do {				\
		cc->idx++;					\
		cc->idx = cc->idx % DEBUGGING_HISTORY;		\
		snprintf(cc->debugging[cc->idx], DEBUGGING_BUFLEN, f, ## arg); \
	} while (0)

static int log_resp_rec = 0;

#define RECOVERING_REGION_SECTION_SIZE 64
struct checkpoint_data {
	uint32_t requester;
	char uuid[CPG_MAX_NAME_LENGTH];

	int bitmap_size; /* in bytes */
	char *sync_bits;
	char *clean_bits;
	char *recovering_region;
	struct checkpoint_data *next;
};

#define INVALID 0
#define VALID   1
#define LEAVING 2

#define MAX_CHECKPOINT_REQUESTERS 10
struct clog_cpg {
	struct dm_list list;

	uint32_t lowest_id;
	cpg_handle_t handle;
	struct cpg_name name;
	uint64_t luid;

	/* Are we the first, or have we received checkpoint? */
	int state;
	int cpg_state;  /* FIXME: debugging */
	int free_me;
	int delay;
	int resend_requests;
	struct dm_list startup_list;
	struct dm_list working_list;

	int checkpoints_needed;
	uint32_t checkpoint_requesters[MAX_CHECKPOINT_REQUESTERS];
	struct checkpoint_data *checkpoint_list;
	int idx;
	char debugging[DEBUGGING_HISTORY][DEBUGGING_BUFLEN];
};

static struct dm_list clog_cpg_list;

/*
 * cluster_send
 * @rq
 *
 * Returns: 0 on success, -Exxx on error
 */
int cluster_send(struct clog_request *rq)
{
	int r;
	int found = 0;
	struct iovec iov;
	struct clog_cpg *entry;

	dm_list_iterate_items(entry, &clog_cpg_list)
		if (!strncmp(entry->name.value, rq->u_rq.uuid,
			     CPG_MAX_NAME_LENGTH)) {
			found = 1;
			break;
		}

	if (!found) {
		rq->u_rq.error = -ENOENT;
		return -ENOENT;
	}

	/*
	 * Once the request heads for the cluster, the luid looses
	 * all its meaning.
	 */
	rq->u_rq.luid = 0;

	iov.iov_base = rq;
	iov.iov_len = sizeof(struct clog_request) + rq->u_rq.data_size;

	rq->u.version[0] = xlate64(CLOG_TFR_VERSION);
	rq->u.version[1] = CLOG_TFR_VERSION;

	r = clog_request_to_network(rq);
	if (r < 0)
		/* FIXME: Better error code for byteswap failure? */
		return -EINVAL;

	if (entry->cpg_state != VALID)
		return -EINVAL;

#if CMIRROR_HAS_CHECKPOINT
	do {
		int count = 0;

		r = cpg_mcast_joined(entry->handle, CPG_TYPE_AGREED, &iov, 1);
		if (r != SA_AIS_ERR_TRY_AGAIN)
			break;
		count++;
		if (count < 10)
			LOG_PRINT("[%s]  Retry #%d of cpg_mcast_joined: %s",
				  SHORT_UUID(rq->u_rq.uuid), count,
				  str_ais_error(r));
		else if ((count < 100) && !(count % 10))
			LOG_ERROR("[%s]  Retry #%d of cpg_mcast_joined: %s",
				  SHORT_UUID(rq->u_rq.uuid), count,
				  str_ais_error(r));
		else if ((count < 1000) && !(count % 100))
			LOG_ERROR("[%s]  Retry #%d of cpg_mcast_joined: %s",
				  SHORT_UUID(rq->u_rq.uuid), count,
				  str_ais_error(r));
		else if ((count < 10000) && !(count % 1000))
			LOG_ERROR("[%s]  Retry #%d of cpg_mcast_joined: %s - "
				  "OpenAIS not handling the load?",
				  SHORT_UUID(rq->u_rq.uuid), count,
				  str_ais_error(r));
		usleep(1000);
	} while (1);
#else
	r = cpg_mcast_joined(entry->handle, CPG_TYPE_AGREED, &iov, 1);
#endif
	if (r == CS_OK)
		return 0;

	/* error codes found in openais/cpg.h */
	LOG_ERROR("cpg_mcast_joined error: %d", r);

	rq->u_rq.error = -EBADE;
	return -EBADE;
}

static struct clog_request *get_matching_rq(struct clog_request *rq,
					    struct dm_list *l)
{
	struct clog_request *match, *n;

	dm_list_iterate_items_gen_safe(match, n, l, u.list)
		if (match->u_rq.seq == rq->u_rq.seq) {
			dm_list_del(&match->u.list);
			return match;
		}

	return NULL;
}

static char rq_buffer[DM_ULOG_REQUEST_SIZE];
static int handle_cluster_request(struct clog_cpg *entry __attribute__((unused)),
				  struct clog_request *rq, int server)
{
	int r = 0;
	struct clog_request *tmp = (struct clog_request *)rq_buffer;

	/*
	 * We need a separate dm_ulog_request struct, one that can carry
	 * a return payload.  Otherwise, the memory address after
	 * rq will be altered - leading to problems
	 */
	memset(rq_buffer, 0, sizeof(rq_buffer));
	memcpy(tmp, rq, sizeof(struct clog_request) + rq->u_rq.data_size);

	/*
	 * With resumes, we only handle our own.
	 * Resume is a special case that requires
	 * local action (to set up CPG), followed by
	 * a cluster action to co-ordinate reading
	 * the disk and checkpointing
	 */
	if (tmp->u_rq.request_type == DM_ULOG_RESUME) {
		if (tmp->originator == my_cluster_id) {
			r = do_request(tmp, server);

			r = kernel_send(&tmp->u_rq);
			if (r < 0)
				LOG_ERROR("Failed to send resume response to kernel");
		}
		return r;
	}

	r = do_request(tmp, server);

	if (server &&
	    (tmp->u_rq.request_type != DM_ULOG_CLEAR_REGION) &&
	    (tmp->u_rq.request_type != DM_ULOG_POSTSUSPEND)) {
		tmp->u_rq.request_type |= DM_ULOG_RESPONSE;

		/*
		 * Errors from previous functions are in the rq struct.
		 */
		r = cluster_send(tmp);
		if (r < 0)
			LOG_ERROR("cluster_send failed: %s", strerror(-r));
	}

	return r;
}

static int handle_cluster_response(struct clog_cpg *entry,
				   struct clog_request *rq)
{
	int r = 0;
	struct clog_request *orig_rq;

	/*
	 * If I didn't send it, then I don't care about the response
	 */
	if (rq->originator != my_cluster_id)
		return 0;

	rq->u_rq.request_type &= ~DM_ULOG_RESPONSE;
	orig_rq = get_matching_rq(rq, &entry->working_list);

	if (!orig_rq) {
		/* Unable to find match for response */

		LOG_ERROR("[%s] No match for cluster response: %s:%u",
			  SHORT_UUID(rq->u_rq.uuid),
			  _RQ_TYPE(rq->u_rq.request_type),
			  rq->u_rq.seq);

		LOG_ERROR("Current local list:");
		if (dm_list_empty(&entry->working_list))
			LOG_ERROR("   [none]");

		dm_list_iterate_items_gen(orig_rq, &entry->working_list, u.list)
			LOG_ERROR("   [%s]  %s:%u",
				  SHORT_UUID(orig_rq->u_rq.uuid),
				  _RQ_TYPE(orig_rq->u_rq.request_type),
				  orig_rq->u_rq.seq);

		return -EINVAL;
	}

	if (log_resp_rec > 0) {
		LOG_COND(log_resend_requests,
			 "[%s] Response received to %s/#%u",
			 SHORT_UUID(rq->u_rq.uuid),
			 _RQ_TYPE(rq->u_rq.request_type),
			 rq->u_rq.seq);
		log_resp_rec--;
	}

	/* FIXME: Ensure memcpy cannot explode */
	memcpy(orig_rq, rq, sizeof(*rq) + rq->u_rq.data_size);

	r = kernel_send(&orig_rq->u_rq);
	if (r)
		LOG_ERROR("Failed to send response to kernel");

	free(orig_rq);
	return r;
}

static struct clog_cpg *find_clog_cpg(cpg_handle_t handle)
{
	struct clog_cpg *match;

	dm_list_iterate_items(match, &clog_cpg_list)
		if (match->handle == handle)
			return match;

	return NULL;
}

/*
 * prepare_checkpoint
 * @entry: clog_cpg describing the log
 * @cp_requester: nodeid requesting the checkpoint
 *
 * Creates and fills in a new checkpoint_data struct.
 *
 * Returns: checkpoint_data on success, NULL on error
 */
static struct checkpoint_data *prepare_checkpoint(struct clog_cpg *entry,
						  uint32_t cp_requester)
{
	int r;
	struct checkpoint_data *new;

	if (entry->state != VALID) {
		/*
		 * We can't store bitmaps yet, because the log is not
		 * valid yet.
		 */
		LOG_ERROR("Forced to refuse checkpoint for nodeid %u - log not valid yet",
			  cp_requester);
		return NULL;
	}

	new = malloc(sizeof(*new));
	if (!new) {
		LOG_ERROR("Unable to create checkpoint data for %u",
			  cp_requester);
		return NULL;
	}
	memset(new, 0, sizeof(*new));
	new->requester = cp_requester;
	strncpy(new->uuid, entry->name.value, entry->name.length);

	new->bitmap_size = push_state(entry->name.value, entry->luid,
				      "clean_bits",
				      &new->clean_bits, cp_requester);
	if (new->bitmap_size <= 0) {
		LOG_ERROR("Failed to store clean_bits to checkpoint for node %u",
			  new->requester);
		free(new);
		return NULL;
	}

	new->bitmap_size = push_state(entry->name.value, entry->luid,
				      "sync_bits",
				      &new->sync_bits, cp_requester);
	if (new->bitmap_size <= 0) {
		LOG_ERROR("Failed to store sync_bits to checkpoint for node %u",
			  new->requester);
		free(new->clean_bits);
		free(new);
		return NULL;
	}

	r = push_state(entry->name.value, entry->luid,
		       "recovering_region",
		       &new->recovering_region, cp_requester);
	if (r <= 0) {
		LOG_ERROR("Failed to store recovering_region to checkpoint for node %u",
			  new->requester);
		free(new->sync_bits);
		free(new->clean_bits);
		free(new);
		return NULL;
	}
	LOG_DBG("[%s] Checkpoint prepared for node %u:",
		SHORT_UUID(new->uuid), new->requester);
	LOG_DBG("  bitmap_size = %d", new->bitmap_size);

	return new;
}

/*
 * free_checkpoint
 * @cp: the checkpoint_data struct to free
 *
 */
static void free_checkpoint(struct checkpoint_data *cp)
{
	free(cp->recovering_region);
	free(cp->sync_bits);
	free(cp->clean_bits);
	free(cp);
}

#if CMIRROR_HAS_CHECKPOINT
static int export_checkpoint(struct checkpoint_data *cp)
{
	SaCkptCheckpointCreationAttributesT attr;
	SaCkptCheckpointHandleT h;
	SaCkptSectionIdT section_id;
	SaCkptSectionCreationAttributesT section_attr;
	SaCkptCheckpointOpenFlagsT flags;
	SaNameT name;
	SaAisErrorT rv;
	struct clog_request *rq;
	int len, r = 0;
	char buf[32];

	LOG_DBG("Sending checkpointed data to %u", cp->requester);

	len = snprintf((char *)(name.value), SA_MAX_NAME_LENGTH,
		       "bitmaps_%s_%u", SHORT_UUID(cp->uuid), cp->requester);
	name.length = (SaUint16T)len;

	len = (int)strlen(cp->recovering_region) + 1;

	attr.creationFlags = SA_CKPT_WR_ALL_REPLICAS;
	attr.checkpointSize = cp->bitmap_size * 2 + len;

	attr.retentionDuration = SA_TIME_MAX;
	attr.maxSections = 4;      /* don't know why we need +1 */

	attr.maxSectionSize = (cp->bitmap_size > len) ?	cp->bitmap_size : len;
	attr.maxSectionIdSize = 22;

	flags = SA_CKPT_CHECKPOINT_READ |
		SA_CKPT_CHECKPOINT_WRITE |
		SA_CKPT_CHECKPOINT_CREATE;

open_retry:
	rv = saCkptCheckpointOpen(ckpt_handle, &name, &attr, flags, 0, &h);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("export_checkpoint: ckpt open retry");
		usleep(1000);
		goto open_retry;
	}

	if (rv == SA_AIS_ERR_EXIST) {
		LOG_DBG("export_checkpoint: checkpoint already exists");
		return -EEXIST;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("[%s] Failed to open checkpoint for %u: %s",
			  SHORT_UUID(cp->uuid), cp->requester,
			  str_ais_error(rv));
		return -EIO; /* FIXME: better error */
	}

	/*
	 * Add section for sync_bits
	 */
	section_id.idLen = (SaUint16T)snprintf(buf, 32, "sync_bits");
	section_id.id = (unsigned char *)buf;
	section_attr.sectionId = &section_id;
	section_attr.expirationTime = SA_TIME_END;

sync_create_retry:
	rv = saCkptSectionCreate(h, &section_attr,
				 cp->sync_bits, cp->bitmap_size);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("Sync checkpoint section create retry");
		usleep(1000);
		goto sync_create_retry;
	}

	if (rv == SA_AIS_ERR_EXIST) {
		LOG_DBG("Sync checkpoint section already exists");
		saCkptCheckpointClose(h);
		return -EEXIST;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("Sync checkpoint section creation failed: %s",
			  str_ais_error(rv));
		saCkptCheckpointClose(h);
		return -EIO; /* FIXME: better error */
	}

	/*
	 * Add section for clean_bits
	 */
	section_id.idLen = snprintf(buf, 32, "clean_bits");
	section_id.id = (unsigned char *)buf;
	section_attr.sectionId = &section_id;
	section_attr.expirationTime = SA_TIME_END;

clean_create_retry:
	rv = saCkptSectionCreate(h, &section_attr, cp->clean_bits, cp->bitmap_size);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("Clean checkpoint section create retry");
		usleep(1000);
		goto clean_create_retry;
	}

	if (rv == SA_AIS_ERR_EXIST) {
		LOG_DBG("Clean checkpoint section already exists");
		saCkptCheckpointClose(h);
		return -EEXIST;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("Clean checkpoint section creation failed: %s",
			  str_ais_error(rv));
		saCkptCheckpointClose(h);
		return -EIO; /* FIXME: better error */
	}

	/*
	 * Add section for recovering_region
	 */
	section_id.idLen = snprintf(buf, 32, "recovering_region");
	section_id.id = (unsigned char *)buf;
	section_attr.sectionId = &section_id;
	section_attr.expirationTime = SA_TIME_END;

rr_create_retry:
	rv = saCkptSectionCreate(h, &section_attr, cp->recovering_region,
				 strlen(cp->recovering_region) + 1);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("RR checkpoint section create retry");
		usleep(1000);
		goto rr_create_retry;
	}

	if (rv == SA_AIS_ERR_EXIST) {
		LOG_DBG("RR checkpoint section already exists");
		saCkptCheckpointClose(h);
		return -EEXIST;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("RR checkpoint section creation failed: %s",
			  str_ais_error(rv));
		saCkptCheckpointClose(h);
		return -EIO; /* FIXME: better error */
	}

	LOG_DBG("export_checkpoint: closing checkpoint");
	saCkptCheckpointClose(h);

	rq = malloc(DM_ULOG_REQUEST_SIZE);
	if (!rq) {
		LOG_ERROR("export_checkpoint: Unable to allocate transfer structs");
		return -ENOMEM;
	}
	memset(rq, 0, sizeof(*rq));

	dm_list_init(&rq->u.list);
	rq->u_rq.request_type = DM_ULOG_CHECKPOINT_READY;
	rq->originator = cp->requester;  /* FIXME: hack to overload meaning of originator */
	strncpy(rq->u_rq.uuid, cp->uuid, CPG_MAX_NAME_LENGTH);
	rq->u_rq.seq = my_cluster_id;

	r = cluster_send(rq);
	if (r)
		LOG_ERROR("Failed to send checkpoint ready notice: %s",
			  strerror(-r));

	free(rq);
	return 0;
}

#else
static int export_checkpoint(struct checkpoint_data *cp)
{
	int r, rq_size;
	struct clog_request *rq;

	rq_size = sizeof(*rq);
	rq_size += RECOVERING_REGION_SECTION_SIZE;
	rq_size += cp->bitmap_size * 2; /* clean|sync_bits */

	rq = malloc(rq_size);
	if (!rq) {
		LOG_ERROR("export_checkpoint: "
			  "Unable to allocate transfer structs");
		return -ENOMEM;
	}
	memset(rq, 0, rq_size);

	dm_list_init(&rq->u.list);
	rq->u_rq.request_type = DM_ULOG_CHECKPOINT_READY;
	rq->originator = cp->requester;
	strncpy(rq->u_rq.uuid, cp->uuid, CPG_MAX_NAME_LENGTH);
	rq->u_rq.seq = my_cluster_id;
	rq->u_rq.data_size = rq_size - sizeof(*rq);

	/* Sync bits */
	memcpy(rq->u_rq.data, cp->sync_bits, cp->bitmap_size);

	/* Clean bits */
	memcpy(rq->u_rq.data + cp->bitmap_size, cp->clean_bits, cp->bitmap_size);

	/* Recovering region */
	memcpy(rq->u_rq.data + (cp->bitmap_size * 2), cp->recovering_region,
	       strlen(cp->recovering_region));

	r = cluster_send(rq);
	if (r)
		LOG_ERROR("Failed to send checkpoint ready notice: %s",
			  strerror(-r));

	free(rq);
	return 0;
}
#endif /* CMIRROR_HAS_CHECKPOINT */

#if CMIRROR_HAS_CHECKPOINT
static int import_checkpoint(struct clog_cpg *entry, int no_read,
			     struct clog_request *rq __attribute__((unused)))
{
	int rtn = 0;
	SaCkptCheckpointHandleT h;
	SaCkptSectionIterationHandleT itr;
	SaCkptSectionDescriptorT desc;
	SaCkptIOVectorElementT iov;
	SaNameT name;
	SaAisErrorT rv;
	char *bitmap = NULL;
	int len;

	bitmap = malloc(1024*1024);
	if (!bitmap)
		return -ENOMEM;

	len = snprintf((char *)(name.value), SA_MAX_NAME_LENGTH, "bitmaps_%s_%u",
		       SHORT_UUID(entry->name.value), my_cluster_id);
	name.length = (SaUint16T)len;

open_retry:
	rv = saCkptCheckpointOpen(ckpt_handle, &name, NULL,
				  SA_CKPT_CHECKPOINT_READ, 0, &h);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("import_checkpoint: ckpt open retry");
		usleep(1000);
		goto open_retry;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("[%s] Failed to open checkpoint: %s",
			  SHORT_UUID(entry->name.value), str_ais_error(rv));
		free(bitmap);
		return -EIO; /* FIXME: better error */
	}

unlink_retry:
	rv = saCkptCheckpointUnlink(ckpt_handle, &name);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("import_checkpoint: ckpt unlink retry");
		usleep(1000);
		goto unlink_retry;
	}

	if (no_read) {
		LOG_DBG("Checkpoint for this log already received");
		goto no_read;
	}

init_retry:
	rv = saCkptSectionIterationInitialize(h, SA_CKPT_SECTIONS_ANY,
					      SA_TIME_END, &itr);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("import_checkpoint: sync create retry");
		usleep(1000);
		goto init_retry;
	}

	if (rv != SA_AIS_OK) {
		LOG_ERROR("[%s] Sync checkpoint section creation failed: %s",
			  SHORT_UUID(entry->name.value), str_ais_error(rv));
		free(bitmap);
		return -EIO; /* FIXME: better error */
	}

	len = 0;
	while (1) {
		rv = saCkptSectionIterationNext(itr, &desc);
		if (rv == SA_AIS_OK)
			len++;
		else if ((rv == SA_AIS_ERR_NO_SECTIONS) && len)
			break;
		else if (rv != SA_AIS_ERR_TRY_AGAIN) {
			LOG_ERROR("saCkptSectionIterationNext failure: %d", rv);
			break;
		}
	}
	saCkptSectionIterationFinalize(itr);
	if (len != 3) {
		LOG_ERROR("import_checkpoint: %d checkpoint sections found",
			  len);
		usleep(1000);
		goto init_retry;
	}
	saCkptSectionIterationInitialize(h, SA_CKPT_SECTIONS_ANY,
					 SA_TIME_END, &itr);

	while (1) {
		rv = saCkptSectionIterationNext(itr, &desc);
		if (rv == SA_AIS_ERR_NO_SECTIONS)
			break;

		if (rv == SA_AIS_ERR_TRY_AGAIN) {
			LOG_ERROR("import_checkpoint: ckpt iternext retry");
			usleep(1000);
			continue;
		}

		if (rv != SA_AIS_OK) {
			LOG_ERROR("import_checkpoint: clean checkpoint section "
				  "creation failed: %s", str_ais_error(rv));
			rtn = -EIO; /* FIXME: better error */
			goto fail;
		}

		if (!desc.sectionSize) {
			LOG_ERROR("Checkpoint section empty");
			continue;
		}

		memset(bitmap, 0, sizeof(*bitmap));
		iov.sectionId = desc.sectionId;
		iov.dataBuffer = bitmap;
		iov.dataSize = desc.sectionSize;
		iov.dataOffset = 0;

	read_retry:
		rv = saCkptCheckpointRead(h, &iov, 1, NULL);
		if (rv == SA_AIS_ERR_TRY_AGAIN) {
			LOG_ERROR("ckpt read retry");
			usleep(1000);
			goto read_retry;
		}

		if (rv != SA_AIS_OK) {
			LOG_ERROR("import_checkpoint: ckpt read error: %s",
				  str_ais_error(rv));
			rtn = -EIO; /* FIXME: better error */
			goto fail;
		}

		if (iov.readSize) {
			if (pull_state(entry->name.value, entry->luid,
				       (char *)desc.sectionId.id, bitmap,
				       iov.readSize)) {
				LOG_ERROR("Error loading state");
				rtn = -EIO;
				goto fail;
			}
		} else {
			/* Need to request new checkpoint */
			rtn = -EAGAIN;
			goto fail;
		}
	}

fail:
	saCkptSectionIterationFinalize(itr);
no_read:
	saCkptCheckpointClose(h);

	free(bitmap);
	return rtn;
}

#else
static int import_checkpoint(struct clog_cpg *entry, int no_read,
			     struct clog_request *rq)
{
	int bitmap_size;

	if (no_read) {
		LOG_DBG("Checkpoint for this log already received");
		return 0;
	}

	bitmap_size = (rq->u_rq.data_size - RECOVERING_REGION_SECTION_SIZE) / 2;
	if (bitmap_size < 0) {
		LOG_ERROR("Checkpoint has invalid payload size.");
		return -EINVAL;
	}

	if (pull_state(entry->name.value, entry->luid, "sync_bits",
		       rq->u_rq.data, bitmap_size) ||
	    pull_state(entry->name.value, entry->luid, "clean_bits",
		       rq->u_rq.data + bitmap_size, bitmap_size) ||
	    pull_state(entry->name.value, entry->luid, "recovering_region",
		       rq->u_rq.data + (bitmap_size * 2),
		       RECOVERING_REGION_SECTION_SIZE)) {
		LOG_ERROR("Error loading bitmap state from checkpoint.");
		return -EIO;
	}
	return 0;
}
#endif /* CMIRROR_HAS_CHECKPOINT */

static void do_checkpoints(struct clog_cpg *entry, int leaving)
{
	struct checkpoint_data *cp;

	for (cp = entry->checkpoint_list; cp;) {
		/*
		 * FIXME: Check return code.  Could send failure
		 * notice in rq in export_checkpoint function
		 * by setting rq->error
		 */
		switch (export_checkpoint(cp)) {
		case -EEXIST:
			LOG_SPRINT(entry, "[%s] Checkpoint for %u already handled%s",
				   SHORT_UUID(entry->name.value), cp->requester,
				   (leaving) ? "(L)": "");
			LOG_COND(log_checkpoint,
				 "[%s] Checkpoint for %u already handled%s",
				 SHORT_UUID(entry->name.value), cp->requester,
				 (leaving) ? "(L)": "");
			entry->checkpoint_list = cp->next;
			free_checkpoint(cp);
			cp = entry->checkpoint_list;
			break;
		case 0:
			LOG_SPRINT(entry, "[%s] Checkpoint data available for node %u%s",
				   SHORT_UUID(entry->name.value), cp->requester,
				   (leaving) ? "(L)": "");
			LOG_COND(log_checkpoint,
				 "[%s] Checkpoint data available for node %u%s",
				 SHORT_UUID(entry->name.value), cp->requester,
				 (leaving) ? "(L)": "");
			entry->checkpoint_list = cp->next;
			free_checkpoint(cp);
			cp = entry->checkpoint_list;
			break;
		default:
			/* FIXME: Skipping will cause list corruption */
			LOG_ERROR("[%s] Failed to export checkpoint for %u%s",
				  SHORT_UUID(entry->name.value), cp->requester,
				  (leaving) ? "(L)": "");
		}
	}
}

static int resend_requests(struct clog_cpg *entry)
{
	int r = 0;
	struct clog_request *rq, *n;

	if (!entry->resend_requests || entry->delay)
		return 0;

	if (entry->state != VALID)
		return 0;

	entry->resend_requests = 0;

	dm_list_iterate_items_gen_safe(rq, n, &entry->working_list, u.list) {
		dm_list_del(&rq->u.list);

		if (strcmp(entry->name.value, rq->u_rq.uuid)) {
			LOG_ERROR("[%s]  Stray request from another log (%s)",
				  SHORT_UUID(entry->name.value),
				  SHORT_UUID(rq->u_rq.uuid));
			free(rq);
			continue;
		}

		switch (rq->u_rq.request_type) {
		case DM_ULOG_SET_REGION_SYNC:
			/*
			 * Some requests simply do not need to be resent.
			 * If it is a request that just changes log state,
			 * then it doesn't need to be resent (everyone makes
			 * updates).
			 */
			LOG_COND(log_resend_requests,
				 "[%s] Skipping resend of %s/#%u...",
				 SHORT_UUID(entry->name.value),
				 _RQ_TYPE(rq->u_rq.request_type),
				 rq->u_rq.seq);
			LOG_SPRINT(entry, "###  No resend: [%s] %s/%u ###",
				   SHORT_UUID(entry->name.value),
				   _RQ_TYPE(rq->u_rq.request_type),
				   rq->u_rq.seq);

			rq->u_rq.data_size = 0;
			if (kernel_send(&rq->u_rq))
				LOG_ERROR("Failed to respond to kernel [%s]",
					  RQ_TYPE(rq->u_rq.request_type));
			break;

		default:
			/*
			 * If an action or a response is required, then
			 * the request must be resent.
			 */
			LOG_COND(log_resend_requests,
				 "[%s] Resending %s(#%u) due to new server(%u)",
				 SHORT_UUID(entry->name.value),
				 _RQ_TYPE(rq->u_rq.request_type),
				 rq->u_rq.seq, entry->lowest_id);
			LOG_SPRINT(entry, "***  Resending: [%s] %s/%u ***",
				   SHORT_UUID(entry->name.value),
				   _RQ_TYPE(rq->u_rq.request_type),
				   rq->u_rq.seq);
			r = cluster_send(rq);
			if (r < 0)
				LOG_ERROR("Failed resend");
		}
		free(rq);
	}

	return r;
}

static int do_cluster_work(void *data __attribute__((unused)))
{
	int r = CS_OK;
	struct clog_cpg *entry, *tmp;

	dm_list_iterate_items_safe(entry, tmp, &clog_cpg_list) {
		r = cpg_dispatch(entry->handle, CS_DISPATCH_ALL);
		if (r != CS_OK) {
			if ((r == CS_ERR_BAD_HANDLE) &&
			    ((entry->state == INVALID) ||
			     (entry->state == LEAVING)))
				/* It's ok if we've left the cluster */
				r = CS_OK;
			else
				LOG_ERROR("cpg_dispatch failed: %s",
					  str_ais_error(r));
		}

		if (entry->free_me) {
			free(entry);
			continue;
		}
		do_checkpoints(entry, 0);

		resend_requests(entry);
	}

	return (r == CS_OK) ? 0 : -1;  /* FIXME: good error number? */
}

static int flush_startup_list(struct clog_cpg *entry)
{
	int r = 0;
	int i_was_server;
	struct clog_request *rq, *n;
	struct checkpoint_data *new;

	dm_list_iterate_items_gen_safe(rq, n, &entry->startup_list, u.list) {
		dm_list_del(&rq->u.list);

		if (rq->u_rq.request_type == DM_ULOG_MEMBER_JOIN) {
			new = prepare_checkpoint(entry, rq->originator);
			if (!new) {
				/*
				 * FIXME: Need better error handling.  Other nodes
				 * will be trying to send the checkpoint too, and we
				 * must continue processing the list; so report error
				 * but continue.
				 */
				LOG_ERROR("Failed to prepare checkpoint for %u!!!",
					  rq->originator);
				free(rq);
				continue;
			}
			LOG_SPRINT(entry, "[%s] Checkpoint prepared for %u",
				   SHORT_UUID(entry->name.value), rq->originator);
			LOG_COND(log_checkpoint, "[%s] Checkpoint prepared for %u",
				 SHORT_UUID(entry->name.value), rq->originator);
			new->next = entry->checkpoint_list;
			entry->checkpoint_list = new;
		} else {
			LOG_DBG("[%s] Processing delayed request: %s",
				SHORT_UUID(rq->u_rq.uuid),
				_RQ_TYPE(rq->u_rq.request_type));
			i_was_server = (rq->pit_server == my_cluster_id) ? 1 : 0;
			r = handle_cluster_request(entry, rq, i_was_server);

			if (r)
				/*
				 * FIXME: If we error out here, we will never get
				 * another opportunity to retry these requests
				 */
				LOG_ERROR("Error while processing delayed CPG message");
		}
		free(rq);
	}

	return 0;
}

static void cpg_message_callback(cpg_handle_t handle, const struct cpg_name *gname __attribute__((unused)),
				 uint32_t nodeid, uint32_t pid __attribute__((unused)),
				 void *msg, size_t msg_len)
{
	int i;
	int r = 0;
	int i_am_server;
	int response = 0;
	struct clog_request *rq = msg;
	struct clog_request *tmp_rq, *tmp_rq2;
	struct clog_cpg *match;

	match = find_clog_cpg(handle);
	if (!match) {
		LOG_ERROR("Unable to find clog_cpg for cluster message");
		return;
	}

	/*
	 * Perform necessary endian and version compatibility conversions
	 */
	if (clog_request_from_network(rq, msg_len) < 0)
		/* Any error messages come from 'clog_request_from_network' */
		return;

	if ((nodeid == my_cluster_id) &&
	    !(rq->u_rq.request_type & DM_ULOG_RESPONSE) &&
	    (rq->u_rq.request_type != DM_ULOG_RESUME) &&
	    (rq->u_rq.request_type != DM_ULOG_CLEAR_REGION) &&
	    (rq->u_rq.request_type != DM_ULOG_CHECKPOINT_READY)) {
		tmp_rq = malloc(DM_ULOG_REQUEST_SIZE);
		if (!tmp_rq) {
			/*
			 * FIXME: It may be possible to continue... but we
			 * would not be able to resend any messages that might
			 * be necessary during membership changes
			 */
			LOG_ERROR("[%s] Unable to record request: -ENOMEM",
				  SHORT_UUID(rq->u_rq.uuid));
			return;
		}
		memcpy(tmp_rq, rq, sizeof(*rq) + rq->u_rq.data_size);
		dm_list_init(&tmp_rq->u.list);
		dm_list_add(&match->working_list, &tmp_rq->u.list);
	}

	if (rq->u_rq.request_type == DM_ULOG_POSTSUSPEND) {
		/*
		 * If the server (lowest_id) indicates it is leaving,
		 * then we must resend any outstanding requests.  However,
		 * we do not want to resend them if the next server in
		 * line is in the process of leaving.
		 */
		if (nodeid == my_cluster_id) {
			LOG_COND(log_resend_requests, "[%s] I am leaving.1.....",
				 SHORT_UUID(rq->u_rq.uuid));
		} else {
			if (nodeid < my_cluster_id) {
				if (nodeid == match->lowest_id) {
					match->resend_requests = 1;
					LOG_COND(log_resend_requests, "[%s] %u is leaving, resend required%s",
						 SHORT_UUID(rq->u_rq.uuid), nodeid,
						 (dm_list_empty(&match->working_list)) ? " -- working_list empty": "");

					dm_list_iterate_items_gen(tmp_rq, &match->working_list, u.list)
						LOG_COND(log_resend_requests,
							 "[%s]                %s/%u",
							 SHORT_UUID(tmp_rq->u_rq.uuid),
							 _RQ_TYPE(tmp_rq->u_rq.request_type),
							 tmp_rq->u_rq.seq);
				}

				match->delay++;
				LOG_COND(log_resend_requests, "[%s] %u is leaving, delay = %d",
					 SHORT_UUID(rq->u_rq.uuid), nodeid, match->delay);
			}
			rq->originator = nodeid; /* don't really need this, but nice for debug */
			goto out;
		}
	}

	/*
	 * We can receive messages after we do a cpg_leave but before we
	 * get our config callback.  However, since we can't respond after
	 * leaving, we simply return.
	 */
	if (match->state == LEAVING)
		return;

	i_am_server = (my_cluster_id == match->lowest_id) ? 1 : 0;

	if (rq->u_rq.request_type == DM_ULOG_CHECKPOINT_READY) {
		if (my_cluster_id == rq->originator) {
			/* Redundant checkpoints ignored if match->valid */
			LOG_SPRINT(match, "[%s] CHECKPOINT_READY notification from %u",
				   SHORT_UUID(rq->u_rq.uuid), nodeid);
			if (import_checkpoint(match,
					      (match->state != INVALID), rq)) {
				LOG_SPRINT(match,
					   "[%s] Failed to import checkpoint from %u",
					   SHORT_UUID(rq->u_rq.uuid), nodeid);
				LOG_ERROR("[%s] Failed to import checkpoint from %u",
					  SHORT_UUID(rq->u_rq.uuid), nodeid);
				kill(getpid(), SIGUSR1);
				/* Could we retry? */
				goto out;
			} else if (match->state == INVALID) {
				LOG_SPRINT(match,
					   "[%s] Checkpoint data received from %u.  Log is now valid",
					   SHORT_UUID(match->name.value), nodeid);
				LOG_COND(log_checkpoint,
					 "[%s] Checkpoint data received from %u.  Log is now valid",
					 SHORT_UUID(match->name.value), nodeid);
				match->state = VALID;

				flush_startup_list(match);
			} else {
				LOG_SPRINT(match,
					   "[%s] Redundant checkpoint from %u ignored.",
					   SHORT_UUID(rq->u_rq.uuid), nodeid);
			}
		}
		goto out;
	}

	if (rq->u_rq.request_type & DM_ULOG_RESPONSE) {
		response = 1;
		r = handle_cluster_response(match, rq);
	} else {
		rq->originator = nodeid;

		if (match->state == LEAVING) {
			LOG_ERROR("[%s]  Ignoring %s from %u.  Reason: I'm leaving",
				  SHORT_UUID(rq->u_rq.uuid), _RQ_TYPE(rq->u_rq.request_type),
				  rq->originator);
			goto out;
		}

		if (match->state == INVALID) {
			LOG_DBG("Log not valid yet, storing request");
			if (!(tmp_rq2 = malloc(DM_ULOG_REQUEST_SIZE))) {
				LOG_ERROR("cpg_message_callback:  Unable to"
					  " allocate transfer structs");
				r = -ENOMEM; /* FIXME: Better error #? */
				goto out;
			}

			memcpy(tmp_rq2, rq, sizeof(*rq) + rq->u_rq.data_size);
			tmp_rq2->pit_server = match->lowest_id;
			dm_list_init(&tmp_rq2->u.list);
			dm_list_add(&match->startup_list, &tmp_rq2->u.list);
			goto out;
		}

		r = handle_cluster_request(match, rq, i_am_server);
	}

	/*
	 * If the log is now valid, we can queue the checkpoints
	 */
	for (i = match->checkpoints_needed; i; ) {
		struct checkpoint_data *new;

		if (log_get_state(&rq->u_rq) != LOG_RESUMED) {
			LOG_DBG("[%s] Withholding checkpoints until log is valid (%s from %u)",
				SHORT_UUID(rq->u_rq.uuid), _RQ_TYPE(rq->u_rq.request_type), nodeid);
			break;
		}

		i--;
		new = prepare_checkpoint(match, match->checkpoint_requesters[i]);
		if (!new) {
			/* FIXME: Need better error handling */
			LOG_ERROR("[%s] Failed to prepare checkpoint for %u!!!",
				  SHORT_UUID(rq->u_rq.uuid), match->checkpoint_requesters[i]);
			break;
		}
		LOG_SPRINT(match, "[%s] Checkpoint prepared for %u* (%s)",
			   SHORT_UUID(rq->u_rq.uuid), match->checkpoint_requesters[i],
			   (log_get_state(&rq->u_rq) != LOG_RESUMED)? "LOG_RESUMED": "LOG_SUSPENDED");
		LOG_COND(log_checkpoint, "[%s] Checkpoint prepared for %u*",
			 SHORT_UUID(rq->u_rq.uuid), match->checkpoint_requesters[i]);
		match->checkpoints_needed--;

		new->next = match->checkpoint_list;
		match->checkpoint_list = new;
	}

out:
	/* nothing happens after this point.  It is just for debugging */
	if (r) {
		LOG_ERROR("[%s] Error while processing CPG message, %s: %s",
			  SHORT_UUID(rq->u_rq.uuid),
			  _RQ_TYPE(rq->u_rq.request_type & ~DM_ULOG_RESPONSE),
			  strerror(-r));
		LOG_ERROR("[%s]    Response  : %s", SHORT_UUID(rq->u_rq.uuid),
			  (response) ? "YES" : "NO");
		LOG_ERROR("[%s]    Originator: %u",
			  SHORT_UUID(rq->u_rq.uuid), rq->originator);
		if (response)
			LOG_ERROR("[%s]    Responder : %u",
				  SHORT_UUID(rq->u_rq.uuid), nodeid);

		LOG_ERROR("HISTORY::");
		for (i = 0; i < DEBUGGING_HISTORY; i++) {
			match->idx++;
			match->idx = match->idx % DEBUGGING_HISTORY;
			if (match->debugging[match->idx][0] == '\0')
				continue;
			LOG_ERROR("%d:%d) %s", i, match->idx,
				  match->debugging[match->idx]);
		}
	} else if (!(rq->u_rq.request_type & DM_ULOG_RESPONSE) ||
		   (rq->originator == my_cluster_id)) {
		if (!response)
			LOG_SPRINT(match, "SEQ#=%u, UUID=%s, TYPE=%s, ORIG=%u, RESP=%s",
				   rq->u_rq.seq, SHORT_UUID(rq->u_rq.uuid),
				   _RQ_TYPE(rq->u_rq.request_type),
				   rq->originator, (response) ? "YES" : "NO");
		else
			LOG_SPRINT(match, "SEQ#=%u, UUID=%s, TYPE=%s, ORIG=%u, RESP=%s, RSPR=%u, error=%d",
				   rq->u_rq.seq, SHORT_UUID(rq->u_rq.uuid),
				   _RQ_TYPE(rq->u_rq.request_type),
				   rq->originator, (response) ? "YES" : "NO",
				   nodeid, rq->u_rq.error);
	}
}

static void cpg_join_callback(struct clog_cpg *match,
			      const struct cpg_address *joined,
			      const struct cpg_address *member_list,
			      size_t member_list_entries)
{
	unsigned i;
	uint32_t my_pid = (uint32_t)getpid();
	uint32_t lowest = match->lowest_id;
	struct clog_request *rq;
	char dbuf[64] = { 0 };
	char *dbuf_p = dbuf;
	size_t dbuf_rem = sizeof dbuf;

	/* Assign my_cluster_id */
	if ((my_cluster_id == 0xDEAD) && (joined->pid == my_pid))
		my_cluster_id = joined->nodeid;

	/* Am I the very first to join? */
	if (member_list_entries == 1) {
		match->lowest_id = joined->nodeid;
		match->state = VALID;
	}

	/* If I am part of the joining list, I do not send checkpoints */
	if (joined->nodeid == my_cluster_id)
		goto out;

	for (i = 0; i < member_list_entries - 1; i++) {
		int written = snprintf(dbuf_p, dbuf_rem, "%u-", member_list[i].nodeid);
		if (written < 0) continue; /* impossible */
		if ((unsigned)written >= dbuf_rem) {
			dbuf_rem = 0;
			break;
		}
		dbuf_rem -= written;
		dbuf_p += written;
	}
	snprintf(dbuf_p, dbuf_rem, "(%u)", joined->nodeid);
	LOG_COND(log_checkpoint, "[%s] Joining node, %u needs checkpoint [%s]",
		 SHORT_UUID(match->name.value), joined->nodeid, dbuf);

	/*
	 * FIXME: remove checkpoint_requesters/checkpoints_needed, and use
	 * the startup_list interface exclusively
	 */
	if (dm_list_empty(&match->startup_list) && (match->state == VALID) &&
	    (match->checkpoints_needed < MAX_CHECKPOINT_REQUESTERS)) {
		match->checkpoint_requesters[match->checkpoints_needed++] = joined->nodeid;
		goto out;
	}

	rq = malloc(DM_ULOG_REQUEST_SIZE);
	if (!rq) {
		LOG_ERROR("cpg_config_callback: "
			  "Unable to allocate transfer structs");
		LOG_ERROR("cpg_config_callback: "
			  "Unable to perform checkpoint");
		goto out;
	}
	rq->u_rq.request_type = DM_ULOG_MEMBER_JOIN;
	rq->originator = joined->nodeid;
	dm_list_init(&rq->u.list);
	dm_list_add(&match->startup_list, &rq->u.list);

out:
	/* Find the lowest_id, i.e. the server */
	match->lowest_id = member_list[0].nodeid;
	for (i = 0; i < member_list_entries; i++)
		if (match->lowest_id > member_list[i].nodeid)
			match->lowest_id = member_list[i].nodeid;

	if (lowest == 0xDEAD)
		LOG_COND(log_membership_change, "[%s]  Server change <none> -> %u (%u %s)",
			 SHORT_UUID(match->name.value), match->lowest_id,
			 joined->nodeid, (member_list_entries == 1) ?
			 "is first to join" : "joined");
	else if (lowest != match->lowest_id)
		LOG_COND(log_membership_change, "[%s]  Server change %u -> %u (%u joined)",
			 SHORT_UUID(match->name.value), lowest,
			 match->lowest_id, joined->nodeid);
	else
		LOG_COND(log_membership_change, "[%s]  Server unchanged at %u (%u joined)",
			 SHORT_UUID(match->name.value),
			 lowest, joined->nodeid);
	LOG_SPRINT(match, "+++  UUID=%s  %u join  +++",
		   SHORT_UUID(match->name.value), joined->nodeid);
}

static void cpg_leave_callback(struct clog_cpg *match,
			       const struct cpg_address *left,
			       const struct cpg_address *member_list,
			       size_t member_list_entries)
{
	unsigned i;
	int j, fd;
	uint32_t lowest = match->lowest_id;
	struct clog_request *rq, *n;
	struct checkpoint_data *p_cp, *c_cp;

	LOG_SPRINT(match, "---  UUID=%s  %u left  ---",
		   SHORT_UUID(match->name.value), left->nodeid);

	/* Am I leaving? */
	if (my_cluster_id == left->nodeid) {
		LOG_DBG("Finalizing leave...");
		dm_list_del(&match->list);

		cpg_fd_get(match->handle, &fd);
		links_unregister(fd);

		cluster_postsuspend(match->name.value, match->luid);

		dm_list_iterate_items_gen_safe(rq, n, &match->working_list, u.list) {
			dm_list_del(&rq->u.list);

			if (rq->u_rq.request_type == DM_ULOG_POSTSUSPEND)
				if (kernel_send(&rq->u_rq))
					LOG_ERROR("Failed to respond to kernel [%s]",
						  RQ_TYPE(rq->u_rq.request_type));
			free(rq);
		}

		cpg_finalize(match->handle);

		match->free_me = 1;
		match->lowest_id = 0xDEAD;
		match->state = INVALID;
	}

	/* Remove any pending checkpoints for the leaving node. */
	for (p_cp = NULL, c_cp = match->checkpoint_list;
	     c_cp && (c_cp->requester != left->nodeid);
	     p_cp = c_cp, c_cp = c_cp->next);
	if (c_cp) {
		if (p_cp)
			p_cp->next = c_cp->next;
		else
			match->checkpoint_list = c_cp->next;

		LOG_COND(log_checkpoint,
			 "[%s] Removing pending checkpoint (%u is leaving)",
			 SHORT_UUID(match->name.value), left->nodeid);
		free_checkpoint(c_cp);
	}
	dm_list_iterate_items_gen_safe(rq, n, &match->startup_list, u.list) {
		if ((rq->u_rq.request_type == DM_ULOG_MEMBER_JOIN) &&
		    (rq->originator == left->nodeid)) {
			LOG_COND(log_checkpoint,
				 "[%s] Removing pending ckpt from startup list (%u is leaving)",
				 SHORT_UUID(match->name.value), left->nodeid);
			dm_list_del(&rq->u.list);
			free(rq);
		}
	}
	for (i = 0, j = 0; i < match->checkpoints_needed; i++, j++) {
		match->checkpoint_requesters[j] = match->checkpoint_requesters[i];
		if (match->checkpoint_requesters[i] == left->nodeid) {
			LOG_ERROR("[%s] Removing pending ckpt from needed list (%u is leaving)",
				  SHORT_UUID(match->name.value), left->nodeid);
			j--;
		}
	}
	match->checkpoints_needed = j;

	if (left->nodeid < my_cluster_id) {
		match->delay = (match->delay > 0) ? match->delay - 1 : 0;
		if (!match->delay && dm_list_empty(&match->working_list))
			match->resend_requests = 0;
		LOG_COND(log_resend_requests, "[%s] %u has left, delay = %d%s",
			 SHORT_UUID(match->name.value), left->nodeid,
			 match->delay, (dm_list_empty(&match->working_list)) ?
			 " -- working_list empty": "");
	}

	/* Find the lowest_id, i.e. the server */
	if (!member_list_entries) {
		match->lowest_id = 0xDEAD;
		LOG_COND(log_membership_change, "[%s]  Server change %u -> <none> "
			 "(%u is last to leave)",
			 SHORT_UUID(match->name.value), left->nodeid,
			 left->nodeid);
		return;
	}

	match->lowest_id = member_list[0].nodeid;
	for (i = 0; i < member_list_entries; i++)
		if (match->lowest_id > member_list[i].nodeid)
			match->lowest_id = member_list[i].nodeid;

	if (lowest != match->lowest_id) {
		LOG_COND(log_membership_change, "[%s]  Server change %u -> %u (%u left)",
			 SHORT_UUID(match->name.value), lowest,
			 match->lowest_id, left->nodeid);
	} else
		LOG_COND(log_membership_change, "[%s]  Server unchanged at %u (%u left)",
			 SHORT_UUID(match->name.value), lowest, left->nodeid);

	if ((match->state == INVALID) && !match->free_me) {
		/*
		 * If all CPG members are waiting for checkpoints and they
		 * are all present in my startup_list, then I was the first to
		 * join and I must assume control.
		 *
		 * We do not normally end up here, but if there was a quick
		 * 'resume -> suspend -> resume' across the cluster, we may
		 * have initially thought we were not the first to join because
		 * of the presence of out-going (and unable to respond) members.
		 */

		i = 1; /* We do not have a DM_ULOG_MEMBER_JOIN entry of our own */
		dm_list_iterate_items_gen(rq, &match->startup_list, u.list)
			if (rq->u_rq.request_type == DM_ULOG_MEMBER_JOIN)
				i++;

		if (i == member_list_entries) {
			/* 
			 * Last node who could have given me a checkpoint just left.
			 * Setting log state to VALID and acting as 'first join'.
			 */
			match->state = VALID;
			flush_startup_list(match);
		}
	}
}

static void cpg_config_callback(cpg_handle_t handle, const struct cpg_name *gname __attribute__((unused)),
				const struct cpg_address *member_list,
				size_t member_list_entries,
				const struct cpg_address *left_list,
				size_t left_list_entries,
				const struct cpg_address *joined_list,
				size_t joined_list_entries)
{
	struct clog_cpg *match;
	int found = 0;

	dm_list_iterate_items(match, &clog_cpg_list)
		if (match->handle == handle) {
			found = 1;
			break;
		}

	if (!found) {
		LOG_ERROR("Unable to find match for CPG config callback");
		return;
	}

	if ((joined_list_entries + left_list_entries) > 1)
		LOG_ERROR("[%s]  More than one node joining/leaving",
			  SHORT_UUID(match->name.value));

	if (joined_list_entries)
		cpg_join_callback(match, joined_list,
				  member_list, member_list_entries);
	else
		cpg_leave_callback(match, left_list,
				   member_list, member_list_entries);
}

cpg_callbacks_t cpg_callbacks = {
	.cpg_deliver_fn = cpg_message_callback,
	.cpg_confchg_fn = cpg_config_callback,
};

/*
 * remove_checkpoint
 * @entry
 *
 * Returns: 1 if checkpoint removed, 0 if no checkpoints, -EXXX on error
 */
static int remove_checkpoint(struct clog_cpg *entry)
{
#if CMIRROR_HAS_CHECKPOINT
	int len;
	SaNameT name;
	SaAisErrorT rv;
	SaCkptCheckpointHandleT h;

	len = snprintf((char *)(name.value), SA_MAX_NAME_LENGTH, "bitmaps_%s_%u",
                       SHORT_UUID(entry->name.value), my_cluster_id);
	name.length = len;

open_retry:
	rv = saCkptCheckpointOpen(ckpt_handle, &name, NULL,
                                  SA_CKPT_CHECKPOINT_READ, 0, &h);
	if (rv == SA_AIS_ERR_TRY_AGAIN) {
		LOG_ERROR("abort_startup: ckpt open retry");
                usleep(1000);
                goto open_retry;
        }

	if (rv != SA_AIS_OK)
                return 0;

	LOG_DBG("[%s]  Removing checkpoint", SHORT_UUID(entry->name.value));
unlink_retry:
        rv = saCkptCheckpointUnlink(ckpt_handle, &name);
        if (rv == SA_AIS_ERR_TRY_AGAIN) {
                LOG_ERROR("abort_startup: ckpt unlink retry");
                usleep(1000);
                goto unlink_retry;
        }

	if (rv != SA_AIS_OK) {
                LOG_ERROR("[%s] Failed to unlink checkpoint: %s",
                          SHORT_UUID(entry->name.value), str_ais_error(rv));
                return -EIO;
        }

	saCkptCheckpointClose(h);

	return 1;
#else
	/* No checkpoint to remove, so 'success' */
	return 1;
#endif
}

int create_cluster_cpg(char *uuid, uint64_t luid)
{
	int r;
	size_t size;
	struct clog_cpg *new = NULL;
	struct clog_cpg *tmp;

	dm_list_iterate_items(tmp, &clog_cpg_list)
		if (!strncmp(tmp->name.value, uuid, CPG_MAX_NAME_LENGTH)) {
			LOG_ERROR("Log entry already exists: %s", uuid);
			return -EEXIST;
		}

	new = malloc(sizeof(*new));
	if (!new) {
		LOG_ERROR("Unable to allocate memory for clog_cpg");
		return -ENOMEM;
	}
	memset(new, 0, sizeof(*new));
	dm_list_init(&new->list);
	new->lowest_id = 0xDEAD;
	dm_list_init(&new->startup_list);
	dm_list_init(&new->working_list);

	size = ((strlen(uuid) + 1) > CPG_MAX_NAME_LENGTH) ?
		CPG_MAX_NAME_LENGTH : (strlen(uuid) + 1);
	strncpy(new->name.value, uuid, size);
	new->name.length = (uint32_t)size;
	new->luid = luid;

	/*
	 * Ensure there are no stale checkpoints around before we join
	 */
	if (remove_checkpoint(new) == 1)
		LOG_COND(log_checkpoint,
			 "[%s]  Removing checkpoints left from previous session",
			 SHORT_UUID(new->name.value));

	r = cpg_initialize(&new->handle, &cpg_callbacks);
	if (r != CS_OK) {
		LOG_ERROR("cpg_initialize failed:  Cannot join cluster");
		free(new);
		return -EPERM;
	}

	r = cpg_join(new->handle, &new->name);
	if (r != CS_OK) {
		LOG_ERROR("cpg_join failed:  Cannot join cluster");
		free(new);
		return -EPERM;
	}

	new->cpg_state = VALID;
	dm_list_add(&clog_cpg_list, &new->list);
	LOG_DBG("New   handle: %llu", (unsigned long long)new->handle);
	LOG_DBG("New   name: %s", new->name.value);

	/* FIXME: better variable */
	cpg_fd_get(new->handle, &r);
	links_register(r, "cluster", do_cluster_work, NULL);

	return 0;
}

static void abort_startup(struct clog_cpg *del)
{
	struct clog_request *rq, *n;

	LOG_DBG("[%s]  CPG teardown before checkpoint received",
		SHORT_UUID(del->name.value));

	dm_list_iterate_items_gen_safe(rq, n, &del->startup_list, u.list) {
		dm_list_del(&rq->u.list);

		LOG_DBG("[%s]  Ignoring request from %u: %s",
			SHORT_UUID(del->name.value), rq->originator,
			_RQ_TYPE(rq->u_rq.request_type));
		free(rq);
	}

	remove_checkpoint(del);
}

static int _destroy_cluster_cpg(struct clog_cpg *del)
{
	int r;
	int state;

	LOG_COND(log_resend_requests, "[%s] I am leaving.2.....",
		 SHORT_UUID(del->name.value));

	/*
	 * We must send any left over checkpoints before
	 * leaving.  If we don't, an incoming node could
	 * be stuck with no checkpoint and stall.
	 do_checkpoints(del); --- THIS COULD BE CAUSING OUR PROBLEMS:

	 - Incoming node deletes old checkpoints before joining
	 - A stale checkpoint is issued here by leaving node
	 - (leaving node leaves)
	 - Incoming node joins cluster and finds stale checkpoint.
	 - (leaving node leaves - option 2)
	*/
	do_checkpoints(del, 1);

	state = del->state;

	del->cpg_state = INVALID;
	del->state = LEAVING;

	/*
	 * If the state is VALID, we might be processing the
	 * startup list.  If so, we certainly don't want to
	 * clear the startup_list here by calling abort_startup
	 */
	if (!dm_list_empty(&del->startup_list) && (state != VALID))
		abort_startup(del);

	r = cpg_leave(del->handle, &del->name);
	if (r != CS_OK)
		LOG_ERROR("Error leaving CPG!");
	return 0;
}

int destroy_cluster_cpg(char *uuid)
{
	struct clog_cpg *del, *tmp;

	dm_list_iterate_items_safe(del, tmp, &clog_cpg_list)
		if (!strncmp(del->name.value, uuid, CPG_MAX_NAME_LENGTH))
			_destroy_cluster_cpg(del);

	return 0;
}

int init_cluster(void)
{
#if CMIRROR_HAS_CHECKPOINT
	SaAisErrorT rv;

	rv = saCkptInitialize(&ckpt_handle, &callbacks, &version);

	if (rv != SA_AIS_OK)
		return EXIT_CLUSTER_CKPT_INIT;
#endif
	dm_list_init(&clog_cpg_list);
	return 0;
}

void cleanup_cluster(void)
{
#if CMIRROR_HAS_CHECKPOINT
	SaAisErrorT err;

	err = saCkptFinalize(ckpt_handle);
	if (err != SA_AIS_OK)
		LOG_ERROR("Failed to finalize checkpoint handle");
#endif
}

void cluster_debug(void)
{
	struct checkpoint_data *cp;
	struct clog_cpg *entry;
	struct clog_request *rq;
	int i;

	LOG_ERROR("");
	LOG_ERROR("CLUSTER COMPONENT DEBUGGING::");
	dm_list_iterate_items(entry, &clog_cpg_list) {
		LOG_ERROR("%s::", SHORT_UUID(entry->name.value));
		LOG_ERROR("  lowest_id         : %u", entry->lowest_id);
		LOG_ERROR("  state             : %s", (entry->state == INVALID) ?
			  "INVALID" : (entry->state == VALID) ? "VALID" :
			  (entry->state == LEAVING) ? "LEAVING" : "UNKNOWN");
		LOG_ERROR("  cpg_state         : %d", entry->cpg_state);
		LOG_ERROR("  free_me           : %d", entry->free_me);
		LOG_ERROR("  delay             : %d", entry->delay);
		LOG_ERROR("  resend_requests   : %d", entry->resend_requests);
		LOG_ERROR("  checkpoints_needed: %d", entry->checkpoints_needed);
		for (i = 0, cp = entry->checkpoint_list;
		     i < MAX_CHECKPOINT_REQUESTERS; i++)
			if (cp)
				cp = cp->next;
			else
				break;
		LOG_ERROR("  CKPTs waiting     : %d", i);
		LOG_ERROR("  Working list:");
		dm_list_iterate_items_gen(rq, &entry->working_list, u.list)
			LOG_ERROR("  %s/%u", _RQ_TYPE(rq->u_rq.request_type),
				  rq->u_rq.seq);

		LOG_ERROR("  Startup list:");
		dm_list_iterate_items_gen(rq, &entry->startup_list, u.list)
			LOG_ERROR("  %s/%u", _RQ_TYPE(rq->u_rq.request_type),
				  rq->u_rq.seq);

		LOG_ERROR("Command History:");
		for (i = 0; i < DEBUGGING_HISTORY; i++) {
			entry->idx++;
			entry->idx = entry->idx % DEBUGGING_HISTORY;
			if (entry->debugging[entry->idx][0] == '\0')
				continue;
			LOG_ERROR("%d:%d) %s", i, entry->idx,
				  entry->debugging[entry->idx]);
		}
	}
}
