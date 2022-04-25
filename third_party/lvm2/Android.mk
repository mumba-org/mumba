LOCAL_PATH := $(call my-dir)

# Limit libdevmapper source files to minimum required by external/cryptsetup
libdm_src_files := libdm/libdm-common.c \
                   libdm/libdm-config.c \
                   libdm/libdm-deptree.c \
                   libdm/libdm-file.c \
                   libdm/libdm-report.c \
                   libdm/libdm-stats.c \
                   libdm/libdm-string.c \
                   libdm/libdm-timestamp.c \
                   libdm/datastruct/bitset.c \
                   libdm/datastruct/list.c \
                   libdm/ioctl/libdm-iface.c \
                   libdm/mm/dbg_malloc.c \
                   libdm/mm/pool.c

libdm_c_includes := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/libdm \
                    $(LOCAL_PATH)/libdm/ioctl \
                    $(LOCAL_PATH)/libdm/misc \
                    $(LOCAL_PATH)/lib/log \
                    $(LOCAL_PATH)/lib/misc

libdm_cflags := -Drindex=strrchr

include $(CLEAR_VARS)
LOCAL_MODULE := libdevmapper
LOCAL_CFLAGS := -O2 -g $(libdm_cflags)

LOCAL_SRC_FILES := $(libdm_src_files)

LOCAL_C_INCLUDES := $(libdm_c_includes)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/libdm

LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
