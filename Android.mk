LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := init
LOCAL_SRC_FILES := init.c
include $(BUILD_EXECUTABLE)
