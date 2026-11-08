// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#if defined(TT_RELEASE_NO_LOGS)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#define TT_ANDROID_LOG_PRINT(...) ((void)0)
#define TT_ANDROID_LOG_WRITE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define TT_ANDROID_LOG_PRINT(...) __android_log_print(__VA_ARGS__)
#define TT_ANDROID_LOG_WRITE(...) __android_log_write(__VA_ARGS__)
#endif
