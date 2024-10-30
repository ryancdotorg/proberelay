#pragma once

#include "common.h"

#define RT_TSFT                          0
#define RT_FLAGS                         1
#define RT_RATE                          2
#define RT_CHANNEL                       3
#define RT_FHSS                          4
#define RT_DBM_SIGNAL                    5
#define RT_DBM_NOISE                     6
#define RT_LOCK_QUALITY                  7
#define RT_TX_ATTENUATION                8
#define RT_DB_TX_ATTENUATION             9
#define RT_DBM_TX_POWER                 10
#define RT_ANTENNA                      11
#define RT_DB_SIGNAL                    12
#define RT_DB_NOISE                     13
#define RT_RX_FLAGS                     14
#define RT_TX_FLAGS                     15
#define RT_RTS_RETRIES                  16
#define RT_DATA_RETRIES                 17
#define RT_XCHANNEL                     18
#define RT_MCS                          19
#define RT_A_MPDU_STATUS                20
#define RT_VHT                          21
#define RT_TIMESTAMP                    22
#define RT_HE                           23
#define RT_HE_MU                        24
#define RT_HE_MU_OTHER_USER             25
#define RT_ZERO_LENGTH_PSDU             26
#define RT_L_SIG                        27

#define RT_TSFT_PARAMS                   0,  8, 8
#define RT_FLAGS_PARAMS                  1,  1, 1
#define RT_RATE_PARAMS                   2,  1, 1
#define RT_CHANNEL_PARAMS                3,  4, 2
#define RT_FHSS_PARAMS                   4,  2, 1
#define RT_DBM_SIGNAL_PARAMS             5,  1, 1
#define RT_DBM_NOISE_PARAMS              6,  1, 1
#define RT_LOCK_QUALITY_PARAMS           7,  2, 2
#define RT_TX_ATTENUATION_PARAMS         8,  2, 2
#define RT_DB_TX_ATTENUATION_PARAMS      9,  2, 2
#define RT_DBM_TX_POWER_PARAMS          10,  1, 1
#define RT_ANTENNA_PARAMS               11,  1, 1
#define RT_DB_SIGNAL_PARAMS             12,  1, 1
#define RT_DB_NOISE_PARAMS              13,  1, 1
#define RT_RX_FLAGS_PARAMS              14,  2, 2
#define RT_TX_FLAGS_PARAMS              15,  2, 2
#define RT_RTS_RETRIES_PARAMS           16,  1, 1
#define RT_DATA_RETRIES_PARAMS          17,  1, 1
#define RT_XCHANNEL_PARAMS              18,  8, 4
#define RT_MCS_PARAMS                   19,  3, 1
#define RT_A_MPDU_STATUS_PARAMS         20,  8, 4
#define RT_VHT_PARAMS                   21, 12, 2
#define RT_TIMESTAMP_PARAMS             22, 12, 8
#define RT_HE_PARAMS                    23, 12, 2
#define RT_HE_MU_PARAMS                 24, 12, 2
#define RT_HE_MU_OTHER_USER_PARAMS      25,  6, 2
#define RT_ZERO_LENGTH_PSDU_PARAMS      26,  6, 2
#define RT_L_SIG_PARAMS                 27,  4, 2

int calc_filter(struct capture_s *, const uint8_t *, size_t);
int get_channel(struct capture_s *, const uint8_t *);
int get_signal(struct capture_s *, const uint8_t *);
