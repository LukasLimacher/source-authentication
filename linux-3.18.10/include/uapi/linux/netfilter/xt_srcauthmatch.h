/*
 * Provides Source meta-information authentication when used in conjunction with corresponding db and match module.
 *
 * Written by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
 * Copyright (c) 2015 Open Systems AG, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 *
 */
#ifndef _XT_srcauthmatch_H
#define _XT_srcauthmatch_H 1

#include <linux/netfilter.h>
#include <linux/types.h>

enum {
    XT_SRCAUTH_NO_HEADER                = 1 << 0,
    XT_SRCAUTH_SESSION_PRESENT          = 1 << 1,
    XT_SRCAUTH_HAS_INFORMATION          = 1 << 2,
};

#define XT_SRCAUTH_MT_MAXMODE XT_SRCAUTH_HAS_INFORMATION


/* Only data relevant for match itself*/
struct xt_srcauth_match_info {
    /* Selected option */
    __u8 option;
    /* Invert current option - only for session-present XT_SRCAUTH_SESSION_PRESENT and no-header XT_SRCAUTH_NO_HEADER */
    __u8 invertSessionPresent;
    __u8 invertNoHeader;
    /* Meta Information Length in 32 bit words*/
    //__u8 MTL;//FUTURE WORK: make dynamic for more meta inf
    /* Meta_inf to set */
    __u32 new_meta_cmp[XT_SRCAUTH_MAXN];
};

#endif /* _XT_srcauthmatch_H */
