/* Shared library add-on to iptables for the SRCAUTH match.
 *
 * Written by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
 * Copyright (c) 2015 Open Systems AG, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */
#include "config.h"
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_SRCAUTH.h>
#include <linux/netfilter/xt_srcauthmatch.h>

enum {
    id_SRCAUTH_NO_HEADER = 0,
    id_SRCAUTH_SESSION_PRESENT,
    id_SRCAUTH_HAS_INFORMATION,
    F_SRCAUTH_NO_HEADER            = 1 << id_SRCAUTH_NO_HEADER,
    F_SRCAUTH_SESSION_PRESENT      = 1 << id_SRCAUTH_SESSION_PRESENT,
    F_SRCAUTH_HAS_INFORMATION      = 1 << id_SRCAUTH_HAS_INFORMATION,
    F_ANY                          = F_SRCAUTH_NO_HEADER | F_SRCAUTH_SESSION_PRESENT | F_SRCAUTH_HAS_INFORMATION,
    F_EXCLUSIVE                    = F_SRCAUTH_HAS_INFORMATION,
};

#define s struct xt_srcauth_match_info
static const struct xt_option_entry srcauth_match_opts[] = {
    // FUTURE WORK: extend to get more than 32 bits input meta inf
    {.name = "no-header", .type = XTTYPE_NONE,
        .id = id_SRCAUTH_NO_HEADER, .excl = F_EXCLUSIVE, .flags = XTOPT_INVERT},
    {.name = "session-present", .type = XTTYPE_NONE,
        .id = id_SRCAUTH_SESSION_PRESENT, .excl = F_EXCLUSIVE, .flags = XTOPT_INVERT},
    {.name = "has-information", .type = XTTYPE_UINT32,
        .id = id_SRCAUTH_HAS_INFORMATION, .excl = F_ANY,
        .flags = XTOPT_PUT, XTOPT_POINTER(s, new_meta_cmp[0])},
    XTOPT_TABLEEND,
};
#undef s

static void srcauth_match_help(void)
{
    printf(
           "srcauth match options:\n"
           "[!] --no-header               Matches if (! = not) no scheme header present\n"
           "[!] --session-present         Matches if a session (! = not) exists in DB\n"
           "    --has-information value   Matches if value is equal to meta information in the scheme header (exclusive option)\n");
}

static void srcauth_match_parse(struct xt_option_call *cb)
{
    struct xt_srcauth_match_info *info = cb->data;
    
    // for each option separately called
    xtables_option_parse(cb);
    switch (cb->entry->id) {
        case id_SRCAUTH_NO_HEADER:
            info->option |= XT_SRCAUTH_NO_HEADER;
            if (cb->invert)
                info->invertNoHeader = true;
            break;
            break;
        case id_SRCAUTH_SESSION_PRESENT:
            info->option |= XT_SRCAUTH_SESSION_PRESENT;
            if (cb->invert)
                info->invertSessionPresent = true;
            break;
        case id_SRCAUTH_HAS_INFORMATION:
            info->option = XT_SRCAUTH_HAS_INFORMATION;
            break;
    }
}

static void srcauth_match_check(struct xt_fcheck_call *cb)
{
    if (!(cb->xflags & F_ANY))
        xtables_error(PARAMETER_PROBLEM,
                      "srcauthmatch: You must specify an action");
}

static void srcauth_match_save(const void *ip,  const struct xt_entry_match *match)
{
    const struct xt_srcauth_match_info *info =
    (struct xt_srcauth_match_info *) match->data;
    
    switch (info->option) {
        case XT_SRCAUTH_HAS_INFORMATION:
            printf(" --has-information %u", info->new_meta_cmp[0]);
            break;
    }
    if (info->option & XT_SRCAUTH_NO_HEADER) {
        if (info->invertNoHeader)
            printf(" !");
        printf(" --no-header");
    }
    if (info->option & XT_SRCAUTH_SESSION_PRESENT) {
        if (info->invertSessionPresent)
            printf(" !");
        printf(" --session-present");
    }
}

static void srcauth_match_print(const void *ip, const struct xt_entry_match *match,
                                int numeric)
{
    const struct xt_srcauth_match_info *info =
    (struct xt_srcauth_match_info *) match->data;
    
    printf(" srcauth match:");
    switch (info->option) {
        case XT_SRCAUTH_HAS_INFORMATION:
            printf(" Has information %u", info->new_meta_cmp[0]);
            break;
    }
    if (info->option & XT_SRCAUTH_NO_HEADER) {
        if (info->invertNoHeader)
            printf(" !");
        printf(" No header");
    }
    if (info->option & XT_SRCAUTH_SESSION_PRESENT) {
        if (info->invertSessionPresent)
            printf(" !");
        printf(" Session present");
    }
}

static struct xtables_match srcauth_mt_reg = {
    .name		= "srcauthmatch",
    .version	= XTABLES_VERSION,
    .family		= NFPROTO_IPV4,
    .size		= XT_ALIGN(sizeof(struct xt_srcauth_match_info)),
    .userspacesize	= XT_ALIGN(sizeof(struct xt_srcauth_match_info)),
    .help		= srcauth_match_help,
    .print		= srcauth_match_print,
    .save		= srcauth_match_save,
    .x6_parse	= srcauth_match_parse,
    .x6_fcheck	= srcauth_match_check,
    .x6_options	= srcauth_match_opts,
    .revision   = 0,
};

void _init(void)
{
    xtables_register_match(&srcauth_mt_reg);
}