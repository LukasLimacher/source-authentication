/* Shared library add-on to iptables for the SRCAUTH target
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

enum {
    id_SRCAUTH_SET = 0,
    id_SRCAUTH_UPDATE,
    id_SRCAUTH_REMOVE,
    F_SRCAUTH_SET    = 1 << id_SRCAUTH_SET,
    F_SRCAUTH_UPDATE = 1 << id_SRCAUTH_UPDATE,
    F_SRCAUTH_REMOVE = 1 << id_SRCAUTH_REMOVE,
    F_ANY            = F_SRCAUTH_SET | F_SRCAUTH_UPDATE | F_SRCAUTH_REMOVE,
};

#define s struct xt_SRCAUTH_info
static const struct xt_option_entry SRCAUTH_opts[] = {
    // FUTURE WORK: extend to get more than 32 bits input meta inf
    {.name = "set-information", .type = XTTYPE_UINT32, .id = id_SRCAUTH_SET,
        .excl = F_ANY, .flags = XTOPT_PUT, XTOPT_POINTER(s, new_meta_inf[0])},
    {.name = "update-header", .type = XTTYPE_NONE, .id = id_SRCAUTH_UPDATE,
        .excl = F_ANY},
    {.name = "remove-header", .type = XTTYPE_NONE, .id = id_SRCAUTH_REMOVE,
        .excl = F_ANY},
    XTOPT_TABLEEND,
};
#undef s

static void SRCAUTH_help(void)
{
    printf(
           "SRCAUTH target options:\n"
           "  --set-information value   Set meta informaton to value\n"
           "  --update-header           Update header\n"
           "  --remove-header           Remove header\n");
}

static void SRCAUTH_parse(struct xt_option_call *cb)
{
    struct xt_SRCAUTH_info *info = cb->data;
    
    xtables_option_parse(cb);
    switch (cb->entry->id) {
        case id_SRCAUTH_SET:
            info->option = XT_SRCAUTH_SET;
            break;
        case id_SRCAUTH_UPDATE:
            info->option = XT_SRCAUTH_UPDATE;
            break;
        case id_SRCAUTH_REMOVE:
            info->option = XT_SRCAUTH_REMOVE;
            break;
    }
}

static void SRCAUTH_check(struct xt_fcheck_call *cb)
{
    if (!(cb->xflags & F_ANY))
        xtables_error(PARAMETER_PROBLEM,
                      "SRCAUTH: You must specify an action");
}

static void SRCAUTH_save(const void *ip, const struct xt_entry_target *target)
{
    const struct xt_SRCAUTH_info *info =
    (struct xt_SRCAUTH_info *) target->data;
    
    switch (info->option) {
        case XT_SRCAUTH_SET:
            printf(" --set-information %u", info->new_meta_inf[0]);
            break;
        case XT_SRCAUTH_UPDATE:
            printf(" --update-header");
            break;
        case XT_SRCAUTH_REMOVE:
            printf(" --remove-header");
            break;
    }

}

static void SRCAUTH_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
    const struct xt_SRCAUTH_info *info =
    (struct xt_SRCAUTH_info *) target->data;
    
    printf(" SRCAUTH:");
    switch (info->option) {
        case XT_SRCAUTH_SET:
            printf(" Set information %u", info->new_meta_inf[0]);
            break;
        case XT_SRCAUTH_UPDATE:
            printf(" Update header");
            break;
        case XT_SRCAUTH_REMOVE:
            printf(" Remove header");
            break;
    }
}

static struct xtables_target srcauth_tg_reg = {
    .name		= "SRCAUTH",
    .version	= XTABLES_VERSION,
    .family		= NFPROTO_IPV4,
    .size		= XT_ALIGN(sizeof(struct xt_SRCAUTH_info)),
    .userspacesize	= XT_ALIGN(sizeof(struct xt_SRCAUTH_info)),
    .help		= SRCAUTH_help,
    .print		= SRCAUTH_print,
    .save		= SRCAUTH_save,
    .x6_parse	= SRCAUTH_parse,
    .x6_fcheck	= SRCAUTH_check,
    .x6_options	= SRCAUTH_opts,
    .revision   = 0,
};

void _init(void)
{
    xtables_register_target(&srcauth_tg_reg);
}