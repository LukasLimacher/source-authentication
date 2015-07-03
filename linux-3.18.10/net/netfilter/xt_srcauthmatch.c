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
/* Use this to enforce debug output or define config */
//#if 1
// #define DEBUG 1
//#endif
/* Format debug output */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/ip.h> /* ip_send_check */

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SRCAUTH.h>
#include <linux/netfilter/xt_srcauthmatch.h>
#include <linux/netfilter/xt_SRCAUTH_DB.h>

/* Load External Functions from DB module*/
/**
 * xt_srcauth_entry - lookup entry in mapping and in final hash table, write to *session_entry
 * The do_copy flag set to 1 ensures that data is copied to the *session_entry.
 * If it is set to 0 only true or false depending on whether an entry has been found is returned.
 * return value: 1 if success, 0 if no entry found.
 * Note: Does also update according to timeout: if timeout occured, then remove the entry etc
 */
extern bool xt_srcauth_lookup(union nf_inet_addr *dst_addr_in_key, struct xt_SRCAUTH_session *session_entry, bool do_copy);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lukas Limacher <lul@open.ch>");
MODULE_DESCRIPTION("Xtables: Source meta-information authentication match module");
MODULE_ALIAS("ipt_srcauthmatch");

static bool
srcauth_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_srcauth_match_info *info = par->matchinfo;
    struct iphdr *iph;
    struct xt_SRCAUTH_header *sah = NULL;
    struct xt_SRCAUTH_session* sessionp = NULL;//only passed
    unsigned int iph_size;
    __u32 meta_inf_tmp;
    int i;
    bool is_same = false;
    bool no_header = false;
    bool session_present = false;
#ifdef DEBUG
    char tmp[16];
#endif
    
    // Get ip header and calculate offset for sa header
    iph = ip_hdr(skb);
    iph_size = iph->ihl * 4;
    
    /* check if header present */
    no_header = (iph->protocol != XT_SRCAUTH_HEADER_ID);
    
    // Note: case ! no_header (alone) could be done more efficiently: just use -p 250
    
    if (!no_header) {
        sah = (struct xt_SRCAUTH_header *) (skb_network_header(skb)+iph_size);
    }
    // careful, can have a combination of options turned on
    switch (info->option) {
            /* Exclusive option HAS_INFORMATION!*/
        case XT_SRCAUTH_HAS_INFORMATION:
            /* If no header, then no valid meta info */
            if (no_header)
                return false;
            // check information in the header, note does not verify the information yet
            is_same = true;
            pr_devel("srcauth_HAS_INFORMATION: Compare meta information with MTL %u\n", sah->MTL);
            for (i = 0; i < sah->MTL && i < XT_SRCAUTH_MAXN; i++) {
                pr_devel("srcauth_HAS_INFORMATION: Compare meta information at %u\n", i);
                // dont forget to convert the network byte ordering
                meta_inf_tmp = ntohl(sah->meta_inf[i]);
                if (memcmp(&info->new_meta_cmp[i], &meta_inf_tmp, sizeof(sah->meta_inf[0])) != 0) {
                    is_same = false;
                }
            }
            return is_same;
            break;
    }
    
    
    //invert?
    no_header = (info->invertNoHeader) ? (! no_header) : no_header;
    
    /* following options can occure at the same time */
    if (info->option & XT_SRCAUTH_NO_HEADER) {
        // match on custom iph protocol number
        // If no_header is false, we do not need to check session_present anyway since AND
        // more efficient since no lookup then
        // DEBUG, FUTURE WORK: Use rate limited debug output
        // pr_devel("srcauth_NO_HEADER: check if IP header protocol field (not) set to scheme header\n");
        if (!no_header)
            return false;
    }
    if (info->option & XT_SRCAUTH_SESSION_PRESENT) {
        // NB if NO_HEADER also called it is true here
        // Do lookup to check if information present and delete if not
#ifdef DEBUG
        snprintf(tmp, 16, "%pI4", &iph->daddr);
        pr_devel("srcauth_SESSION_PRESENT: check if session present for daddr %s\n", tmp);
#endif
        session_present = xt_srcauth_lookup( (union nf_inet_addr *)&iph->daddr, sessionp, false);
#ifdef DEBUG
        if (!session_present) {
            pr_devel("srcauth_SESSION_PRESENT: did not receive an entry, please run session setup\n");
        }
#endif
        /* Invert (cf function table) */
        if (session_present == info->invertSessionPresent) {
            //case return false
            return false;
        }
        else {
            //case return true
            return true;
        }
    }

    //case no-header true
    return no_header;
}

static int srcauth_mt_check(const struct xt_mtchk_param *par)
{
    const struct xt_srcauth_match_info *info = par->matchinfo;

    if (info->option > XT_SRCAUTH_MT_MAXMODE) {
        pr_info("srcauth: unknown option %u note: has-information is exclusive option!\n", info->option);
        return -EINVAL;
     }
    
    return 0;
}

static struct xt_match srcauth_mt_reg[] __read_mostly = {
    {
        .name		= "srcauthmatch",
        .family		= NFPROTO_IPV4,
        .checkentry = srcauth_mt_check,
        .match		= srcauth_mt,
        .matchsize	= sizeof(struct xt_srcauth_match_info),
        .revision   = 0,
        .me         = THIS_MODULE,
    },
    /*Add IPV6 Support here*/
};

static int __init srcauth_mt_init(void)
{
    return xt_register_matches(srcauth_mt_reg, ARRAY_SIZE(srcauth_mt_reg));
}

static void __exit srcauth_mt_exit(void)
{
    xt_unregister_matches(srcauth_mt_reg, ARRAY_SIZE(srcauth_mt_reg));
}

module_init(srcauth_mt_init);
module_exit(srcauth_mt_exit);

