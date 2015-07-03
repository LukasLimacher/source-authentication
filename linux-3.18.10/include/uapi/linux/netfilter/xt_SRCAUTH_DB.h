/*
 * Provides Source meta-information authentication when used in conjunction with corresponding match and target module.
 *
 * Written by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
 * Copyright (c) 2015 Open Systems AG, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 *
 */
#ifndef _XT_SRCAUTH_DB_H
#define _XT_SRCAUTH_DB_H 1

#include <linux/netfilter.h>
#include <linux/types.h>
#include <linux/hashtable.h>

#include <linux/netfilter/xt_SRCAUTH.h>

#define XT_SRCAUTH_PROCFS_NAME "SRCAUTH_DB_proc"

/* At most PAGE_SIZE which is usually 4096 Bytes.
 * However, with 128 bit keys and n max = 15 we are safe even for 1024 Bytes. */
#define XT_SRCAUTH_PROCFS_WRITE_MAX 1024


struct xt_SRCAUTH_entry {
    /*Hash Table*/
    struct hlist_node hash_list;
    /* Key of Hash Table */
    // use field "__be32          ip;"
    //can extend to IPv6, for hash cast to (u32 *)
    //This is the id of the destination (OSPF router ID) within the source authentication scheme
    union nf_inet_addr dst_addr_key;

    struct xt_SRCAUTH_session session;
};

/* Map destination addresses to unique identifiers*/
struct xt_SRCAUTH_mapping {
    /*Hash Table*/
    struct hlist_node hash_list;
    
    union nf_inet_addr dst_addr_in_key;
    union nf_inet_addr dst_addr_id_out;
};

/* Map unique identifiers to destination addresses*/
// needed for detection of broken links
struct xt_SRCAUTH_routing {
    /*Hash Table*/
    struct hlist_node hash_list;
    
    union nf_inet_addr id_in_key;
    union nf_inet_addr dst_addr_out;
};

/* Exported Functions */
/**
 * xt_srcauth_entry - lookup entry in mapping and in final hash table, write to *session_entry
 * The do_copy flag set to 1 ensures that data is copied to the *session_entry. 
 * If it is set to 0 only true or false depending on whether an entry has been found is returned.
 * return value: 1 if success, 0 if no entry found.
 * Note: Does also update according to timeout: if timeout occured, then remove the entry etc
 */
bool xt_srcauth_lookup(union nf_inet_addr *dst_addr_in_key, struct xt_SRCAUTH_session *session_entry, bool do_copy);

/**
 * xt_srcauth_lookup_routing - lookup entry for unique destination identifier in routing and write to *addr
 * return value: 1 if success, 0 if no entry found.
 */
bool xt_srcauth_lookup_routing(union nf_inet_addr *id_in_key, union nf_inet_addr* addr);

/**
 * xt_srcauth_get_localkey - return locally stored key
 */
struct keys* xt_srcauth_get_localkey(void);

#endif /* _XT_SRCAUTH_DB_H */
