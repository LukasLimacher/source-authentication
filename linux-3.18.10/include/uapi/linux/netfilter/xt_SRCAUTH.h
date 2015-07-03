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
#ifndef _XT_SRCAUTH_H
#define _XT_SRCAUTH_H 1

#include <linux/netfilter.h>
#include <linux/types.h>

enum {
    XT_SRCAUTH_SET    = 1 << 0,
    XT_SRCAUTH_UPDATE = 1 << 1,
    XT_SRCAUTH_REMOVE = 1 << 2
};

/* parameters for the scheme */
#define XT_SRCAUTH_MAXMODE XT_SRCAUTH_REMOVE

#define XT_SRCAUTH_MAXN 15

#define XT_SRCAUTH_HASH_LEN 6//16 bit words

#define XT_SRCAUTH_DATAHASH_LEN_BYTES 12//8 bits each

#define XT_SRCAUTH_SESSIONID_LEN_BYTES 12//8 bits each

#define XT_SRCAUTH_KEY_LEN 4//32 bit words //at least 16 bytes

#define XT_SRCAUTH_SESSION_TIMEOUT 300//timeout in seconds, default 300

#define XT_SRCAUTH_TIMEOUT_DELTA 10//delta in seconds when lookups w/o copy return false, i.e., when session should be renewed

#define XT_SRCAUTH_HEADER_ID 0xFA //use number 250

/* other parameters */
#define XT_SRCAUTH_SHA1_LENGTH 20
#define XT_SRCAUTH_AES_LENGTH 16
#define XT_SRCAUTH_AES_IV 0x00000000000000000000000000000000 //128 bits iv 0 for cbc-mac baed on aes

/* Hash Table Sizes */
/* number represents bits to use, size is then power-of-2. */
/* Careful with big values */
#define XT_SRCAUTH_HT_ENTRIES_SIZE  8 //Increase if many destination ids for scheme
#define XT_SRCAUTH_HT_MAPPINGS_SIZE 8 //Increase if many destinations for scheme
#define XT_SRCAUTH_HT_ROUTINGS_SIZE 8 //Increase if many neighbours


/* Only data relevant for target itself, database seperately */
struct xt_SRCAUTH_info {
    /* Selected option */
    __u8 option;
    /* Meta Information Length in 32 bit words*/
//    __u8 MTL;//FUTURE WORK: make dynamic for more meta inf
    /* Meta_inf to set */
    __u32 new_meta_inf[XT_SRCAUTH_MAXN];
};

/* Session information received from DB module*/
struct keys {
    __u32 key[XT_SRCAUTH_KEY_LEN];
};

struct xt_SRCAUTH_session {
    __u8 n;
    
    //use signed 64 bit int for timestamp
    __s64 timestamp;
    
    __u16 sessionid[XT_SRCAUTH_HASH_LEN];
    __u16 indicators[XT_SRCAUTH_MAXN];//n * 16 bits
    __be32 identifiers[XT_SRCAUTH_MAXN];// n * 32bits
    
    /* n-1 keys (all but source) */
    struct keys keys[(XT_SRCAUTH_MAXN-1)];
};

/* Source Authentication Header. Use zero length arrays for dynamic size */
struct verification {
    __u16 value;
    __u16 indicator;
};

struct xt_SRCAUTH_header {
    __u8 protocol;
    __u8 MTL;//meta_inf length in 32 bit words (4 bits)
    __u8 position;//Position pointer
    __u8 n;//number of path set entities
    __u16 data_hash[XT_SRCAUTH_HASH_LEN];
    __u16 sessionid[XT_SRCAUTH_HASH_LEN];
    
    /* Original Destination, needed for own routing with custom table w/o changing normal routing */
    __be32 dst_addr_orig;
    
    /* MTL * 32 bits */
    __u32 meta_inf[0];
    
    /* n * 32 bits*/
    struct verification verification[0];
    
    /* n * 32bits ipv4 addresses length*/
    __be32 identifiers[0];
};

#endif /* _XT_SRCAUTH_H */
