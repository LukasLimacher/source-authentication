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
/* Use this to enforce debug output or define config */
//#if 1
// #define DEBUG 1
//#endif
/* Format debug output */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/time.h>

// DEBUG for in_aton
#ifdef DEBUG
#include <linux/inet.h>
#endif

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>

#include <linux/netfilter/xt_SRCAUTH.h>
#include <linux/netfilter/xt_SRCAUTH_DB.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lukas Limacher <lul@open.ch>");
MODULE_DESCRIPTION("Xtables SRCAUTH helper: Manages database for Source meta-information authentication");
MODULE_ALIAS("ipt_SRCAUTH_DB");

static DEFINE_HASHTABLE(xt_SRCAUTH_HT_entries, XT_SRCAUTH_HT_ENTRIES_SIZE);
static DEFINE_HASHTABLE(xt_SRCAUTH_HT_mappings, XT_SRCAUTH_HT_MAPPINGS_SIZE);
static DEFINE_HASHTABLE(xt_SRCAUTH_HT_routing, XT_SRCAUTH_HT_ROUTINGS_SIZE);

static DEFINE_SPINLOCK(srcauth_lock);

struct keys localkey;

/* Internal static Functions Prototypes*/
/* ------------------------- */
/**
 * xt_srcauth_lookup_mapping -  mapping hash table, set pointer id_out if entry found,
 * return value: 1 if success, 0 if no entry found.
 * Note: get spinlock before
 */
static bool xt_srcauth_lookup_mapping(union nf_inet_addr *dst_addr_in_key, union nf_inet_addr **id_out);

/**
 * xt_srcauth_add_entry - add new entry table with the (mapped) destination identifier key.
 * Will not replace current entries but append them in current hashtable bucket
 * Returns true if successful.
 */
static bool xt_srcauth_add_entry(union nf_inet_addr *dst_addr_in_key, struct xt_SRCAUTH_session *session_in);

/**
 * xt_srcauth_add_mapping - add new mapping.
 * Will also replace a mapping.
 * Returns true if successful.
 */
static bool xt_srcauth_add_mapping(const union nf_inet_addr *in_key,
                                   const union nf_inet_addr *id_out);

/**
 * xt_srcauth_add_routing - add new routing entry.
 * Will also replace a routing entry.
 * Returns true if successful.
 */
static bool xt_srcauth_add_routing(const union nf_inet_addr *in_key,
                                   const union nf_inet_addr *addr_out);

/**
 * xt_srcauth_remove_mapping - internal function to remove an entry from table, e.g. if timeout done.
 */
static bool xt_srcauth_remove_mapping(union nf_inet_addr *dst_addr_in_key);

/**
 * xt_srcauth_remove - internal function to remove an entry from table, e.g. if timeout done.
 */
static bool xt_srcauth_remove_entry(union nf_inet_addr *dst_addr_key);

/**
 * flush_entries_hashtable - remove all entries from hashtable and kfree memory
 */
static void flush_entries_hashtable(void);

/**
 * flush_routing_hashtable - remove all entries from hashtable and kfree memory
 */
static void flush_routing_hashtable(void);

/**
 * flush_mappings_hashtable - remove all entries from hashtable and kfree memory
 */
static void flush_mappings_hashtable(void);

/* Exported Functions */
/* ------------------ */
/* Important: Designed for save and efficient lookups.
 * For this to work, only this function can call remove, such that we never copy invalid memory.
 * In addition, it is critical that new session informaion is appended in the hashtbale bucket
 * and the old one is deleted when timedout in the next lookup 
 * In particular, it relies on the fact that the entry table is not flashed from outside
 */
bool xt_srcauth_lookup(union nf_inet_addr *dst_addr_in_key, struct xt_SRCAUTH_session *session_entry, bool do_copy)
{
    struct xt_SRCAUTH_entry *tmpep;
    union nf_inet_addr *currentmp;
    struct hlist_node *tmpnodep;
    struct timespec ts;
    unsigned int delta;
#ifdef DEBUG
    char tmp[16];
#endif
    
    //Lookup mapping
    if (!xt_srcauth_lookup_mapping(dst_addr_in_key, &currentmp)) {
#ifdef DEBUG
        snprintf(tmp, 16, "%pI4", &dst_addr_in_key->ip);
        pr_devel("No Mapping found for entry %s, using original destination\n", tmp);
#endif
        currentmp = dst_addr_in_key;
    }
    

    // FUTURE WORK: Could make query faster with locks only at removing at the cost of rarely
    // giving back the wrong information if information is freed and overwritten
    /* Get Lock make to make it safe for all queries*/
    spin_lock_bh(&srcauth_lock);
    hash_for_each_possible_safe(xt_SRCAUTH_HT_entries, tmpep, tmpnodep,
                                hash_list, (__force u32) currentmp->ip) {
        //check if really this entry
        //here only ipv4, i.e., ip field, for ipv6 use all fields, make sure values initialized!
        if (memcmp(&tmpep->dst_addr_key.ip, &currentmp->ip, sizeof(tmpep->dst_addr_key.ip)) == 0) {
            //check if timestamp in range
            getnstimeofday(&ts);
            delta = (do_copy) ? 0 : XT_SRCAUTH_TIMEOUT_DELTA;
            pr_devel("timestamp in kernel %lld and in session %lld, delta is %u\n", ts.tv_sec, tmpep->session.timestamp, delta);
            if ( (tmpep->session.timestamp + (__s64) XT_SRCAUTH_SESSION_TIMEOUT )>= ((__s64) ts.tv_sec + (__s64) delta) ) {
                pr_devel("timestamp valid\n");
                // Copy session to user to prevent problems if it is later deleted
                // provide flag for match only!
                
                if (do_copy) {
                    memcpy(session_entry, &tmpep->session, sizeof(*session_entry));
                }
                
                /* Release Lock */
                spin_unlock_bh(&srcauth_lock);
                return true;
            }
            // make sure new session made before timeout
            else {
                //timeout: delete session and mapping
                pr_devel("timestamp timed out, delete session and mapping entry!\n");

                //lock aquired before
                xt_srcauth_remove_mapping(dst_addr_in_key);
                xt_srcauth_remove_entry(&tmpep->dst_addr_key);

            }
        }
    }
    
    /* Release Lock */
    spin_unlock_bh(&srcauth_lock);
#ifdef DEBUG
    snprintf(tmp, 16, "%pI4", &currentmp->ip);
    pr_devel("No entry found for %s in entries table\n", tmp);
#endif
    return false;
}
EXPORT_SYMBOL(xt_srcauth_lookup);

bool xt_srcauth_lookup_routing(union nf_inet_addr *id_in_key, union nf_inet_addr* addr)
{
    struct xt_SRCAUTH_routing *tmprp;
#ifdef DEBUG
    char tmp[16];
    char tmp2[16];
#endif
    
    // Note: In simplified setting, we have mapping 1 to 1, only reason to use is the adaptive routing detection
    
    /* Get lock before search and copy */
    spin_lock_bh(&srcauth_lock);
    // since we have the lock and do not remove, we can use the faster non _safe version
    hash_for_each_possible(xt_SRCAUTH_HT_routing, tmprp,
                                hash_list, (__force u32) id_in_key->ip) {
        //check if really this entry
        //here only ipv4, i.e., ip field, for ipv6 use all fields, make sure values initialized!
        if (memcmp(&tmprp->id_in_key.ip, &id_in_key->ip, sizeof(tmprp->id_in_key.ip)) == 0) {

#ifdef DEBUG
            snprintf(tmp, 16, "%pI4", &tmprp->id_in_key.ip);
            snprintf(tmp2, 16, "%pI4", &tmprp->dst_addr_out.ip);
            pr_devel("Routing found entry id to adr: %s -> %s\n", tmp, tmp2);
#endif
            // Copy addr to user to prevent if it is shortly later deleted, NB here only for IPv4 at the moment
            memcpy(&addr->ip, &tmprp->dst_addr_out.ip, sizeof(addr->ip));
            /* Release Lock */
            spin_unlock_bh(&srcauth_lock);
            return true;
        }
    }
    /* Release Lock */
    spin_unlock_bh(&srcauth_lock);
    
#ifdef DEBUG
    snprintf(tmp, 16, "%pI4", &id_in_key->ip);
    pr_devel("Could not find routing entry for id %s\n", tmp);
#endif

    return false;
}
EXPORT_SYMBOL(xt_srcauth_lookup_routing);

struct keys* xt_srcauth_get_localkey(void)
{
    return &localkey;
}
EXPORT_SYMBOL(xt_srcauth_get_localkey);


/* Internal static Functions */
/* ------------------------- */

//make sure entries only removed in xt_srcauth_lookup!, copies pointer to *id_out
static bool xt_srcauth_lookup_mapping(union nf_inet_addr *dst_addr_in_key, union nf_inet_addr **id_out)
{
    struct xt_SRCAUTH_mapping *tmpmp;
#ifdef DEBUG
    char tmp[16];
    char tmp2[16];
#endif
    
    //lookup mapping to *dst_addr_in_key
    hash_for_each_possible(xt_SRCAUTH_HT_mappings, tmpmp,
                                hash_list, (__force u32) dst_addr_in_key->ip) {
        //check if really this entry
        //here only ipv4, i.e., ip field, for ipv6 use all fields, make sure values initialized!
        if (memcmp(&tmpmp->dst_addr_in_key.ip, &dst_addr_in_key->ip, sizeof(tmpmp->dst_addr_in_key.ip)) == 0) {
#ifdef DEBUG
            snprintf(tmp, 16, "%pI4", &tmpmp->dst_addr_in_key.ip);
            snprintf(tmp2, 16, "%pI4", &tmpmp->dst_addr_id_out.ip);
            pr_devel("Mapping entry found from addr to id: %s -> %s\n", tmp, tmp2);
#endif
            //assign to pointer
            *id_out = &tmpmp->dst_addr_id_out;
            return true;
        }
    }
    //debug
#ifdef DEBUG
    snprintf(tmp, 16, "%pI4", &dst_addr_in_key->ip);
    pr_devel("No mapping found for %s\n", tmp);
#endif
    
    return false;
}

static bool xt_srcauth_add_entry(union nf_inet_addr *dst_addr_in_key,
                                 struct xt_SRCAUTH_session *session_in)
{
    //Note spinlock must be used before call
    struct xt_SRCAUTH_entry *e;
    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (e == NULL)
        return false;
    
    memcpy(&e->dst_addr_key, dst_addr_in_key, sizeof(e->dst_addr_key));
    memcpy(&e->session, session_in, sizeof(e->session));
    
    hash_add(xt_SRCAUTH_HT_entries, &e->hash_list,
             (__force u32) e->dst_addr_key.ip);
    
    return true;
}

static bool
xt_srcauth_add_mapping(const union nf_inet_addr *in_key,
                     const union nf_inet_addr *id_out)
{
    //Note spinlock must be used before call
    struct xt_SRCAUTH_mapping *m;
    m = kmalloc(sizeof(*m), GFP_ATOMIC);
    if (m == NULL)
        return false;
    
    memcpy(&m->dst_addr_in_key, in_key, sizeof(m->dst_addr_in_key));
    memcpy(&m->dst_addr_id_out, id_out, sizeof(m->dst_addr_id_out));
    
    hash_add(xt_SRCAUTH_HT_mappings, &m->hash_list,
             (__force u32) m->dst_addr_in_key.ip);
    
    return true;
}

static bool xt_srcauth_add_routing(const union nf_inet_addr *in_key,
                                   const union nf_inet_addr *addr_out)
{
    //Note spinlock must be used before call
    struct xt_SRCAUTH_routing *r;
    r = kmalloc(sizeof(*r), GFP_ATOMIC);
    if (r == NULL)
        return false;

    memcpy(&r->id_in_key, in_key, sizeof(r->id_in_key));
    memcpy(&r->dst_addr_out, addr_out, sizeof(r->dst_addr_out));
    
    hash_add(xt_SRCAUTH_HT_routing, &r->hash_list,
             (__force u32) r->id_in_key.ip);
    
    return true;
}

//only delete one entry
static bool xt_srcauth_remove_mapping(union nf_inet_addr *dst_addr_in_key)
{
    // NOTE: spinlock before call needed
    struct xt_SRCAUTH_mapping *tmpmp;
#ifdef DEBUG
    char tmp[16];
#endif
    // lookup mapping to dst_addr_in_key, simplified setting mapping 1 to 1
    // only delete one, do not need to use _safe
    hash_for_each_possible(xt_SRCAUTH_HT_mappings, tmpmp,
                           hash_list, (__force u32) dst_addr_in_key->ip) {
        // here only ipv4, i.e., ip field, for ipv6 use all fields, make sure values initialized!
        if (memcmp(&tmpmp->dst_addr_in_key.ip, &dst_addr_in_key->ip, sizeof(tmpmp->dst_addr_in_key.ip)) == 0) {
#ifdef DEBUG
            snprintf(tmp, 16, "%pI4", &tmpmp->dst_addr_in_key.ip);
            pr_devel("Deleting mapping entry %s\n", tmp);
#endif
            hash_del(&tmpmp->hash_list);
            kfree(tmpmp);
            //only delete the first entry!
            return true;
        }
    }
#ifdef DEBUG
    snprintf(tmp, 16, "%pI4", &dst_addr_in_key->ip);
    pr_devel("Could not delete mapping entry %s\n", tmp);
#endif
    return false;
}

//only delete one entry
static bool xt_srcauth_remove_entry(union nf_inet_addr *dst_addr_key)
{
    // NOTE: spinlock before call needed
    struct xt_SRCAUTH_entry *tmpep;
#ifdef DEBUG
    char tmp[16];
#endif
    // lookup mapping to dst_addr_in_key, simplified setting mapping 1 to 1
    // only delete one, do not need to use _safe
    hash_for_each_possible(xt_SRCAUTH_HT_entries, tmpep,
                                hash_list, (__force u32) dst_addr_key->ip) {
        // here only ipv4, i.e., ip field, for ipv6 use all fields, make sure values initialized!
        if (memcmp(&tmpep->dst_addr_key.ip, &dst_addr_key->ip, sizeof(tmpep->dst_addr_key.ip)) == 0) {
#ifdef DEBUG
            snprintf(tmp, 16, "%pI4", &tmpep->dst_addr_key.ip);
            pr_devel("Deleting session entry %s\n", tmp);
#endif
            hash_del(&tmpep->hash_list);
            kfree(tmpep);
            //only delete the first entry!
            return true;
        }
    }
#ifdef DEBUG
    snprintf(tmp, 16, "%pI4", &dst_addr_key->ip);
    pr_devel("Could not delete session entry %s\n", tmp);
#endif
    return false;
}

static void flush_entries_hashtable(void) {
    int bkt;
    struct xt_SRCAUTH_entry *tmpep;
    struct hlist_node *tmpnodep;
    
    hash_for_each_safe(xt_SRCAUTH_HT_entries, bkt, tmpnodep, tmpep, hash_list){
        hash_del(&tmpep->hash_list);
        kfree(tmpep);
    }
}

static void flush_routing_hashtable(void) {
    int bkt;
    struct xt_SRCAUTH_routing *tmprp;
    struct hlist_node *tmpnodep;
    
    hash_for_each_safe(xt_SRCAUTH_HT_routing, bkt, tmpnodep, tmprp, hash_list){
        hash_del(&tmprp->hash_list);
        kfree(tmprp);
    }
}

static void flush_mappings_hashtable(void) {
    int bkt;
    struct xt_SRCAUTH_mapping *tmpmp;
    struct hlist_node *tmpnodep;
    
    hash_for_each_safe(xt_SRCAUTH_HT_mappings, bkt, tmpnodep, tmpmp, hash_list){
        hash_del(&tmpmp->hash_list);
        kfree(tmpmp);
    }
}

static ssize_t srcauth_proc_write(struct file *file, const char __user *input,
                                  size_t size, loff_t *loff)
{
    char buf[XT_SRCAUTH_PROCFS_WRITE_MAX];
    const char *cur = buf;//can change cur but not buf
    bool succ = false;
    bool sess = false;
    bool mapp = false;
    bool rout = false;
    bool flush = false;
    bool flushAll = false;
    bool addlocalkey = false;
    
    struct xt_SRCAUTH_session *tmps;
    union nf_inet_addr *tmpaddrp;
    union nf_inet_addr *tmpaddrp2;
    struct keys *tmpkeyp;
    
    //DEBUG STUFF
#ifdef DEBUG
    __be32 debugaddr;
    struct xt_SRCAUTH_session tmpsession;
    char tmp[16];
    union nf_inet_addr tmpquery;
    union nf_inet_addr tmpout;
#endif
    
    if (size == 0)
        return 0;
    if (size <= 2) { //needed otherwise can crash with input '/'
        pr_info("Not supported input in procfs!\n");
        return -EINVAL;
    }
    if (size > sizeof(buf))
    {
        size = sizeof(buf);
        pr_info("Attempt of write bigger than procfs buffer!\n");
    }
    //DEBUG
    pr_devel("written size is %d!\n", size);
    
    if (copy_from_user(buf, input, size) != 0)
        return -EFAULT;

    // comment: *loff != 0 is allowed to write mapping and then session material
    
    /* INTERFACE TO PROCFS FROM USERSPACE, COMMAND CHARs */
    /* Case distinction depending on first char input */
    /* '/x'0x2F flush tables // = all /r = routing, /s = entries, /m = mappings */
    /* 'r' 0x72 add routing entry */
    /* 's' 0x73 add session enry */
    /* 'm' 0x6D add mapping entry */
    /* 'k'      add local key */
    /* 'd'      debug lookup */
    switch (*cur) {
            /* IMPORTANT: Flashing of entries is for DEBUG only (except routing entries)!
             * Not supposed to use when lookup in heavy use since entries could be deleted while copying etc.
             * Instead entries are deleted on the fly after timeout*/
        case '/': /* flush tables // = all /r = routing, /s = entries. */
            flush = true;
            break;
        case 'r': /* add routing entry */
            rout = true;
            break;
        case 's': /* add (session) entry */
            sess = true;
            break;
        case 'm': /* add mapping entry */
            mapp = true;
            break;
        case 'k': /* add local key */
            addlocalkey = true;
            break;
#ifdef DEBUG
        case 'd': /* debug lookup */
            debugaddr = in_aton("10.0.6.2"); //is BE
            tmpquery.ip = debugaddr;
            snprintf(tmp, 16, "%pI4", &debugaddr);
            pr_devel("Call entry lookup %s\n", tmp);
            
            if (!(xt_srcauth_lookup(&tmpquery, &tmpsession, true)) ) {
                pr_devel("No entry received!\n");
            }
            else {
                pr_devel("received entry with timestamp %lld!\n", tmpsession.timestamp);
            }
            
            debugaddr = in_aton("213.156.234.2"); //is BE
            tmpquery.ip = debugaddr;
            snprintf(tmp, 16, "%pI4", &debugaddr);
            pr_devel("Call routing lookup %s\n", tmp);
            
            if (!(xt_srcauth_lookup_routing(&tmpquery, &tmpout)) ) {
                pr_devel("No entry received!\n");
            }
            else {
                snprintf(tmp, 16, "%pI4", &tmpout.ip);
                pr_devel("received entry %s\n", tmp);
            }

            //make sure no error returned
            succ = true;
            
            break;
#endif
        default:
            pr_info("SRCAUTH_DB: Not supported input in procfs!\n");
            return -EINVAL;
    }
    
    /* Ignore first char */
    ++cur;
    pr_devel("Successfully parsed first char in procfs write!\n");
    
    /* Parse and add to internal data structure. Use lock*/
    ///////////////////////////////////////////////////////
    // Dont return without releasing lock!
    spin_lock_bh(&srcauth_lock);
    
    if(rout)
    {
        tmpaddrp = (union nf_inet_addr *) cur;
        tmpaddrp2 = (union nf_inet_addr *) (cur+sizeof(union nf_inet_addr));
        //add entry
        if (tmpaddrp != NULL && tmpaddrp2 != NULL)
            succ = xt_srcauth_add_routing(tmpaddrp,
                                          tmpaddrp2);
        else //usually != NULL FUTURE WORK: check size
            pr_info("Parsed routing was NULL!\n");
        
        pr_devel("In add routing!\n");
    }
    else if(mapp) {
        tmpaddrp = (union nf_inet_addr *) cur;
        tmpaddrp2 = (union nf_inet_addr *) (cur+sizeof(union nf_inet_addr));
        //add entry
        if (tmpaddrp != NULL && tmpaddrp2 != NULL)
            succ = xt_srcauth_add_mapping(tmpaddrp,
                                          tmpaddrp2);
        else //usually != NULL FUTURE WORK: check size
            pr_info("Parsed mapping was NULL!\n");
        
        pr_devel("In add mapping!\n");
    }
    else if(sess) {
        tmpaddrp = (union nf_inet_addr *) cur;
        tmps = (struct xt_SRCAUTH_session *) (cur+sizeof(union nf_inet_addr));
        //add entry
        if (tmps != NULL && tmpaddrp != NULL) {
            succ = xt_srcauth_add_entry(tmpaddrp, tmps);
        }
        else //usually != NULL FUTURE WORK: check size
            pr_info("Parsed entry was NULL!\n");

        pr_devel("In add entry!\n");
    }
    else if (flush) {
        // flush hash table: entries
        switch (*cur) {
            case '/': /* flush tables */ // // all /r routing, /s entries, /m mapping.
                flushAll = true;
                break;
            case 'r': /* delete routing entries */
                rout = true;
                break;
            case 's': /* delete (session) entries */
                sess = true;
                break;
            case 'm': /* delete mapping entries */
                mapp = true;
                break;
            default:
                pr_info("Not supported input in procfs!\n");
                flush = false;
        }
        // Entries Table
        if (flushAll || sess) {
            flush_entries_hashtable();
            pr_devel("Flushed entry table!\n");
        }
        // Routing Table
        if (flushAll || rout) {
            flush_routing_hashtable();
            pr_devel("Flushed routing table!\n");
        }
        // Mappings Table
        if (flushAll || mapp) {
            flush_mappings_hashtable();
            pr_devel("Flushed mappings table!\n");
        }
    }
    else if(addlocalkey) {
        if (size == sizeof(localkey)+1){//key length plus first char
            tmpkeyp = (struct keys *) cur;
            if(tmpkeyp != NULL) {
                memcpy(&localkey, tmpkeyp, sizeof(localkey));
                succ = true;
                pr_devel("Added local key!\n");
            }
            else {
                pr_info("Local key pointer was NULL!\n");
            }
        }
        else {
            pr_info("Wrong size in add local key!\n");
        }
        pr_devel("In add key!\n");
    }
    
    ///////////////////////////////////////////////////////
    /* unlock */
    spin_unlock_bh(&srcauth_lock);
    
    //report error if any
    if (!succ && !flush) {
        pr_info("Object could not be added!\n");
        return -EINVAL;
    }
    
    /* Update what we read */
    *loff += size;
    return size;
}

static int srcauth_proc_show(struct seq_file *m, void *v)
{
    int bkt;
    int i;
    struct xt_SRCAUTH_entry *tmpep;
    struct xt_SRCAUTH_routing *tmprp;
    struct xt_SRCAUTH_mapping *tmpmp;
    char source[16];
    char destination[16];
    struct hlist_node *tmpnodep;

    /* Show data, since we use pointers etc which could be 
     * removed in running system we use lock
     * This is save but slow - for DEBUG only like this */
    ///////////////////////////////////////////////////////
    // Dont return without releasing lock!
    spin_lock_bh(&srcauth_lock);
    
    seq_printf(m, "SRCAUTH_DB: printing local key:\n");
    seq_printf(m,"%08x%08x%08x%08x\n", localkey.key[0], localkey.key[1], localkey.key[2], localkey.key[3]);
    
    // Entries Table
    seq_printf(m, "SRCAUTH_DB: printing entries hashtable:\n");
    
    if (hash_empty(xt_SRCAUTH_HT_entries)) {
        seq_printf(m,"Entries hashtable empty\n");
    }
    else {
        hash_for_each_safe(xt_SRCAUTH_HT_entries, bkt, tmpnodep, tmpep, hash_list){
            //convert to readable ipv4 address
            snprintf(source, 16, "%pI4", &tmpep->dst_addr_key.ip);
            seq_printf(m," entry with id: %s, timestamp: %lld has path set entities:\n", source, tmpep->session.timestamp);
            for (i=0; i < XT_SRCAUTH_MAXN; i++) {
                if (tmpep->session.identifiers[i] != 0) {
                    snprintf(destination, 16, "%pI4", &tmpep->session.identifiers[i]);
                    seq_printf(m,"%s \n", destination);
                }
            }
            seq_printf(m,"and has keys: \n");
            for (i=0; i < (XT_SRCAUTH_MAXN-1) && i < (tmpep->session.n-1); i++) {
                    //assume 16 bytes aes keys
                    seq_printf(m,"%08x%08x%08x%08x\n", tmpep->session.keys[i].key[0], tmpep->session.keys[i].key[1], tmpep->session.keys[i].key[2], tmpep->session.keys[i].key[3]);
            }
            
            seq_printf(m,"and has sessionid: %04x%04x%04x%04x%04x%04x\n", tmpep->session.sessionid[0], tmpep->session.sessionid[1], tmpep->session.sessionid[2], tmpep->session.sessionid[3], tmpep->session.sessionid[4], tmpep->session.sessionid[5]);
            
            seq_printf(m,"and is in bucket %d\n", bkt);
        }
    }
    // Routing Table
    seq_printf(m, "SRCAUTH_DB: printing routing hashtable:\n");
    
    if (hash_empty(xt_SRCAUTH_HT_routing)) {
        seq_printf(m,"Routing hashtable empty\n");
    }
    else {
        hash_for_each_safe(xt_SRCAUTH_HT_routing, bkt, tmpnodep, tmprp, hash_list){
            //convert to readable ipv4 address
            snprintf(source, 16, "%pI4", &tmprp->id_in_key);
            snprintf(destination, 16, "%pI4", &tmprp->dst_addr_out);
            seq_printf(m,"ID: %s maps to %s and is in bucket %d\n", source, destination, bkt);
        }
    }
    // Mappings Table
    seq_printf(m, "SRCAUTH_DB: printing mappings hashtable:\n");
    
    if (hash_empty(xt_SRCAUTH_HT_mappings)) {
        seq_printf(m,"Mappings hashtable empty\n");
    }
    else {
        hash_for_each_safe(xt_SRCAUTH_HT_mappings, bkt, tmpnodep, tmpmp, hash_list){
            //convert to readable ipv4 address
            snprintf(source, 16, "%pI4", &tmpmp->dst_addr_in_key);
            snprintf(destination, 16, "%pI4", &tmpmp->dst_addr_id_out);
            seq_printf(m,"ID (original destination): %s maps to %s and is in bucket %d\n", source, destination, bkt);
        }
    }
    
    ///////////////////////////////////////////////////////
    /* unlock */
    spin_unlock_bh(&srcauth_lock);
    
    return 0;
}

static int srcauth_proc_open(struct inode *inode, struct  file *file)
{
    return single_open(file, srcauth_proc_show, NULL);
}

static const struct file_operations srcauth_fops = {
    .owner = THIS_MODULE,
    .open = srcauth_proc_open,
    .read = seq_read,
    .write = srcauth_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init xt_srcauth_init(void)
{
    struct proc_dir_entry *pde;
    int i;
    
    for (i=0; i<XT_SRCAUTH_KEY_LEN; i++) {
        localkey.key[i] = 0;
    }
    
    pde = proc_create(XT_SRCAUTH_PROCFS_NAME, 0644, NULL, &srcauth_fops);
    if (pde == NULL) {
        pr_err("SRCAUTH_DB: Could not create procfs file!\n");
        return -ENOMEM;
    }

    
    pr_devel("SRCAUTH_DB: Module successfully loaded!\n");
    
    return 0;
}

static void __exit xt_srcauth_exit(void)
{
    //remove all hash tables needed and entries.
    
    // Entries Table
    flush_entries_hashtable();
    pr_devel("Flushed entry table!\n");
    
    // Routing Table
    flush_routing_hashtable();
    pr_devel("Flushed routing table!\n");
    
    // Mappings Table
    flush_mappings_hashtable();
    pr_devel("Flushed mappings table!\n");
    
    pr_devel("SRCAUTH_DB: Module will be unloaded!\n");

    remove_proc_entry(XT_SRCAUTH_PROCFS_NAME, NULL);
}

module_init(xt_srcauth_init);
module_exit(xt_srcauth_exit);
