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
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SRCAUTH.h>
#include <linux/netfilter/xt_SRCAUTH_DB.h>

// Crypto Stuff
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

/* Load External Functions from DB module*/
/**
 * xt_srcauth_entry - lookup entry in mapping and in final hash table, write to *session_entry
 * The do_copy flag set to 1 ensures that data is copied to the *session_entry.
 * If it is set to 0 only true or false depending on whether an entry has been found is returned.
 * return value: 1 if success, 0 if no entry found.
 * Note: Does also update according to timeout: if timeout occured, then remove the entry etc
 */
extern bool xt_srcauth_lookup(union nf_inet_addr *dst_addr_in_key, struct xt_SRCAUTH_session *session_entry, bool do_copy);

/**
 * xt_srcauth_lookup_routing - lookup entry for unique destination identifier in routing and write to *addr
 * return value: 1 if success, 0 if no entry found.
 */
extern bool xt_srcauth_lookup_routing(union nf_inet_addr *id_in_key, union nf_inet_addr* addr);

/**
 * xt_srcauth_get_localkey - return locally stored key
 */
extern struct keys* xt_srcauth_get_localkey(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lukas Limacher <lul@open.ch>");
MODULE_DESCRIPTION("Xtables: Source meta-information authentication");
MODULE_ALIAS("ipt_SRCAUTH");

static bool srcauth_set_header(struct xt_SRCAUTH_header *sah,
                               const struct xt_SRCAUTH_info *info,
                               struct xt_SRCAUTH_session *session,
                               struct iphdr *iph, struct sk_buff *skb, unsigned int sah_size)
{
    // FUTURE WORK: optimize this function
    int i = 0;
    // data for hashing
    struct scatterlist sg;
    struct hash_desc desc;
    unsigned char output[XT_SRCAUTH_SHA1_LENGTH];
    unsigned int payload_length;
    // for aes
    unsigned char aesdst[XT_SRCAUTH_AES_LENGTH];
    struct crypto_cipher *aes;
    
    //Set first word
    sah->protocol = iph->protocol;
    pr_devel("SRCAUTH_SET save protocol %u\n", sah->protocol);
    sah->MTL = 1;//FUTURE WORK: make dynamic for more fields
    sah->position = 1;//next hop is 1 if possible (shortest path first in path set), adaptive routing lookup made later
    sah->n = session->n;
    
    /////////////////////////////////////////////////////
    /* Set everything except DataHash and Verification Values */
    // set meta inf and indicators in header,
    // init verification values with 0 and then hash from and including meta inf until end of linear data
    // DataHash DataHash = H(P|INDICATOR|MetaInf)
    for(i = 0; i < XT_SRCAUTH_HASH_LEN; i++)
    {
        //this to network byte ordering bug was the last one
        sah->sessionid[i] = htons(session->sessionid[i]);
    }
    
    
    //Original Destination Addr, is in network byte order
    sah->dst_addr_orig = iph->daddr;
    
    //Meta Inf
    for(i = 0; i < sah->MTL; i++)
    {
        sah->meta_inf[i] = htonl(info->new_meta_inf[i]);
    }
    
    for(i = 0; i < sah->n; i++)
    {
        //verification, offset is sah->MTL * 32bits
        sah->verification[sah->MTL + i].value = 0x0000;
        sah->verification[sah->MTL + i].indicator = htons(session->indicators[i]);//verification indicators
        //Debug
        pr_devel("Session has indicator %04x of entity %u\n", session->indicators[i], i);
        pr_devel("Set session indicator %04x of entity %u\n", sah->verification[sah->MTL + i].indicator, i);
        //identifiers aka path set, offset is (sah->n + sah->MTL) * 32bits
        sah->identifiers[(sah->n + sah->MTL) + i] = session->identifiers[i];//identifiers, already in network byte order
    }
    
    /////////////////////////////////////////////////////
    // DataHash = H(P|INDICATOR|MetaInf)
    
    pr_devel("DataHash sha1: \n");
    
    desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    
    if (IS_ERR(desc.tfm)) {
        pr_err("Error occured while allocating sha1 hash, missing module?");
        return false;
    }
    
    desc.flags = 0;
    
    // hash only linear data in skb
    // note: the amount of non-paged data at skb->data can be calculated as skb->len - skb->data_len.
    // future work: can extend to directly hash all paged data of skb! - Crypto API with scatterlists supports this
    // sg_set_buf(&sg[0], &pagetable1, length1);
    // sg_set_buf(&sg[1], &pagetable2, length2);
    // .. etc
    // sg_init_table(sg, ARRAY_SIZE(sg));
    // future work 2: use efficient mac for large data, like PMAC
    
    // Hash from from our header in skb from and including meta_inf[0] to the end of linear data
    // (offset is position of meta_inf in sa header)
    payload_length = skb_headlen(skb)-offsetof(struct xt_SRCAUTH_header, meta_inf[0]);
    pr_devel("Running sha1 on skb for length %u", payload_length);
    sg_init_one(&sg, &sah->meta_inf[0], payload_length); // same as (skb->data + offsetof(struct xt_SRCAUTH_header, meta_inf[0]))
    
    //Hash init, calc, copy
    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, payload_length);
    if (crypto_hash_final(&desc, output)) {
        pr_err("Error occured while hashing data hash!");
        return false;
    }
#ifdef DEBUG
    for (i = 0; i < 20; i++) {
        pr_devel("%d-%d\n", output[i], i);
    }
#endif
    
    //truncate hash and copy to header
    memcpy(&sah->data_hash[0], output, XT_SRCAUTH_DATAHASH_LEN_BYTES);
    
    // Free mem
    crypto_free_hash(desc.tfm);
    
    //Data hash to network byte ordering
    for(i = 0; i < XT_SRCAUTH_HASH_LEN; i++)
    {
        sah->data_hash[i] = htons(sah->data_hash[i]);
    }
    
    /////////////////////////////////////////////////////
    // calculate verification values V_j = MAC_K_j(DataHash), CBC-MAC based AES for each entity except source
    // one block size input for aes
    pr_devel("Calculate verification values with AES\n");
    //set padding of output datahash to 00 for bits not used
    memset(&output[XT_SRCAUTH_DATAHASH_LEN_BYTES], 0x00, XT_SRCAUTH_SHA1_LENGTH - XT_SRCAUTH_DATAHASH_LEN_BYTES);
    
    /* The kernel crypto API may provide multiple implementations of a template or a single block cipher. For example, AES on newer Intel hardware has the following implementations: AES-NI, assembler implementation, or straight C. Now, when using the string "aes" with the kernel crypto API, which cipher implementation is used? The answer to that question is the priority number assigned to each cipher implementation by the kernel crypto API. When a caller uses the string to refer to a cipher during initialization of a cipher handle, the kernel crypto API looks up all implementations providing an implementation with that name and selects the implementation with the highest priority. */
    // source: http://www.chronox.de/crypto-API/ch02s04.html
    // on physical machines, have either async cbc(aes) or sync cipher aes. As we only need to encrypt 1 block and have iv of 0, we use simple
    // aes for one single block! AESni used if provided by system.
    aes = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(aes)) {
        pr_err("Error occured while allocating AES module, missing module?");
        return false;
    }
    
    // calculate all V_j's (except for source)
    for(i = 0; i < (sah->n -1); i++) {
        if (crypto_cipher_setkey(aes, (const u8 *) &session->keys[i], 4*XT_SRCAUTH_KEY_LEN) ) {
            pr_err("Error occured while setting key for AES for entity %u!", (i+1));
            return false;
        }
        // encrypt 1 block
        crypto_cipher_encrypt_one(aes, aesdst, output);
        
        // copy truncated value (2 bytes); start at entity 1 (no value for source)
        memcpy(&sah->verification[sah->MTL + i + 1].value, aesdst, 2);
        
        // switch to network byte order
        sah->verification[sah->MTL + i + 1].value = htons(sah->verification[sah->MTL + i + 1].value);
    }
    
    crypto_free_cipher(aes);
    
    pr_devel("Successfully calculated all verification values");
    
    return true;
}

static unsigned int
srcauth_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *iph;
    struct iphdr *iph_new = NULL;
    __u16 old_tot_len, mask, indicator, comparevalue;
    __u16 checksumtmp = 0x0000;//disable compiler warning
    __u8 n, MTL, position, nextposition;
    __u8 old_protocol;
    struct xt_SRCAUTH_header *sah;
    unsigned int sah_size;
    unsigned int iph_size;
    //union nf_inet_addr *lookup;
    struct ethhdr *eth;
    struct ethhdr *eth_new = NULL;
    bool is_eth = false;
    bool pulled_eth = false;
    bool recalc_checksum = false;
    unsigned int old_headroom;
    __be32 nextid;
    int i = 0;
    // data for hashing
    struct scatterlist sg;
    struct hash_desc desc;
    unsigned char output[XT_SRCAUTH_SHA1_LENGTH];
    unsigned int payload_length;
    // for AES:
    unsigned char aesdst[XT_SRCAUTH_AES_LENGTH];
    struct crypto_cipher *aes;
    u8 derivedkey[XT_SRCAUTH_AES_LENGTH];
    __u16 sessionidtmp[XT_SRCAUTH_HASH_LEN];
    //to save checksums for datahash calculation
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    
    struct xt_SRCAUTH_session session;
#ifdef DEBUG
    char tmp[16];
#endif
    
    const struct xt_SRCAUTH_info *info = par->targinfo;
    
    
    /* Call this before modifying an existing packet: ensures it is
     * modifiable and linear to the point you care about (writable_len).
     * Returns true or false. */
    if (!skb_make_writable(skb, skb->len))
    {
        pr_err("Could not make skb writeable!\n");
        return NF_DROP;
    }
    pr_devel("SRCAUTH TARGET: Enter after skb make writeable!\n");
    
    iph = ip_hdr(skb);
    
    /* Get current protocol field */
    old_protocol = iph->protocol;
    old_tot_len = ntohs(iph->tot_len);
    iph_size = iph->ihl * 4;
    
    old_headroom = skb_headroom(skb);
    
    switch (info->option) {
     case XT_SRCAUTH_SET:
            
            /* Save old protocol field and change to our custom next header */
            //Note can filter ICMP packets and any other protocols if desired
            if(old_protocol != XT_SRCAUTH_HEADER_ID)
            {
                recalc_checksum = true;

                
                /* Inject scheme header */
                // http://stackoverflow.com/questions/10245281/using-sk-buff-to-add-an-ethernet-frame-header
                
                // Load session material
                //Get session for this original destination
                if (!xt_srcauth_lookup( (union nf_inet_addr *)&iph->daddr, &session, true)) {
                    pr_err("Did not receive an entry in target, this should not happen, check your iptables rules!\n");
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
                n = session.n;
                // FUTURE WORK: Extend to provide more meta inf
                //MTL = info->MTL;
                MTL = 1;
                
                pr_devel("SRCAUTH_SET headers before expand:\n");
                pr_devel("SRCAUTH_SET mac_header: %u\n", skb->mac_header);
                pr_devel("SRCAUTH_SET ip_header: %u\n", skb->network_header);
                pr_devel("SRCAUTH_SET transport_header: %u\n", skb->transport_header);
                
                pr_devel("SRCAUTH_SET csum at start: %u\n", skb->csum_start);
                
                sah_size = sizeof(*sah) + MTL*sizeof(sah->meta_inf[0])    +
                                          n*(sizeof(sah->verification[0]) +
                                             sizeof(sah->identifiers[0]));
                
                /* Check if space in packet */
                if (old_tot_len > (65535 - sah_size)) {
                    pr_err("SRCAUTH_SET no space in packet to add SRCAUTH header!\n");
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
                pr_devel("SRCAUTH_SET skb_headroom is: %u\n", skb_headroom(skb));
                pr_devel("SRCAUTH_SET sah_size is: %u\n", sah_size);
                
                //FUTURE WORK: check performance when headroom not reduced.
                if (skb_headroom(skb) < sah_size) {
                    /*Allocate more space*/
                    /*Note this offset is already added!*/
                    if (0 != pskb_expand_head(skb, sah_size - skb_headroom(skb),
                                              0, GFP_ATOMIC))
                    {
                        pr_err("SRCAUTH_SET could not increase skbuff!\n");
                        kfree_skb(skb);
                        return NF_STOLEN;
                    }
                    else
                    {
                        pr_devel("SRCAUTH_SET expanded skb headroom\n");
                    }
                }
                
                if (skb_is_nonlinear(skb)) {
                    pr_warn("SRCAUTH_SET SKB not linear which maches DataHash only over part of packet!\n");
                    // future work: extend to hash all paged data of skb!
                    //kfree_skb(skb);
                    //return NF_STOLEN;
                }

                pr_devel("SRCAUTH_SET headers after expand:\n");
                pr_devel("SRCAUTH_SET mac_header: %u\n", skb->mac_header);
                pr_devel("SRCAUTH_SET ip_header: %u\n", skb->network_header);
                pr_devel("SRCAUTH_SET transport_header: %u\n", skb->transport_header);
                
                //save and overwrite checksum for data hash computation
                if (old_protocol == 17) {
                    //UDP
                    udph = udp_hdr(skb);
                    checksumtmp = ntohs(udph->check);
                    udph->check = 0x0000;
                    pr_devel("SRCAUTH_SET overwrite udp checksum for data hash\n");
                }
                else if (old_protocol == 6) {
                    //TCP
                    tcph = tcp_hdr(skb);
                    checksumtmp = ntohs(tcph->check);
                    tcph->check = 0x0000;
                    pr_devel("SRCAUTH_SET overwrite tcp checksum for data hash\n");
                }
                
                
                /* link layer header */
                //For completeness also copy mac header
                switch (skb->dev->type) {
                    //ARPHRD_LOOPBACK
                    case 772:
                    //ARPHRD_ETHER
                    case 1:
                    {
                        pr_devel("SRCAUTH_SET ethernet device recognized\n");
                        if (skb_mac_header_was_set(skb))
                        {
                            eth = (struct ethhdr *) skb_mac_header(skb);
                            
                            eth_new = kmalloc(skb->mac_len, GFP_ATOMIC);
                            
                            if (eth_new == NULL)
                            {
                                pr_err("SRCAUTH_SET could not copy MAC header!\n");
                                kfree_skb(skb);
                                return NF_STOLEN;
                            }
                            
                            
                            memcpy(eth_new, eth, skb->mac_len);
                            is_eth = true;
                            
                            //Only if data pointer at mac header
                            if(old_headroom == skb->mac_header)
                            {
                                // Remove link layer
                                skb_pull(skb, skb->mac_len);
                                pulled_eth = true;
                            }
                            else
                            {
                                pr_devel("SRCAUTH_SET mac not pulled!\n");
                            }
                        }
                        else
                        {
                            pr_devel("SRCAUTH_SET ethernet mac not set!\n");
                        }
                        break;
                    }
                    default:
                        pr_devel("SRCAUTH_SET no ethernet header dev set\n");
                        break;
                };
                

                /* Store current IP header */
                iph_new = kmalloc(iph_size, GFP_ATOMIC);
                if (iph_new == NULL)
                {
                    pr_err("SRCAUTH_SET could not copy IP header!\n");
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
                memcpy(iph_new, iph, iph_size);
                
                /* Remove IP Header */
                pr_devel("SRCAUTH_SET remove old IP header\n");
                skb_pull(skb, iph_size);
                
                /* Add own header, NB: memory space ensured before */
                pr_devel("SRCAUTH_SET push scheme header\n");
                sah = (struct xt_SRCAUTH_header*) skb_push(skb, sah_size);
                
                
                /* Set own header */
                /* Use copied ip header! */
                if(!srcauth_set_header(sah, info, &session, iph_new, skb, sah_size) ) {
                    pr_err("SRCAUTH_SET sah header could not be set!\n");
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
                
                /* Update IP header length etc. and push back on skb */
                pr_devel("SRCAUTH_SET push and update IP header\n");
                
                /* Set new skb ip header pointer */
                iph = (struct iphdr*) skb_push(skb, iph_size);
                
                memcpy(iph, iph_new, iph_size);
                
                /* Set new skb ip header pointer */
                skb_reset_network_header(skb);
                iph = ip_hdr(skb);
                
                ////////////////////////////////////////////////////
                // Update header info
                /* update total length, check done above */
                iph->tot_len = htons(old_tot_len + sah_size);
                iph->protocol = XT_SRCAUTH_HEADER_ID;
                
                // set next hop for adaptive routing
                position = 0;//source node
                //init indicator, note the byte ordering!
                indicator = ntohs(sah->verification[MTL + position].indicator);
                // init mask
                mask = 0x000F;
                
                pr_devel("SRCAUTH_SET adaptive routing evaluation");
                // get next hop position from indicator
                // FUTURE WORK: Could be further optimized
                do {
                    nextposition = indicator & mask;
                    //never send back to source
                    if(indicator == 0 || nextposition == 0) {
                        //no valid position found
                        pr_err("Did not find any routing table entries! Dropping Packet");
                        return NF_DROP;
                    }
                    // get next hop id (n + MTL for offset)
                    nextid = sah->identifiers[(n + MTL) + nextposition];
#ifdef DEBUG
                    snprintf(tmp, 16, "%pI4", &nextid);
                    pr_devel("SRCAUTH_SET lookup nextip %s at current position %u\n", tmp, nextposition);
#endif
                    
                    //update indicator, move to next id
                    indicator = (indicator >> 4);
                    //now update daddr if there is an entry in kernel DB
                } while(!xt_srcauth_lookup_routing((union nf_inet_addr *) &nextid, (union nf_inet_addr *) &iph->daddr));
#ifdef DEBUG
                snprintf(tmp, 16, "%pI4", &iph->daddr);
                pr_devel("SRCAUTH_SET change "
                         "ip to next hop %s and update position to %u\n", tmp, nextposition);
#endif
                // update position for the next node
                sah->position = nextposition;
                
                ////////////////////////////////////////////////////
                // Restore rest of skb
                skb_set_transport_header(skb, iph_size + sah_size);
                
                //restore checksum from data hash computation
                if (old_protocol == 17) {
                    //UDP
                    udph = udp_hdr(skb);
                    udph->check = htons(checksumtmp);
                    pr_devel("SRCAUTH_SET restored udp checksum\n");

                }
                else if (old_protocol == 6) {
                    //TCP
                    tcph = tcp_hdr(skb);
                    tcph->check = htons(checksumtmp);
                    pr_devel("SRCAUTH_SET restored tcp checksum\n");
                }
                
                /* Link Layer */
                if(is_eth)
                {
                    pr_devel("SRCAUTH_SET restore mac header\n");
                    
                    //incrase headroom if needed!
                    if (skb_headroom(skb) < skb->mac_len) {
                        /*Allocate more space*/
                        /*Note this offset is already added!*/
                        if (0 != pskb_expand_head(skb, skb->mac_len - skb_headroom(skb),
                                                  0, GFP_ATOMIC))
                        {
                            pr_err("SRCAUTH_SET could not increase skbuff!\n");
                            kfree_skb(skb);
                            return NF_STOLEN;
                        }
                        else
                        {
                            pr_devel("SRCAUTH_SET expanded skb headroom\n");
                        }
                    }
                    
                    eth = (struct ethhdr*) skb_push(skb, skb->mac_len);
                    memcpy(eth, eth_new, skb->mac_len);
                    
                    skb_reset_mac_header(skb);
                    
                    //Restore previous pointer state and adapt correct length
                    if(!pulled_eth)
                    {
                        skb_pull(skb, skb->mac_len);
                    }
                }
                
                
                /* Checksum start relative to skb->head pointer */
                // Note: checksum starts at transport header, therefore we do not alter.
                pr_devel("SRCAUTH_SET let csum unchanged: %u\n", skb->csum_start);
                //pr_devel("SRCAUTH_SET csum start at: %u\n", skb->csum_start);
               
                
                pr_devel("SRCAUTH_SET headers after inject:\n");
                pr_devel("SRCAUTH_SET mac_header: %u\n", skb->mac_header);
                pr_devel("SRCAUTH_SET ip_header: %u\n", skb->network_header);
                pr_devel("SRCAUTH_SET transport_header: %u\n", skb->transport_header);
            }
            else
            {
                pr_info("SRCAUTH_SET failed, header already present!\n");
            }
            
            pr_devel("SRCAUTH_SET finished.\n");
     break;
     case XT_SRCAUTH_UPDATE:
            /* Update our header: update pointer use check --validate-information from match module*/
            
            pr_devel("SRCAUTH_UPDATE mac_header: %u\n", skb->mac_header);
            pr_devel("SRCAUTH_UPDATE ip_header: %u\n", skb->network_header);
            pr_devel("SRCAUTH_UPDATE transport_header: %u\n", skb->transport_header);
            
            pr_devel("SRCAUTH_UPDATE skb_headroom is: %u\n", old_headroom);
            
            if(old_protocol == XT_SRCAUTH_HEADER_ID)
            {
                recalc_checksum = true;
                
                //get sa header with offset!
                sah = (struct xt_SRCAUTH_header *) (skb_network_header(skb)+iph_size);
                
                //set n adn MTL from header
                n = sah->n;
                MTL = sah->MTL;
                position = sah->position;
                
                sah_size = sizeof(*sah) + MTL*sizeof(sah->meta_inf[0])    +
                                           n*(sizeof(sah->verification[0]) +
                                              sizeof(sah->identifiers[0]));
                
                //init indicator, note the byte ordering!
                indicator = ntohs(sah->verification[MTL + position].indicator);
                pr_devel("SRCAUTH_Update reading sah header with n: %u MTL: %u position: %u\n", n, MTL, position);

                ///////////////////////////////////////////////////////////////
                // Check are we destination or intermediate node? indicator of destination is 0
                if(indicator == 0) {
                    // Case Destination
                    // Verify Crypto
                    pr_devel("SRCAUTH_UPDATE: case destination validate verification value and datahash\n");
                    
                    //overwrite checksum for data hash calculation
                    if (sah->protocol == 17) {
                        //UDP
                        udph = (struct udphdr *) (skb_network_header(skb)+iph_size+sah_size);
                        checksumtmp = ntohs(udph->check);
                        udph->check = 0x0000;
                        pr_devel("SRCAUTH_UPDATE overwrite udp checksum for data hash\n");
                    }
                    else if (sah->protocol == 6) {
                        //TCP
                        tcph = (struct tcphdr *) (skb_network_header(skb)+iph_size+sah_size);
                        checksumtmp = ntohs(tcph->check);
                        tcph->check = 0x0000;
                        pr_devel("SRCAUTH_UPDATE overwrite tcp checksum for data hash\n");
                    }
                    
                    
                    // derive session key
                    pr_devel("SRCAUTH_UPDATE: derive key for session\n");
                    memcpy(&sessionidtmp[0], &sah->sessionid[0], XT_SRCAUTH_SESSIONID_LEN_BYTES);
                    // host byte order FUTURE WORK: could be made more efficient
                    for(i = 0; i < XT_SRCAUTH_HASH_LEN; i++)
                    {
                        sessionidtmp[i] = ntohs(sessionidtmp[i]);
                    }
                    memcpy(output, &sessionidtmp[0], XT_SRCAUTH_SESSIONID_LEN_BYTES);
                    memset(&output[XT_SRCAUTH_SESSIONID_LEN_BYTES], 0x00, XT_SRCAUTH_SHA1_LENGTH - XT_SRCAUTH_SESSIONID_LEN_BYTES);

                    //one block only, iv 0
                    aes = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
                    if (IS_ERR(aes)) {
                        pr_err("Error occured while allocating AES module, missing module?");
                        return NF_DROP;
                    }
                    
                    // check verification value, use local key
                    if (crypto_cipher_setkey(aes, (const u8 *) xt_srcauth_get_localkey(), 4*XT_SRCAUTH_KEY_LEN) ) {
                        pr_err("Error occured while setting key for AES!");
                        return NF_DROP;
                    }
                    
                    // encrypt 1 block, Note: at least 1 block size input and output, pad with zeros
                    crypto_cipher_encrypt_one(aes, derivedkey, output);

                    //set derived key to aeskey
                    if (crypto_cipher_setkey(aes, (const u8 *) derivedkey, 4*XT_SRCAUTH_KEY_LEN)) {
                        pr_err("Error occured while setting key for AES!");
                        return NF_DROP;
                    }
                    
                    //debug
#ifdef DEBUG
                    pr_devel("Derived key: \n");
                    for (i = 0; i < XT_SRCAUTH_AES_LENGTH; i++) {
                        pr_devel("%02x", derivedkey[i]);
                    }
#endif
                    
                    ////////////////////////////////////////////////////
                    // destination needs to recalculate datahash
                    // DataHash = H(P|INDICATOR|MetaInf)
                    
                    pr_devel("DataHash sha1: \n");
                    
                    desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
                    
                    if (IS_ERR(desc.tfm)) {
                        pr_err("Error occured while allocating sha1 hash, missing module?");
                        return false;
                    }
                    
                    desc.flags = 0;
                    
                    // copy verification value from destination and set them all to 0 for hashing
                    // switch to host byte order
                    comparevalue = ntohs(sah->verification[MTL + position].value);
                    for(i = 0; i < n; i++)
                    {
                        //verification, offset is sah->MTL * 32bits
                        sah->verification[MTL + i].value = 0x0000;
                    }
                    
                    // Hash from our header in skb from and including meta_inf[0] to the end of linear data
                    // (offset is position of meta_inf in sa header)
                    // careful we are at iph position, therefore substract iph size!
                    payload_length = skb_headlen(skb)-offsetof(struct xt_SRCAUTH_header, meta_inf[0])-iph_size;
                    pr_devel("Running sha1 on skb for length %u", payload_length);
                    sg_init_one(&sg, &sah->meta_inf[0], payload_length);
                    
                    //Hash init, calc, copy
                    crypto_hash_init(&desc);
                    crypto_hash_update(&desc, &sg, payload_length);
                    if (crypto_hash_final(&desc, output)) {
                        pr_err("Error occured while hashing data hash!");
                        return NF_DROP;
                    }
#ifdef DEBUG
                    for (i = 0; i < 20; i++) {
                        pr_devel("%d-%d\n", output[i], i);
                    }
#endif
                    
                    // Free mem
                    crypto_free_hash(desc.tfm);
                    
                    ////////////////////////////////////////////////////
                    // now validate verification values

                    // pad recalculated datahash with zeros
                    memset(&output[XT_SRCAUTH_DATAHASH_LEN_BYTES], 0x00, XT_SRCAUTH_SHA1_LENGTH - XT_SRCAUTH_DATAHASH_LEN_BYTES);

                    // encrypt 1 block, at least 1 block size input and output, pad with zeros
                    crypto_cipher_encrypt_one(aes, aesdst, output);
                    
                    // compare verification values (2 bytes)
                    if (memcmp(&comparevalue, aesdst, 2) != 0) {
                        //verification values do not match!
                        pr_err("Verification values do not match! Read: %04x, calculated: %02x%02x", comparevalue, aesdst[0], aesdst[1]);
                        return NF_DROP;
                    }
                    
                    crypto_free_cipher(aes);
                    
                    pr_devel("SRCAUTH_Update: Verification value and datahash verified");
                    
                    
                    //restore checksums
                    if (sah->protocol == 17) {
                        //UDP
                        udph->check = htons(checksumtmp);
                        pr_devel("SRCAUTH_UPDATE restore udp checksum\n");
                    }
                    else if (sah->protocol == 6) {
                        //TCP
                        tcph->check = htons(checksumtmp);
                        pr_devel("SRCAUTH_UPDATE restore tcp checksum\n");
                    }
                    
                    ////////////////////////////////////////////////////
                    // Update header info
#ifdef DEBUG
                    snprintf(tmp, 16, "%pI4", &sah->dst_addr_orig);
                    pr_devel("SRCAUTH_Update case destination with position %u restore original destination %s \n", position, tmp);
#endif
                    //restore original destination ip
                    iph->daddr = sah->dst_addr_orig;
                }
                else {
                    ///////////////////////////////////////////////////////////
                    // Case intermediate node
                    pr_devel("SRCAUTH_Update: derive key for session\n");
                    
                    //debug

 
                    memcpy(&sessionidtmp[0], &sah->sessionid[0], XT_SRCAUTH_SESSIONID_LEN_BYTES);
                    // host byte order
                    for(i = 0; i < XT_SRCAUTH_HASH_LEN; i++)
                    {
                        sessionidtmp[i] = ntohs(sessionidtmp[i]);
                    }
#ifdef DEBUG
                    pr_devel("use session id: \n");
                    for (i = 0; i < XT_SRCAUTH_HASH_LEN; i++) {
                        pr_devel("%04x", sessionidtmp[i]);
                    }
#endif
                    // derive session key
                    memcpy(output, &sessionidtmp[0], XT_SRCAUTH_SESSIONID_LEN_BYTES);
                    memset(&output[XT_SRCAUTH_SESSIONID_LEN_BYTES], 0x00, XT_SRCAUTH_SHA1_LENGTH - XT_SRCAUTH_SESSIONID_LEN_BYTES);
                    
                    //one block only, iv 0
                    aes = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
                    if (IS_ERR(aes)) {
                        pr_err("Error occured while allocating AES module, missing module?");
                        return NF_DROP;
                    }
                    
                    // use local key
                    if (crypto_cipher_setkey(aes, (const u8 *) xt_srcauth_get_localkey(), 4*XT_SRCAUTH_KEY_LEN) ) {
                        pr_err("Error occured while setting key for AES!");
                        return NF_DROP;
                    }
                    
                    // encrypt 1 block, Note: at least 1 block size input and output, pad with zeros
                    crypto_cipher_encrypt_one(aes, derivedkey, output);
                    
                    //set derived key to aeskey
                    if (crypto_cipher_setkey(aes, (const u8 *) derivedkey, 4*XT_SRCAUTH_KEY_LEN)) {
                        pr_err("Error occured while setting key for AES!");
                        return NF_DROP;
                    }
                    
                    //debug
#ifdef DEBUG
                    pr_devel("Derived key: \n");
                    for (i = 0; i < XT_SRCAUTH_AES_LENGTH; i++) {
                        pr_devel("%02x", derivedkey[i]);
                    }
#endif
                    
                    // validate verification values, read from packet header
                    memcpy(&sessionidtmp[0], &sah->data_hash[0], XT_SRCAUTH_DATAHASH_LEN_BYTES);
                    // host byte order
                    for(i = 0; i < XT_SRCAUTH_HASH_LEN; i++)//use same variable for data hash
                    {
                        sessionidtmp[i] = ntohs(sessionidtmp[i]);
                    }
                    memcpy(output, &sessionidtmp[0], XT_SRCAUTH_DATAHASH_LEN_BYTES);
                    memset(&output[XT_SRCAUTH_DATAHASH_LEN_BYTES], 0x00, XT_SRCAUTH_SHA1_LENGTH - XT_SRCAUTH_DATAHASH_LEN_BYTES);
                    
                    // encrypt 1 block, at least 1 block size input and output, pad with zeros
                    crypto_cipher_encrypt_one(aes, aesdst, output);
                    
                    // compare verification values (2 bytes)
                    // switch to host byte order
                    pr_devel("See verification value: %04x ", sah->verification[MTL + position].value);
                    comparevalue = ntohs(sah->verification[MTL + position].value);
                    if (memcmp(&comparevalue, aesdst, 2) != 0) {
                        //verification values do not match!
                        pr_err("Verification values do not match! Read: %04x, calculated: %02x%02x", comparevalue, aesdst[0], aesdst[1]);
                        return NF_DROP;
                    }
                    
                    crypto_free_cipher(aes);
                    
                    pr_devel("SRCAUTH_Update: Verification values verified");
                    
                    ////////////////////////////////////////////////////
                    // Update header info
                    // init mask
                    mask = 0x000F;
                    
                    // get next hop position from indicator
                    do {
                        nextposition = indicator & mask;
                        //never send back to source
                        if(indicator == 0 || nextposition == 0) {
                            //no valid position found
                            pr_err("Did not find any routing table entries! Dropping Packet");
                            return NF_DROP;
                        }
                        // get next hop id (n + MTL for offset)
                        nextid = sah->identifiers[(n + MTL) + nextposition];
                        
                        //update indicator, move to next id
                        indicator = (indicator >> 4);
                        //now update entry if there is an entry in kernel DB
                    } while(!xt_srcauth_lookup_routing((union nf_inet_addr *) &nextid, (union nf_inet_addr *) &iph->daddr));
#ifdef DEBUG
                    snprintf(tmp, 16, "%pI4", &iph->daddr);
                    pr_devel("SRCAUTH_Update case intermediate node with position "
                             "%u change ip to next hop %s and update position to %u\n", position, tmp, nextposition);
#endif
                    // update position for the next node
                    sah->position = nextposition;
                }
            }
            else
            {
                //to enforce secure source authentication, drop packet if no header present
                pr_err("SRCAUTH_Update failed, no header present! Dropping packet\n");
                return NF_DROP;
            }
            pr_devel("SRCAUTH_UPDATE finished.\n");
     break;
     case XT_SRCAUTH_REMOVE:
            /* Remove our header if present */
            if(old_protocol == XT_SRCAUTH_HEADER_ID)
            {
                recalc_checksum = true;
                
                pr_devel("SRCAUTH_REMOVE headers before:\n");
                pr_devel("SRCAUTH_REMOVE mac_header: %u\n", skb->mac_header);
                pr_devel("SRCAUTH_REMOVE ip_header: %u\n", skb->network_header);
                pr_devel("SRCAUTH_REMOVE transport_header: %u\n", skb->transport_header);
                
                pr_devel("SRCAUTH_REMOVE skb_headroom is: %u\n", old_headroom);
                
                /* Remove old header */
                /* link layer header */
                // Cover case for completeness to keep packet aligned.
                switch (skb->dev->type) {
                    //ARPHRD_LOOPBACK
                    case 772:
                    //ARPHRD_ETHER
                    case 1:
                    {
                        pr_devel("SRCAUTH_REMOVE ethernet device recognized\n");
                        if (skb_mac_header_was_set(skb))
                        {
                            eth = (struct ethhdr *) skb_mac_header(skb);
                            
                            eth_new = kmalloc(skb->mac_len, GFP_ATOMIC);
                            
                            if (eth_new == NULL)
                            {
                                pr_err("SRCAUTH_REMOVE could not copy MAC header!\n");
                                kfree_skb(skb);
                                return NF_STOLEN;
                            }
                            
                            memcpy(eth_new, eth, skb->mac_len);
                            is_eth = true;
                            
                            //Only if data pointer at mac header
                            if(old_headroom == skb->mac_header)
                            {
                                // Remove link layer
                                skb_pull(skb, skb->mac_len);
                                pulled_eth = true;
                            }
                            else
                            {
                                pr_devel("SRCAUTH_REMOVE mac not pulled!\n");
                            }
                        }
                        else
                        {
                            pr_devel("SRCAUTH_REMOVE ethernet mac not set!\n");
                        }
                        break;
                    }
                    default:
                        pr_devel("SRCAUTH_REMOVE no ethernet header dev set\n");
                        break;
                };
                
                
                /* Copy IP header */
                iph_new = kmalloc(iph_size, GFP_ATOMIC);
                if (iph_new == NULL)
                {
                    pr_err("SRCAUTH_REMOVE could not copy IP header!\n");
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
                memcpy(iph_new, iph, iph_size);

                
                
                pr_devel("SRCAUTH_REMOVE remove scheme header\n");

                
                /* Remove IP header, get scheme header */
                sah = (struct xt_SRCAUTH_header*) skb_pull(skb, iph_size);
                
                //set n from header
                n = sah->n;
                MTL = sah->MTL;
                
                sah_size = sizeof(*sah) + MTL*sizeof(sah->meta_inf[0])    +
                                          n*(sizeof(sah->verification[0]) +
                                             sizeof(sah->identifiers[0]));
                
                pr_devel("SRCAUTH_REMOVE scheme header size %u\n", sah_size);
                
                /* Remove Scheme header*/
                skb_pull(skb, sah_size);

                // restore original protocol
                iph_new->protocol = sah->protocol;
                // Note: restore original daddr, done here again to be more felxible with remove-header, careful with overwriting
                iph_new->daddr = sah->dst_addr_orig;
#ifdef DEBUG
                    snprintf(tmp, 16, "%pI4", &sah->dst_addr_orig);
                    pr_devel("SRCAUTH_REMOVE restore original address: %s", tmp);
#endif
                pr_devel("SRCAUTH_REMOVE restore protocol %u\n", iph_new->protocol);
                pr_devel("SRCAUTH_REMOVE read sah protocol %u\n", sah->protocol);
                pr_devel("SRCAUTH_REMOVE read sah MTL %u\n", sah->MTL);
                pr_devel("SRCAUTH_REMOVE read sah position %u\n", sah->position);
                pr_devel("SRCAUTH_REMOVE read sah n %u\n", sah->n);
                
                /* Restore IP header*/
                pr_devel("SRCAUTH_REMOVE restore and update IP header\n");
                
                iph = (struct iphdr*) skb_push(skb, iph_size);
                
                memcpy(iph, iph_new, iph_size);
                
                /* Set new skb ip header pointer */
                skb_reset_network_header(skb);

                /* Adapt Transport Layer */
                skb_set_transport_header(skb, iph_size);
                
                iph = ip_hdr(skb);
                
                /* Update total length */
                iph->tot_len = htons(old_tot_len - sah_size);
                
                /* Link Layer */
                if(is_eth)
                {
                    pr_devel("SRCAUTH_REMOVE restore mac header\n");
                    
                    eth = (struct ethhdr*) skb_push(skb, skb->mac_len);
                    memcpy(eth, eth_new, skb->mac_len);
                    
                    skb_reset_mac_header(skb);
                    
                    //Restore previous pointer state and adapt correct length
                    if(!pulled_eth)
                    {
                        skb_pull(skb, skb->mac_len);
                    }
                }
                
                /* Checksum start relative to skb->head pointer */
                // Note: checksum starts at TCP header, therefore we do not alter
                pr_devel("SRCAUTH_REMOVE csum is unchanged: %u\n", skb->csum_start);
                
                /*pr_devel("SRCAUTH_REMOVE headers after:\n");
                pr_devel("SRCAUTH_REMOVE mac_header: %u\n", skb->mac_header);
                pr_devel("SRCAUTH_REMOVE ip_header: %u\n", skb->network_header);
                pr_devel("SRCAUTH_REMOVE transport_header: %u\n", skb->transport_header);
                pr_devel("SRCAUTH_REMOVE skb_headroom is: %u\n", skb_headroom(skb));*/
            }
            else
            {
                pr_info("SRCAUTH_REMOVE failed, no header present!\n");
            }
            
            pr_devel("SRCAUTH_REMOVE finished.\n");
     break;
     default:
            pr_info("Unknown option.\n");
     break;
     }

    /* Calculation of IP header checksum */
    if (recalc_checksum) {
        if (info->option == XT_SRCAUTH_SET) {
            //needed to really write the new checksum to the skb!
            if (!skb_make_writable(skb, skb->len))
            {
                pr_err("SRCAUTH_SET Could not make skb writeable!\n");
                return NF_DROP;
            }
            pr_devel("SRCAUTH_SET called skb make writeabel!\n");
            
            iph = ip_hdr(skb);
        }
        
        iph->check = 0;
        ip_send_check(iph);
        pr_devel("New IP checksum value set! %04x \n", iph->check);
    }
    
    /* Free temporary sructures - can be called on NULL if not used*/
    kfree(eth_new);
    kfree(iph_new);
    
#ifdef DEBUG
    /*if (info->option == XT_SRCAUTH_SET) {
        pr_devel("SRCAUTH_SET Values after checksum calculation and memory freeing:\n");
        pr_devel("SRCAUTH_SET protocol in sah %u\n", sah->protocol);
        pr_devel("SRCAUTH_SET MTL in sah %u\n", sah->MTL);
        pr_devel("SRCAUTH_SET position in sah %u\n", sah->position);
        pr_devel("SRCAUTH_SET n in sah %u\n", sah->n);
    }*/
#endif
    
    return XT_CONTINUE;
}


static int srcauth_tg4_check(const struct xt_tgchk_param *par)
{
    //simple check for unknown option
    const struct xt_SRCAUTH_info *info = par->targinfo;
    
    if (info->option > XT_SRCAUTH_MAXMODE) {
        pr_info("SRCAUTH: invalid or unknown mode %u\n", info->option);
        pr_devel("SRCAUTH: invalid or unknown mode %u\n", info->option);
        return -EINVAL;
    }
    
    return 0;
}

static struct xt_target srcauth_tg_reg[] __read_mostly = {
    {
        .family		= NFPROTO_IPV4,
        .name		= "SRCAUTH",
        .checkentry	= srcauth_tg4_check,
        .target		= srcauth_tg4,
        .revision   = 0,
        .targetsize	= sizeof(struct xt_SRCAUTH_info),
        .hooks      = (1 << NF_INET_PRE_ROUTING) |
                      (1 << NF_INET_LOCAL_IN)    |
                      (1 << NF_INET_LOCAL_OUT)   |
                      (1 << NF_INET_POST_ROUTING),
        .me         = THIS_MODULE,
    },
    
    /*Add IPV6 Support here*/
};

static int __init srcauth_tg_init(void)
{
    // Note: DB Module will be started before by kernel, no init neeeded.
    return xt_register_targets(srcauth_tg_reg, ARRAY_SIZE(srcauth_tg_reg));
}

static void __exit srcauth_tg_exit(void)
{
    xt_unregister_targets(srcauth_tg_reg, ARRAY_SIZE(srcauth_tg_reg));
}

module_init(srcauth_tg_init);
module_exit(srcauth_tg_exit);
