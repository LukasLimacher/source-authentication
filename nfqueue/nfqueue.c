/**************************************************************************************************
 *  nfqueue.c
 *
 *  Used to initiated session setups for source authentication and
 *  provides interface between procfs and session setup script
 *
 * 
 * Dependencies: sudo apt-get install libnetfilter-queue-dev
 *
 * IPTABLES must be configured to send packets to this daemon like this (as root):
 * iptables -A INPUT -p tcp -j NFQUEUE --queue-num 42
 *
 * Written by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
 * Copyright (c) 2015 Open Systems AG, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 **************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>	// for multi-threads

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> // for verdicts NF_ACCEPT etc.

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <linux/netfilter/xt_SRCAUTH.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


// constants
//how long the daemon should sleep, note that this is the maximal delay of discovering when a link is done.
//we use the same time as the intervalls in OSPF (15 seconds).
#define ROUTING_SLEEP_TIME 15
#define BUFFERSIZE 4096
#define FULL_PROCFS_NAME "/proc/SRCAUTH_DB_proc" //must match kernel module
//#define FULL_LOCALKEY_NAME "/opt/OSAGsrcauth/ma_thesis_implementation/nfqueue/localKey.bin" //must match perl script
#define FULL_LOCALKEY_NAME "localKey.bin" //More flexible relative path for testing
#define DEBUG_SESSION_FILENAME "sampleOutputSessionSetup.bin"
// Note can use absolute paths for calling session script etc. at the moment need to be in working directory nfqueue

// prototypes
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
short int session_setup_nfqueue(unsigned short int queuenum);
int identify_ip_protocol(char *payload);
char *get_src_ip_str(char *payload);
char *get_dst_ip_str(char *payload);
int update_routing_info(void);
int write_local_key(void);
int write_debug_session(void);

// Threads
// Verdict Thread
void *session_setup_thread(void *threadarg) {
    printf("Thread: session setup thread started\n");
    session_setup_nfqueue(*(unsigned short int *)threadarg);
    printf("Thread: session setup thread stops\n");
    pthread_exit(NULL);
}

// Routing Thread
void *routing_thread() {
    printf("Thread: Routing thread started\n");
    while (1) {
        printf("Thread: Routing update routing information\n");
        update_routing_info();
        sleep(ROUTING_SLEEP_TIME);
    }
    printf("Thread: Routing thread stops\n");
    pthread_exit(NULL);
}

// Sessio Setup Server Thread
void *session_server_thread() {
    char command[64];
    strcpy(command, "./sessionSetup.pm -dk -s" );
    
    printf("Thread: Session server thread started: %s\n", command);
    system(command);//use debug keys (local keys though normally)
    printf("Thread: Session server thread stops\n");
    pthread_exit(NULL);
}

// main function
int main(int argc, char **argv) {
    int ret = 0;
    unsigned short int queuenum = 42;	// queue number to read
    int keynotsuccess = 1;
    
    // check root user
    if (getuid() != 0) {
        fprintf(stderr, "Please run as root!\n");
        exit(-1);
    }
    
    // parse command line
    int done = 0;
    while (!done) {		//scan command line options
        ret = getopt(argc, argv, "q:kd");
        switch (ret) {
            case -1 :
                done = 1;
                break;
            case 'q':
                queuenum = (unsigned short int)atoi(optarg);
                break;
            case 'k':
                keynotsuccess = write_local_key();
                if (!keynotsuccess) {
                    printf("Wrote local key to procfs\n");
                }
                else {
                    printf("Could not write local key to procfs\n");
                    exit(keynotsuccess);
                }
                //exit(keynotsuccess); //do not exit and start usually with -k to put localkey into kernel
                break;
            case 'd':
                keynotsuccess = write_debug_session();
                if (!keynotsuccess) {
                    printf("Read and write debug session material %s\n", DEBUG_SESSION_FILENAME);
                }
                else {
                    printf("Could not read and write debug session material %s\n", DEBUG_SESSION_FILENAME);
                }
                exit(keynotsuccess);
                break;
            case '?':	// unknown option
                fprintf(stderr,
                        "Invalid option\n");
                exit(-1);
        }
    }
    
    printf("Starting Daemon, initialize Threads\n");
    
    // Start Threads
    pthread_t sessio_setup, routing, session_server;
    ret = pthread_create(&sessio_setup, NULL, session_setup_thread,
                         (void *) &queuenum);
    if (ret) {
        printf("ERROR; return code from pthread_create() is %d\n", ret);
        exit(-1);
    }
    
    ret = pthread_create(&routing, NULL, routing_thread, NULL);
    if (ret) {
        printf("ERROR; return code from pthread_create() is %d\n", ret);
        exit(-1);
    }
    
    ret = pthread_create(&session_server, NULL, session_server_thread, NULL);
    if (ret) {
        printf("ERROR; return code from pthread_create() is %d\n", ret);
        exit(-1);
    }
    
    pthread_exit(NULL);
}

// loop to process a received packet at the queue
short int session_setup_nfqueue(unsigned short int queuenum) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd, rv;
    char buf[BUFFERSIZE];
    
    // opening library handle
    h = nfq_open();
    if (!h) {
        printf("Error during nfq_open()\n");
        exit(-1);
    }
    
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("Error during nfq_unbind_pf()\n");
        //exit(-1);
    }
    
    // binds the given queue connection handle to process packets.
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("Error during nfq_bind_pf()\n");
        exit(-1);
    }
    printf("NFQUEUE: binding to queue '%hd'\n", queuenum);
    
    // create queue
    qh = nfq_create_queue(h,  queuenum, &nfqueue_cb, NULL);
    if (!qh) {
        printf("Error during nfq_create_queue()\n");
        exit(-1);
    }
    
    // Sets the amount of data to be copied to userspace for each packet queued
    // to the given queue. //CHECK if NFQNL_COPY_NONE can be used though
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("Can't set packet mode\n");
        exit(-1);
    }
    
    // returns the netlink handle associated with the given queue connection handle.
    // Possibly useful if you wish to perform other netlink communication
    // directly after opening a queue without opening a new netlink connection to do so
    nh = nfq_nfnlh(h);
    
    // returns a file descriptor for the netlink connection associated with the
    // given queue connection handle.  The file descriptor can then be used for
    // receiving the queued packets for processing.
    fd = nfnl_fd(nh);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("NFQUEUE: Received new packet\n");
        // triggers an associated callback for the given packet received from the queue.
        // Packets can be read from the queue using nfq_fd() and recv().
        nfq_handle_packet(h, buf, rv);
    }
    
    // unbinding before exit
    printf("NFQUEUE: unbinding from queue '%hd'\n", queuenum);
    nfq_destroy_queue(qh);
    nfq_close(h);
    return(0);
}

// function callback for packet processing
static int nfqueue_cb(
                      struct nfq_q_handle *qh,
                      struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa,
                      void *data) {
    
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    
    if (ph) {
        int id = 0, size = 0;
        char *full_packet; // get data of packet (payload)
        char *dst; //destination ip
        id = ntohl(ph->packet_id);
        //debug
        printf("hw_protocol = 0x%04x hook = %u id = %u \n",
               ntohs(ph->hw_protocol), ph->hook, id);
        
        size = nfq_get_payload(nfa, &full_packet);
        
        int id_protocol = identify_ip_protocol(full_packet);
        printf("NFQUEUE: Packet from %s", get_src_ip_str(full_packet));
        dst = get_dst_ip_str(full_packet);
        printf(" to %s\n", dst);
        
        // DEBUG
        // dst = "10.0.6.2";
		// printf("Set Debug original destination ip: %s\n", dst);
        ////
        
        // DEBUG deactivate // which hook is not needed for functionality (ph->hook)
        switch (id_protocol) {
            case IPPROTO_ICMP :
                printf("ICMP header recognized\n");
                break;
            case IPPROTO_TCP :
                printf("TCP header recognized\n");
                break;
            case IPPROTO_UDP :
                printf("UDP header recognized\n");
                break;
            case IPPROTO_ESP :
                printf("ESP header recognized\n");
                break;
            default :
                printf("%d header id recognized\n", id_protocol);
                break;
        }
        
        // always write new session even if session present and only new mapping:
        // FUTURE WORK: For more speed need to handle this in daemon with new option for
        // sessionScript to only get the mapping back and ( cat /proc/SRCAUTH_DB or better
        // keeping track in the daemon with hashtable and own timestamps of the OSPF id)!
        // Without concurrency solution is:
        // For each packet check to which destination id it belongs.
        // Add packet to this queue
        // For each queue for the first packet, do the session setup.
        // Rest of the packets are buffered until session setup finished and reinjected to iptables
        // keep track of how long session is valid (either procfs or own timer) as
        // new original destinations need to add them to the mapping but not do the session setup.
        
        //call session setup script
        char command[100];
        
        strcpy(command, "./sessionSetup.pm -dk -destination ");
        strcat(command, dst);
        printf("NFQUEUE: Calling session setup script.\n");
        printf("%s\n", command);

        FILE *fp;
        char path[2048];
        
        /* Open the command for reading. */
        fp = popen(command, "r");
        if (fp == NULL) {
            printf("Failed to run command\n");
            exit(1);
        }
        
        //////////////////////////////////////////////////////////////////
        // read and parse for kernel DB
        // DEBUG
        //printf ("sizeof time_t is: %d\n", sizeof(time_t));
        //printf ("sizeof long is: %lld\n", sizeof(long));
        
        // note all data must match with the kernel struct
        // session
        struct xt_SRCAUTH_session session;
        unsigned short int n = 0;
        // for mapping
        union nf_inet_addr dst_addr_in_key;
        union nf_inet_addr dst_addr_id_out;
        
        // get n
        if (fgets(path, sizeof(path), fp) != NULL) {
            n = (unsigned short int)atoi(path);
            session.n = (__u8) n;
            printf("Parsed session.n '%d'\n", session.n);
        }
        else {
            printf("ERROR Could not parse n, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
        // get timestamp
        if (fgets(path, sizeof(path), fp) != NULL) {
            session.timestamp = (__s64)atoll(path);
            printf("Parsed session.timestamp '%lld'\n", session.timestamp);
        }
        else {
            printf("ERROR Could not parse timestamp, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
        // parse path set aka identifiers
        // init identifiers
        int i=0;
        for (i=0; i < XT_SRCAUTH_MAXN; i++) {
            session.identifiers[i] = 0;
        }
        printf("Parsing path set\n");
        for (i=0; i < n; i++) {
            if (fgets(path, sizeof(path), fp) != NULL) {
                //NB Byteorder http://www.bruceblinn.com/linuxinfo/ByteOrder.html
                printf(" parsing %s ", path);
                int result = inet_aton(path, (struct in_addr *)&session.identifiers[i]);
                //inet_aton() returns nonzero if the address is valid, zero if not
                //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
                printf(" coversion result %d\n", result);
            }
            else {
                printf("ERROR Could not parse path set, read: %s\nAbort this run\n", path);
                goto ABORT;
            }
        }
        // parse destination id within scheme (ospf router id)
        // FUTURE WORK for more efficient daemon call this seperatelty before and queue packets for each dest id
        printf("Parsing destination id within scheme\n");
        if (fgets(path, sizeof(path), fp) != NULL) {
            printf(" got id %s ", path);
            int result = inet_aton(path, (struct in_addr *)&dst_addr_id_out.ip);
            //inet_aton() returns nonzero if the address is valid, zero if not
            //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
            printf(" coversion result %d\n", result);
        }
        else {
            printf("ERROR Could not parse destination id, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
        // read by size from now on, fread returns number of elements read
        // Session id, 1 element = 2 Bytes
        printf("Parsing sessionid\n");
        if (fread(path, 2, XT_SRCAUTH_HASH_LEN, fp) == XT_SRCAUTH_HASH_LEN) {
            memcpy(session.sessionid, path, (2*XT_SRCAUTH_HASH_LEN));
            // Debug
            printf("sessionid: %04x%04x%04x%04x%04x%04x\n", session.sessionid[0], session.sessionid[1], session.sessionid[2], session.sessionid[3], session.sessionid[4], session.sessionid[5]);
        }
        else {
            printf("ERROR Could not parse session id\nAbort this run\n");
            goto ABORT;
        }
        // Path indicator, 1 element = 2 Bytes
        // init
        for (i=0; i < XT_SRCAUTH_MAXN; i++) {
            session.indicators[i] = 0;
        }
        printf("Parsing path indicator\n");
        if (fread(path, 2, n, fp) == n) {
            memcpy(session.indicators, path, (2*n));
        }
        else {
            printf("ERROR Could not parse path indicator\nAbort this run\n");
            goto ABORT;
        }
        // Keys, 1 element = 16 bytes
        int j=0;
        for (i=0; i < (XT_SRCAUTH_MAXN-1); i++) {
            for (j=0; j < XT_SRCAUTH_KEY_LEN; j++) {
                session.keys[i].key[j] = 0;
            }
        }
        printf("Parsing keys\n");
        if (fread(path, XT_SRCAUTH_KEY_LEN*4, (n-1), fp) == (n-1)) {
            memcpy(session.keys, path, (XT_SRCAUTH_KEY_LEN*4*(n-1)));
        }
        else {
            printf("ERROR Could not parse keys\nAbort this run\n");
            goto ABORT;
        }
        // there should be nothing left
        while (fgets(path, sizeof(path), fp) != NULL) {
            printf("There should be nothing left, Read:\n%sAbort this run\n", path);
            goto ABORT;
        }
        
        //Create Mapping original addr
        printf("Parse original destination %s\n", dst);
        int result = inet_aton(dst, (struct in_addr *)&dst_addr_in_key.ip);
        //inet_aton() returns nonzero if the address is valid, zero if not
        if (!result) {
            printf("Could not parse original destination. Abort this run\n");
            goto ABORT;
        }
        
        printf("NFQUEUE: Everything parsed successfully. Write to procfs\n");

        //////////////////////////////////////
        // Write to kernel procfs
        FILE * file= fopen(FULL_PROCFS_NAME, "wb");
        char modeMapping = 'm';
        char modeSession = 's';
        if (file != NULL) {
            // make sure all data written at once, NULL = buffer allocated for size
            //Note: sizeof(struct xt_SRCAUTH_session) > sizeof(union nf_inet_addr)
            setvbuf(file, NULL, _IOFBF, sizeof(struct xt_SRCAUTH_session) + sizeof(union nf_inet_addr) + 1);
            /* Write Mapping */
            // write control char
            fwrite(&modeMapping, 1, 1, file);
            //write data
            fwrite(&dst_addr_in_key, sizeof(union nf_inet_addr), 1, file);
            fwrite(&dst_addr_id_out, sizeof(union nf_inet_addr), 1, file);
            fflush(file);
            /* Write Session Data */
            // write control char
            fwrite(&modeSession, 1, 1, file);
            //write data
            fwrite(&dst_addr_id_out, sizeof(union nf_inet_addr), 1, file);
            fwrite(&session, sizeof(struct xt_SRCAUTH_session), 1, file);
            fflush(file);
            fclose(file);
        }
        else {
            printf("Could not write to procfs!\n");
            goto ABORT;
        }
        
        //////////////////////////////////////
        //End parsing and writing to kernel DB
    ABORT:
        /* close */
        pclose(fp);
        
        //set verdict; from official doc:
        // http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html
        // NF_ACCEPT the packet passes, continue iterations.
        // comment: seems does not trigger rules below in same table
        // NF_REPEAT iterate the same cycle once more.
        // comment: im same table from top
        nfq_set_verdict(qh, id, NF_REPEAT, 0, NULL);
    } else {
        printf("NFQUEUE: can't get msg packet header.\n");
        return(1); // from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
    }
    
    return(0);
}

int write_local_key(void) {
    //read local key from file
    struct keys localkey;
    
    FILE * readfile= fopen(FULL_LOCALKEY_NAME, "rb");
    if (readfile != NULL) {
        fread(&localkey, sizeof(struct keys), 1, readfile);
        printf("Read localkey of size %lu which is: %08x%08x%08x%08x\n", sizeof(struct keys), localkey.key[0], localkey.key[1], localkey.key[2], localkey.key[3]);
    }
    else {
        printf("Could not read localkey!\n");
        return 1;
    }
    
    
    //printf("Write localkey to procfs\n");
    //write local key to procfs
    FILE * file= fopen(FULL_PROCFS_NAME, "wb");
    char mode = 'k';
    if (file != NULL) {
        // make sure all data written at once, NULL = buffer allocated for size
        setvbuf(file, NULL, _IOFBF, sizeof(struct keys) + 1);
        // write control char
        fwrite(&mode, 1, 1, file);
        //write data
        fwrite(&localkey, sizeof(struct keys), 1, file);
        fflush(file);
        fclose(file);
    }
    else {
        printf("Could not write to procfs!\n");
        return 1;
    }
    return 0;
}

int write_debug_session(void) {
    char *dst = "10.0.6.2"; //DEBUG
    char path[2048];
    
    FILE * fp= fopen(DEBUG_SESSION_FILENAME, "r");
    if (fp == NULL) {
        printf("Failed to read debug file\n");
        return 1;
    }
    
    //////////////////////////////////////////////////////////////////
    // read and parse for kernel DB
    // DEBUG
    //printf ("sizeof time_t is: %d\n", sizeof(time_t));
    //printf ("sizeof long is: %lld\n", sizeof(long));
    
    // note all data must match with the kernel struct
    // session
    struct xt_SRCAUTH_session session;
    unsigned short int n = 0;
    // for mapping
    union nf_inet_addr dst_addr_in_key;
    union nf_inet_addr dst_addr_id_out;
    
    // get n
    if (fgets(path, sizeof(path), fp) != NULL) {
        n = (unsigned short int)atoi(path);
        session.n = (__u8) n;
        printf("Parsed n '%hd'\n", n);
        printf("Parsed session.n '%d'\n", session.n);
    }
    else {
        printf("ERROR Could not parse n, read: %s\nAbort this run\n", path);
        goto ABORT;
    }
    // get timestamp
    if (fgets(path, sizeof(path), fp) != NULL) {
        session.timestamp = (__s64)atoll(path);
        printf("Parsed session.timestamp '%lld'\n", session.timestamp);
    }
    else {
        printf("ERROR Could not parse timestamp, read: %s\nAbort this run\n", path);
        goto ABORT;
    }
    // parse path set aka identifiers
    // init identifiers
    int i=0;
    for (i=0; i < XT_SRCAUTH_MAXN; i++) {
        session.identifiers[i] = 0;
    }
    printf("Parsing path set\n");
    for (i=0; i < n; i++) {
        if (fgets(path, sizeof(path), fp) != NULL) {
            //NB Byteorder http://www.bruceblinn.com/linuxinfo/ByteOrder.html
            printf(" parsing %s ", path);
            int result = inet_aton(path, (struct in_addr *)&session.identifiers[i]);
            //inet_aton() returns nonzero if the address is valid, zero if not
            //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
            printf(" coversion result %d\n", result);
        }
        else {
            printf("ERROR Could not parse path set, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
    }
    // parse destination id within scheme (ospf router id)
    // FUTURE WORK for more efficient daemon call this seperatelty before and queue packets for each dest id
    printf("Parsing destination id within scheme\n");
    if (fgets(path, sizeof(path), fp) != NULL) {
        printf(" got id %s ", path);
        int result = inet_aton(path, (struct in_addr *)&dst_addr_id_out.ip);
        //inet_aton() returns nonzero if the address is valid, zero if not
        //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
        printf(" coversion result %d\n", result);
    }
    else {
        printf("ERROR Could not parse destination id, read: %s\nAbort this run\n", path);
        goto ABORT;
    }
    // read by size from now on, fread returns number of elements read
    // Session id, 1 element = 2 Bytes
    printf("Parsing sessionid\n");
    if (fread(path, 2*XT_SRCAUTH_HASH_LEN, 1, fp) == XT_SRCAUTH_HASH_LEN) {
        memcpy(session.sessionid, path, (2*XT_SRCAUTH_HASH_LEN));
        printf("sessionid: %04x%04x%04x%04x%04x%04x\n", session.sessionid[0], session.sessionid[1], session.sessionid[2], session.sessionid[3], session.sessionid[4], session.sessionid[5]);
    }
    else {
        printf("ERROR Could not parse session id\nAbort this run\n");
        goto ABORT;
    }
    // Path indicator, 1 element = 2 Bytes
    // init
    for (i=0; i < XT_SRCAUTH_MAXN; i++) {
        session.indicators[i] = 0;
    }
    printf("Parsing path indicator\n");
    if (fread(path, 2, n, fp) == n) {
        memcpy(session.indicators, path, (2*n));
    }
    else {
        printf("ERROR Could not parse path indicator\nAbort this run\n");
        goto ABORT;
    }
    // Keys, 1 element = 16 bytes
    int j=0;
    for (i=0; i < (XT_SRCAUTH_MAXN-1); i++) {
        for (j=0; j < XT_SRCAUTH_KEY_LEN; j++) {
            session.keys[i].key[j] = 0;
        }
    }
    printf("Parsing keys\n");
    if (fread(path, XT_SRCAUTH_KEY_LEN*4, (n-1), fp) == (n-1)) {
        memcpy(session.keys, path, (XT_SRCAUTH_KEY_LEN*4*(n-1)));
    }
    else {
        printf("ERROR Could not parse keys\nAbort this run\n");
        goto ABORT;
    }
    //for file allow 1 ending line
    if (fgets(path, sizeof(path), fp) != NULL)
    {
        // there should be nothing left
        while (fgets(path, sizeof(path), fp) != NULL) {
            printf("There should be nothing left, Read:\n%sAbort this run\n", path);
            goto ABORT;
        }
    }
    
    //Create Mapping original addr
    printf("Parse original destination %s\n", dst);
    int result = inet_aton(dst, (struct in_addr *)&dst_addr_in_key.ip);
    //inet_aton() returns nonzero if the address is valid, zero if not
    if (!result) {
        printf("Could not parse original destination. Abort this run\n");
        goto ABORT;
    }
    
    printf("Everything parsed successfully. Write to procfs\n");

    
    //////////////////////////////////////
    // Write to kernel procfs
    FILE * file= fopen(FULL_PROCFS_NAME, "wb");
    char modeMapping = 'm';
    char modeSession = 's';
    if (file != NULL) {
        // make sure all data written at once, NULL = buffer allocated for size
        //Note: sizeof(struct xt_SRCAUTH_session) > sizeof(union nf_inet_addr)
        setvbuf(file, NULL, _IOFBF, sizeof(struct xt_SRCAUTH_session) + sizeof(union nf_inet_addr) + 1);
        /* Write Mapping */
        // write control char
        fwrite(&modeMapping, 1, 1, file);
        //write data
        fwrite(&dst_addr_in_key, sizeof(union nf_inet_addr), 1, file);
        fwrite(&dst_addr_id_out, sizeof(union nf_inet_addr), 1, file);
        fflush(file);
        /* Write Session Data */
        // write control char
        fwrite(&modeSession, 1, 1, file);
        //write data
        fwrite(&dst_addr_id_out, sizeof(union nf_inet_addr), 1, file);
        fwrite(&session, sizeof(struct xt_SRCAUTH_session), 1, file);
        fflush(file);
        fclose(file);
    }
    else {
        printf("NFQUEUE: Could not write to procfs!\n");
        goto ABORT;
    }
    
    //no errror
    fclose(fp);
    return 0;
    
    //error
ABORT:
    /* close */
    fclose(fp);

    return 1;
}

// lists for dynamic number of routing entries
// Note: More efficient than switching between reading and writing to procfs
struct list_el {
    union nf_inet_addr val;
    struct list_el * next;
};

typedef struct list_el item;

int update_routing_info(void) {
    //update routing info get from perl script and put in kernel
    union nf_inet_addr id_in_key;
    union nf_inet_addr dst_addr_out;
    int n;
    
    //for lists
    item * curr_in, * head_in;
    item * curr_out, * head_out;
    item * tmp;

    //init lists
    head_in = NULL;
    head_out = NULL;

    //call session setup script for routing
    char command[100];
    
    strcpy(command, "./sessionSetup.pm -r ");
    printf("Routing: Calling session setup script for routing.\n");
    printf("%s\n", command);
    // NB system is not enough since we want to read the output :)
    FILE *fp;
    char path[2048];
    
    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        exit(1);
    }
    
    // need while loop and list to read and output all pairs of routing infos
    while (fgets(path, sizeof(path), fp) != NULL) {
        // get peer aka id
        printf("Routing: Parsing peer id\n");
        printf(" got id %s ", path);
        int result = inet_aton(path, (struct in_addr *)&id_in_key.ip);
        //inet_aton() returns nonzero if the address is valid, zero if not
        //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
        printf(" coversion result %d\n", result);
        if (!result) {
            printf("ERROR Could not parse peer id, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
        
        // get destination
        printf("Routing: Parsing destination \n");
        if (fgets(path, sizeof(path), fp) != NULL) {
            printf(" got address %s ", path);
            int result = inet_aton(path, (struct in_addr *)&dst_addr_out.ip);
            //inet_aton() returns nonzero if the address is valid, zero if not
            //inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form (in network byte order)
            printf(" coversion result %d\n", result);
        }
        else {
            printf("ERROR Could not parse destination, read: %s\nAbort this run\n", path);
            goto ABORT;
        }
        
        // dont need timestamp, just flush but could be done more efficiently

        //set list elements
        // id_in_key
        curr_in = (item *)malloc(sizeof(item));
        curr_in->val = id_in_key;
        curr_in->next = head_in;
        head_in = curr_in;
        // dst_addr_out
        curr_out = (item *)malloc(sizeof(item));
        curr_out->val = dst_addr_out;
        curr_out->next = head_out;
        head_out = curr_out;
    }
    
    // set lists to head
    curr_in = head_in;
    curr_out = head_out;
    
    printf("Routing: Everything parsed successfully. Write to procfs\n");

    //////////////////////////////////////
    // Write to kernel procfs
    FILE * file= fopen(FULL_PROCFS_NAME, "wb");
    char modeRouting = 'r';
    char modeFlush = '/';
    if (file != NULL) {
        // make sure all data written at once, NULL = buffer allocated for size
        setvbuf(file, NULL, _IOFBF, 2*sizeof(union nf_inet_addr) + 1);
        /* Flush routing DB */
        // write control chars: Flush, Routing (only!)
        fwrite(&modeFlush, 1, 1, file);
        fwrite(&modeRouting, 1, 1, file);
        fwrite(&modeRouting, 1, 1, file);//need 3 chars
        fflush(file);
        /* Write all routing pairs from list*/
        while (curr_in && curr_out) {
            // write control char
            fwrite(&modeRouting, 1, 1, file);
            //write data
            fwrite(&curr_in->val, sizeof(union nf_inet_addr), 1, file);
            fwrite(&curr_out->val, sizeof(union nf_inet_addr), 1, file);
            //push
            fflush(file);
            
            //set next lists elements
            curr_in = curr_in->next;
            curr_out = curr_out->next;
        }
        // done, close file
        fclose(file);
    }
    else {
        printf("Could not write to procfs!\n");
        goto ABORT;
    }

ABORT:
    /* close */
    pclose(fp);
    
    /* delete lists */
    // reset to head and free
    curr_in = head_in;
    curr_out = head_out;
    
    //in list
    while(curr_in) {
        tmp = curr_in;
        curr_in = curr_in->next;
        free(tmp);
    }
    
    //out list
    while(curr_out) {
        tmp = curr_out;
        curr_out = curr_out->next;
        free(tmp);
    }
}

// Functions from packet engine from "skeleton code"
/*
 * This fuction identifies if the captured packet is TCP or UDP.
 * Fuction will return: Protocol code e.g.  1 for ICMP, 6 for TCP and 17 for UDP.
 */
int identify_ip_protocol(char *payload) {
    return payload[9];
}

/*
 * This function gets src IP as string
 */
char *get_src_ip_str(char *payload) {
    /* Cast the IP Header from the raw packet */
    struct ip *iph = (struct ip *) payload;
    
    /* get src address from iph */
    return(inet_ntoa(iph->ip_src));
}

/*
 * This function gets dst IP as string
 */
char *get_dst_ip_str(char *payload) {
    /* Cast the IP Header from the raw packet */
    struct ip *iph = (struct ip *) payload;
    
    /* get dst address from iph */
    return(inet_ntoa(iph->ip_dst));
}

