#!/usr/bin/perl

###############################################################################
#
# sessionSetup.pm: Session Setup Script for
# SRCAUTH kernel modules and user space daemon.
#
# Written by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
# Copyright (c) 2015 Open Systems AG, Switzerland
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
###############################################################################

# Strict and warnings are recommended
use strict;
use warnings;

# In and Output, Sending
use IO::Socket::INET;
use Getopt::Long;
use Path::Class;
use NetAddr::IP;

# Regex and utils
use Regexp::Common;
use List::Util qw/min/;
use List::MoreUtils qw/uniq/;

# Logging
use Log::Any;
use Log::Any::Adapter;
use Log::Log4perl;
# DEBUG
# use Data::Dumper;
# Piping
use IPC::Open3;

# Crypto modules
use Crypt::Random qw( makerandom_octet );
#use Crypt::RSA;#inefficient
use Crypt::Digest::SHA1;
use Crypt::CBC;
use Crypt::Ed25519;
# Fast RSA
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::AES;
#note Crypt::OpenSSL::AES is used in program

# use custom modules for IPv4 regex and graph library
use lib 'lib';
use RegIP;
use Graph;
use Graph::Undirected;

# Logfile
my $LOGFILE_BASE = 'sessionSetup';
# Configs for OSPF database parsing
my $VTYSH = '/bin/vtysh';
my $CMD_DATABASE = 'show ip ospf database';
my $CMD_ROUTER   = 'show ip ospf database router';
my $CMD_NEIGHBOR = 'show ip ospf neighbor';
# Configs for tunnel status, used to identify unreliable link
my $tunnel_link_state_file = "/opt/OSAGotr/etc/tunnel_link.state";
my $tunnel_translations = "/opt/OSAGotr/etc/tunnel_translations.map";
my $tunnel_final_state = "/opt/OSAGotr/etc/tunnel_link_by_router_id.state";

#########################################################################
# Option Arguments
#########################################################################
#
# -destination x Set destination to x (original destination IP)
# -d             debug output
# -dk            use debug keys (except local keys if constant set)
# -s             run as server
# -r             provide routing info (local neighbours from OSPF) and exit
# -keygen NAME   generate key for destination id NAME, if NAME=localhost,
#                generate the localkey.bin

#########################################################################
# Path Set, Path and Backup Path Algorithm Parameters
#########################################################################
# K-Shortest Path Algorithm used
# 'yen' is yen's k shortest path
# 'eppstein' is eppstein's k shortest path
use constant K_SHORTEST_PATH_ALG => 'yen';
# Min and Max for k for k-shortest path algorithms, otherwise we take k=number of nodes
use constant MAX_K => 400;
use constant MIN_K => 10;
# maximal total cost of a potential backup path
use constant COST_THRESHOLD => 10000;
# maximal number of successors in indicator for a node (size is 4 bits, for max_n 15)
use constant PATH_INDICATOR_SIZE => 4;
# maximal number of (additional) support links, depends on path indicator size
# worst case: backup path split at start node of unreliable link
use constant MAX_SUPPORT_LINKS => PATH_INDICATOR_SIZE()-2;
# Flag to de-/activate the calculation of the backup path
use constant CALC_BACKUP_PATH => 1; # 1 on, 0 off
# maximal number of path set entities, bigger number than 15 needs update of path indicator code
use constant MAX_N => 15;

#########################################################################
# Parameters Security
#########################################################################
# session lifetime and timeout (MUST MATCH WITH KERNEL PARAMETER)
use constant SESSION_LIFETIME => 300; #seconds

# Key sizes
use constant SYMMETRIC_KEY_SIZE => 128; #bits
use constant ASYMMETRIC_KEY_SIZE => 2048; #bits
# Size of encrypted AUTH in Bytes
use constant ENCRYPTED_AUTH_SIZE => 1712; #Bytes
# 1024 bits => 928 Bytes
# 2048 bits => 1712 Bytes
# 4096 bits => 3280 Bytes
# use fixed sizes since calculation depends on
# AES padding (16 Bytes), size of sessionid and assymetric key size.
# Truncate session id hash to follwowing number of bytes
use constant SESSIONID_SIZE => 12; #Bytes
# Fixed IV of 0 for CBC-MAC. PRF key derivation
use constant IV_FIXED => '0000000000000000';#'6304318598924633'
# Key debuging
use constant ALWAYS_LOAD_LOCAL_KEY => 1; #1 on: load local key even if debug key enabled 0: off
use constant DEBUG_SHAREDKEY => '8413650119085227'; #128 bits
# Error code for AUTH missmatch
use constant AUTH_MISSMATCH => -32;
# Error code for Packet not received
use constant PACKET_NOT_RECEIVED => -31;

#########################################################################
# Parameters Sockets
#########################################################################
# Timeout for sockets (implemented with alarms)
use constant TIMEOUT => 3; # implemented with alarms since deactivated in sockets
# Read size for connection
# Port number for connections from Source to Destination
use constant PORT => 4041;
# Port number for connection from Destination to Source
use constant PORT_SRC => 4042;
# Protocol for connection
use constant PROTOCOL => 'udp';
# Timeout for connection
# case at destination or intermediate node, check size
use constant READ_SIZE_MAX => 40960;
# flush after every write
$| = 1;


#########################################################################
# initialization and get command line arguments
#########################################################################
my $debug = '';
my $debugKey = '';
my $isServer = '';
my $destination = 'localhost';
my $keygen = '';
my $routing = '';

GetOptions ("debug|d"       => \$debug,
            "debugkey|dk"   => \$debugKey,
            "server|s"      => \$isServer,
            "routing|r"      => \$routing,
            "destination=s" => \$destination,
            "keygen=s"      => \$keygen);

# init logger
my $log = init_logger($debug, $isServer);
$log->info("Logger initialized");

if($debug)
{
    $log->info("Debug option enabled!");
}

#########################################################################
# Case: Get and return routing info for adaptive routing
#########################################################################
if($routing)
{
    my ($one_ref, $two_ref) = get_neighbours();
    my @peers = @{$one_ref};
    my @destinations = @{$two_ref};
    
    #output
    for my $i (0 .. $#peers) #read by line for routing info
    {
        print STDOUT "$peers[$i]\n";
        print STDOUT "$destinations[$i]\n";
    }

    #done, do not execute rest of script
    exit;
}


#########################################################################
# Case: Create and Write symmetric key, for debug
#########################################################################
if($keygen)
{
    my $file;
    
    if($keygen eq 'localhost') {
        # local key
        $file = file("localKey.bin");
        $log->info("Creating and storing local symmetric key localKey.bin");
    }
    #FUTURE WORK predistribute certificates
    elsif ($keygen eq 'signing'){
        my ($pubkey, $privkey) = Crypt::Ed25519::generate_keypair;
        $file = file('presharedKeys', "localSigningPublic.bin"); #presharedKeys/NAME.bin
        my $file2 = file('presharedKeys', "localSigningPrivate.bin");
        my $file_handle = $file->openw() or die "Can't write $file: $!";
        my $file_handle2 = $file2->openw() or die "Can't write $file: $!";
        $file_handle->print($pubkey);
        $file_handle2->print($privkey);
        $log->info("Public Key:\n", unpack('H*',$pubkey));
        $log->info("Private Key:\n", unpack('H*',$privkey));
        $log->info("Creating and storing local signing public key localSigningPublic.bin");
        $log->info("Creating and storing local signing private key localSigningPrivate.bin");
        exit;
    }
    else {
        # Preshared keys with destination
        $file = file('presharedKeys', "$destination.bin"); #presharedKeys/NAME.bin
        $log->info("Creating and storing symmetric key $destination.bin");
    }

    # Create symmetric key, strong from /dev/random but can block! Size is minus 1, changed to 0 cannot block!
    my $symmetricKey = makerandom_octet( Size => SYMMETRIC_KEY_SIZE()-1, Strength => 0);
    #Debug
    #my $symmetricKey = pack('h*', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
    
    # Get a file_handle (IO::File object) you can write to
    my $file_handle = $file->openw() or die "Can't write $file: $!";
    #open(my $file_handle, '>:raw', $file) or die "Unable to write: $!";
    
    $file_handle->binmode;
    
    
    $log->info("New key H: ", unpack('H*', $symmetricKey));
    $log->info("New key h: ", unpack('h*', $symmetricKey));

    my $newKeyLength = bytes::length($symmetricKey);
    $log->info("New key length: $newKeyLength");
    
    #note: Little vs big endian, however if the data is read, it is correctly interpreted! check
    $file_handle->print( $symmetricKey );
    
    exit;
}

#########################################################################
# SEVER MODE
#########################################################################
if($isServer)
{
    $log->info("Running in server mode");
    
    my ($socket,, $socket_permanent, $received_data);
    my ($peer_address,$peer_port);
    
    #load local secret if stored.
    my $localKey = read_local_key($debugKey);
    
    #Variables
    my $i;
    my @path;
    my @pathSet;
    my $timestamp;
    my $AUTH;
    my $position;
    my $publicSession;
    my $privateSession;
    my @derivedKeysandSignatures = ();
    # second packet
    my @path2;
    my @pathSet2;
    my $timestamp2;
    my $AUTH2;
    my $position2;
    my $publicSession2;
    my @derivedKeysandSignatures2 = ();
    
    #Init the $socket_permanent only once and then receive from all clients!
    $socket_permanent = new IO::Socket::INET (
    LocalPort => PORT(),
    Proto => PROTOCOL(),
    #ReuseAddr => 1, #not needed
    ) or die "Error opening socket: $!\n";
    
#########################################################################
# server main loop
#########################################################################
while(1)
{
    #########################################################################
    # initialize server socket
    #########################################################################
START:
    
    # Read operation on the socket, is buffered when multiple clients send!
    # Do not close this socket
    if(!$socket_permanent->recv($received_data,READ_SIZE_MAX() ) ) {
        # This should not occur
        $log->error("Could not receive data or socket is NULL!");
        exit -2;
    }
    
    #get the peerhost and peerport from which recent data was received.
    $peer_address = $socket_permanent->peerhost();
    $peer_port = $socket_permanent->peerport();
    #$log->debug("($peer_address , $peer_port) received:\n$received_data");
    $log->info("($peer_address , $peer_port) received data");
    
    
    #########################################################################
    # Parse received data
    #########################################################################
    my ($ref_path, $ref_pathSet, $ref_derivedKeys);
    ($position, $ref_path, $publicSession, $ref_pathSet, $timestamp, $AUTH, $ref_derivedKeys) = parse_received_data($received_data);
    @path = @{$ref_path};
    @pathSet = @{$ref_pathSet};
    @derivedKeysandSignatures = @{$ref_derivedKeys};
    
    #$log->debug("Public Session 1: $publicSession");
    #$log->debug("Path Set 1: @pathSet");
    
    # check timestamp
    my $timeCheck = time;
    # DEBUG
    my $humanTimeCheck = localtime($timeCheck);
    my $humanTime = localtime($timestamp);
    $log->debug("Received timestamp: $timestamp which is $humanTime");
    $log->debug("Computed timeCheck: $timeCheck which is $humanTimeCheck");
    # compare timestamp
    if ($timeCheck < $timestamp + SESSION_LIFETIME()) {

        $log->debug("Timestamp valid");
    }
    else {
        $log->info("Old timestamp, aborting this protocol run!");
        goto START;
    }
    
    # Compute sessionid
    my $sessionid = compute_sessionid($publicSession, \@pathSet, $timestamp);
    
    if($position == $#path) {
        ####################################################################
        # CASE DESTINATION
        ####################################################################
        $log->debug("####################################################################");
        $log->debug("# Server case destination");
        $log->debug("####################################################################");
        
        # Check if we are missing entities
        my @check = uniq (@pathSet, @path);
        if ($#check != $#path) {
            $log->debug("Waiting for second packet..");
            # NEED to receive second packet if the path
            # does not contain all entities from the path set!
            
            # Need to implement timeout, since not supported in IO::Socket::INET
            eval {
                local $SIG{ALRM} = sub { die "alarm\n"; };
                alarm TIMEOUT();
                # Wait for destination until timeout
                if(!$socket_permanent->recv($received_data,READ_SIZE_MAX() ) ) {
                    # This should not occur
                    $log->debug("Could not receive data second packet or socket is NULL!");
                    goto START;
                }
                
                
                #get the peerhost and peerport from which recent data was received.
                my $peer_address2 = $socket_permanent->peerhost();
                my $peer_port2 = $socket_permanent->peerport();
                #$log->debug("($peer_address , $peer_port) received:\n$received_data");
                $log->info("($peer_address2 , $peer_port2) received data");
                
                #parse data
                my ($ref_path2, $ref_pathSet2, $ref_derivedKeys2);
                ($position2, $ref_path2, $publicSession2, $ref_pathSet2, $timestamp2, $AUTH2, $ref_derivedKeys2) = parse_received_data($received_data);
                @path2 = @{$ref_path2};
                @pathSet2 = @{$ref_pathSet2};
                @derivedKeysandSignatures2 = @{$ref_derivedKeys2};
                
                #$log->debug("Public Session 1: $publicSession2");
                #$log->debug("Path Set 1: @pathSet");
                
                alarm 0;
            };
            if ($@) {
                die unless $@ eq "alarm\n"; # propagate unexpected errors
                # timed out
                $log->debug("Did not receive second packet, goto START");
                goto START;
            }
            else {
                # check timestamp
                my $timeCheck2 = time;
                # DEBUG
                my $humanTimeCheck2 = localtime($timeCheck2);
                my $humanTime2 = localtime($timestamp2);
                $log->debug("Received timestamp: $timestamp2 which is $humanTime2");
                $log->debug("Computed timeCheck: $timeCheck2 which is $humanTimeCheck2");
                # compare timestamp
                if ($timeCheck2 < $timestamp2 + SESSION_LIFETIME()) {
                    
                    $log->debug("Timestamp valid in second packet");
                }
                else {
                    $log->info("Old timestamp in second packet, aborting this protocol run!");
                    goto START;
                }
                
                # Compute sessionid
                #$log->debug("Sessionid2 use timestamp2: $timestamp2");
                my $sessionid2 = compute_sessionid($publicSession2, \@pathSet2, $timestamp2);
                # Check if sessionids match
                if ($sessionid eq $sessionid2 && $AUTH eq $AUTH2) {
                    $log->debug("Sessionid and AUTH from second packet is same as in first one");
                }
                else {
                    $log->info("Wrong session id or AUTH in second packet, aborting this protocol run!");
                    goto START;
                }
                #ensured also that path set is the same with sessionid!
            }
        }
        
        # decrypt and check information
        my $sourceid = $pathSet[0];
        
        # read preshared key
        my $presharedKey = read_preshared_key($debugKey, $sourceid);
        
        # Derive symmetric keys for S and D for both directions
        my $CBCAESKEYS = Crypt::CBC->new(
        -key    => $presharedKey,
        -iv => IV_FIXED(),
        -header => 'none',#no salt
        -cipher => "Crypt::OpenSSL::AES"
        );
        
        # Block size 16 of CBC ensures key length of 128b = 16B
        my $keySD = $CBCAESKEYS->encrypt("SD$sessionid");
        my $keyDS = $CBCAESKEYS->encrypt("DS$sessionid");;
        # debug keys
        my $sizekeySD = length($keySD);
        $log->debug("Length of derived keys: $sizekeySD");
        
        # Decrypt auth
        my $CBCAESSource = Crypt::CBC->new(
        -key    => $keySD,
        -header => 'salt',
        -cipher => "Crypt::OpenSSL::AES"
        );
        
        my $AUTHdecrypt = $CBCAESSource->decrypt("$AUTH");
        #debug AUTH
        #my $debugAUTH = pack("h*", $AUTHdecrypt);
        $log->debug("Decrypted AUTH:\n$AUTHdecrypt");
        my $sizeAUTH = bytes::length($AUTHdecrypt);
        $log->debug("Length of decr AUTH: $sizeAUTH");
        
        my $sessionidCheck = substr( $AUTHdecrypt, 0, SESSIONID_SIZE() );
        #$log->debug("Sessionid in AUTH: $sessionidCheck");

        my $privateSession = substr( $AUTHdecrypt, SESSIONID_SIZE());#read rest

        #$log->debug("Private session key in AUTH:\n$privateSession");
        
        # check if sessionids match
        if ($sessionid eq $sessionidCheck) {
            $log->debug("Sessionids matched");
        }
        else {
            $log->info("Sessionids missmatch, abort this run");
            goto START;
        }
        
        # Decrypt and validate sent keys and certificates
        # FUTURE WORK load and use specific public signature ed25519
        # Load RSA
        my $rsa_decrypt = Crypt::OpenSSL::RSA->new_private_key($privateSession);

        my @individualKeys;
        
        for($i = 0; $i <= $#derivedKeysandSignatures; $i += 2 ) {
            my $tmpKey = $rsa_decrypt->decrypt($derivedKeysandSignatures[$i]);
            my $tmpSignature = $derivedKeysandSignatures[$i+1];
            
            #FUTURE WORK read for each entitiy, add identifier
            my ($pubkey, $privkey) = read_signing_keys($debugKey);
            
            # verify key
            my $valid = Crypt::Ed25519::verify_croak "$tmpKey$publicSession", $pubkey, $tmpSignature;
            my $sizetmpKey = bytes::length($tmpKey);
            #$log->debug("decrypted key has length $sizetmpKey");
            #$log->debug("and is: $tmpKey");
            #$log->debug("signature is:\n$tmpSignature");
            
            if ($valid) {
                $log->debug("Key signature valid for entity $i");
                push(@individualKeys, $tmpKey);
            }
            else {
                $log->info("Key signature invalid for entity $i, abort this protocol run!");
                goto START;
            }
        }
        
        # Derive own key for session (here since needed in composition below)
        # pad session id with zeros
        my $paddedSessionid = substr($sessionid . pack('H*', "00000000"), 0, 16);
        #my $sizedebug = bytes::length($paddedSessionid);
        #$log->debug("Padded sessionid length: $sizedebug");
        $log->debug("Derive key on sessionid padded 0: ", unpack('H*', "$paddedSessionid"));
        
        # Simple derivation no iv no cbc for cbc mac based AES
        my $cipher = new Crypt::OpenSSL::AES($localKey);
        
        my $destinationKey = $cipher->encrypt($paddedSessionid);
        $log->debug("Direct AES with padding is: ", unpack('H*', "$destinationKey"));
        
        my $sizedestinationKey = length($destinationKey);
        $log->debug("Length of derived destination key: $sizedestinationKey");
        
        $log->debug("Derived key: ", unpack('H*', "$destinationKey"));
        
        
        # do same if second packet
        # Note: could be optimized, do not compute same entities again!
        if (@derivedKeysandSignatures2) {
            my @individualKeys2;
            for($i = 0; $i <= $#derivedKeysandSignatures2; $i += 2 ) {
                my $tmpKey = $rsa_decrypt->decrypt($derivedKeysandSignatures2[$i]);
                my $tmpSignature = $derivedKeysandSignatures2[$i+1];
                
                #FUTURE WORK read for each entitiy, add identifier
                my ($pubkey, $privkey) = read_signing_keys($debugKey);
                
                # verify key
                my $valid = Crypt::Ed25519::verify_croak "$tmpKey$publicSession", $pubkey, $tmpSignature;
                my $sizetmpKey = bytes::length($tmpKey);
                #$log->debug("decrypted key has length $sizetmpKey");
                #$log->debug("and is: $tmpKey");
                #$log->debug("signature is:\n$tmpSignature");
                
                if ($valid) {
                    $log->debug("Key signature valid for entity $i");
                    push(@individualKeys2, $tmpKey);
                }
                else {
                    $log->info("Key signature invalid for entity $i, abort this protocol run!");
                    goto START;
                }
            }
            # Note: Order of path set: add keys in right order!
            # first shortest path, then additional entities from backup path
            my $isFirst = 1;
            for my $i (0 .. $#path)
            {
                if (!($path[$i] eq $pathSet[$i])) {
                    $isFirst = 0;
                    last;
                }
            }
            
            #Note need to handle rare case if keys are same
            #For now S does simply reject
            if ($debugKey && !ALWAYS_LOAD_LOCAL_KEY()) {
                #all have the same key in debug
                my $numberOfKeys = $#pathSet-1;#without destination
                $log->debug("Using debug keys, have $numberOfKeys many keys");
                for my $i (($#path) .. $numberOfKeys)
                {
                    my $tmp = $individualKeys[0];
                    push(@individualKeys, $tmp);
                }
            }
            elsif ($isFirst) {
                # Add destination key at right position according to path set
                push (@individualKeys, $destinationKey);
                @individualKeys = uniq (@individualKeys, @individualKeys2);
            }
            else {
                # Add destination key at right position according to path set
                push (@individualKeys2, $destinationKey);
                @individualKeys = uniq (@individualKeys2, @individualKeys);
            }
        }
        else {
            # simply add destination key at the end in case we only have 1 path
            push (@individualKeys, $destinationKey);
        }
        
        
        $log->debug("Individual keys after adding of destination key #( $#individualKeys )");
        #$log->debug("@individualKeys");

        if ($#individualKeys != $#pathSet-1) {
            $log->error("Number of keys incorrect, check for duplicated keys");
        }
        
        # authentically encrypt information for Source
        my $CBCAESDestination = Crypt::CBC->new(
        -key    => $keyDS,
        # Alternative implementation is Crypt::Cipher::AES
        -header => 'salt',
        -cipher => "Crypt::OpenSSL::AES"
        );

        # all keys
        my $allKeys = $CBCAESDestination->encrypt("@individualKeys$AUTH");
        
        # send back to source
        $socket = new IO::Socket::INET (
        PeerAddr => $sourceid,
        PeerPort => PORT_SRC(),
        Proto    => PROTOCOL(),
        Timeout  => TIMEOUT()
        ) or die "Error opening socket: $!\n";
        
        # send operation
        $socket->send($allKeys);
        
        # close socket
        $socket->close();
        
        $log->debug("Server sent back to source");
    }
    else {
        #########################################################################
        # CASE INTERMEDIATE NODE
        #########################################################################
        $log->debug("####################################################################");
        $log->debug("# Server case intermediate node");
        $log->debug("####################################################################");
        
        #Derive key
        #pad session id with zeros
        my $paddedSessionid = substr($sessionid . pack('H*', "00000000"), 0, 16);
        #my $sizedebug = bytes::length($paddedSessionid);
        #$log->debug("Padded sessionid length: $sizedebug");
        $log->debug("Derive key on sessionid padded 0: ", unpack('H*', "$paddedSessionid"));

        # Simple derivation no iv no cbc for cbc mac based AES
        my $cipher = new Crypt::OpenSSL::AES($localKey);
        
        my $derivedKey = $cipher->encrypt($paddedSessionid);
        $log->debug("Direct AES with padding is: ", unpack('H*', "$derivedKey"));
        
        my $sizederivedkey = bytes::length($derivedKey);
        $log->debug("Derived key length: $sizederivedkey");
        
        $log->debug("Derived key: ", unpack('H*', "$derivedKey"));
        
        # encrypt key
        my $rsa = Crypt::OpenSSL::RSA->new_public_key($publicSession);
        my $encryptedKey = $rsa->encrypt($derivedKey);
        #$log->debug("Encrypted derived key:\n$encryptedKey");
        
        
        # efficient signing with
        # ed25519 http://search.cpan.org/~mlehmann/Crypt-Ed25519-1.0/Ed25519.pm
        my ($pubkey, $privkey) = read_signing_keys($debugKey);
        
        my $signature = Crypt::Ed25519::sign "$derivedKey$publicSession", $pubkey, $privkey;
        
        
        # DEBUG
        #my $valid = Crypt::Ed25519::verify_croak "$derivedKey$publicSession", $pubkey, $signature;
        #$log->debug("Key signature testing is: $valid");
        
        push(@derivedKeysandSignatures, $encryptedKey);
        push(@derivedKeysandSignatures, $signature);
        
        # DEBUG
        #my $sizeEncryptedKey = bytes::length($encryptedKey);
        #my $sizeSignature = bytes::length($signature);
        #$log->debug("Size of encrypted derived key:$sizeEncryptedKey");
        #$log->debug("Size of signature of derived key:$sizeSignature");
        # Size of encrypted key is ASYMMETRIC_KEY_SIZE()\8 (in bytes)
        # Size of signature is always 64 bytes
        
        #########################################################################
        # forward information to next hop on path
        #########################################################################
        my $newPosition = $position+1;
        
        $socket = new IO::Socket::INET (
        PeerAddr => $path[$newPosition],
        PeerPort => PORT(),
        Proto    => PROTOCOL(),
        Timeout  => TIMEOUT()
        ) or die "Error opening socket: $!\n";
        
        my $data = "$newPosition-@path$publicSession@pathSet-$timestamp$AUTH@derivedKeysandSignatures";
        $socket->send($data);
        $log->debug("Sent to next hop: $path[$newPosition]");
        
        # close socket
        $socket->close();
    }
}
}
#########################################################################
# CLIENT MODE: SOURCE
#########################################################################
else {
    $log->info("Running in client mode");
    $log->info("Destination set to $destination");
    
    my ($socket,$data);
    
    #########################################################################
    # calculate path set and the two paths to destination
    #########################################################################
    
    # read paths and path set, ospf router ids. Get address where to send.
    my ($one_ref, $two_ref, $three_ref, $destinationid) = calculate_paths_and_path_set($destination);
    my @pathSet = @{$one_ref};
    my @allPaths = @{$two_ref};
    my @pathIndicator = @{$three_ref};
    $log->debug("Path Set is (outside sub):", "@pathSet");
    
    if ($#pathSet < 1) {
        $log->error("Found no path with at least two entities, is destination correct? Path Set:", "@pathSet\nAbort run.");
        exit(-1);
    }
    
    #########################################################################
    # create other data for the packets to send
    #########################################################################
    # note: symmetric keys buildall predestribution, check if read works.
    
    #Read preshared key
    my $presharedKey = read_preshared_key($debugKey, $destinationid);
    my $sizepresharedKey = bytes::length($presharedKey);
    $log->debug("Size of preshared key: $sizepresharedKey");
    
    # Initiate new session key
    # FUTURE WORK Note To boost performance, create in advance and read!!
    #my $rsa = new Crypt::RSA;
    # Note this is slow, use OpenSSL instead (but OpenSSL more beta).
    #my ($publicSession, $privateSession) = $rsa->keygen( Size => ASYMMETRIC_KEY_SIZE() );
    
    $log->info("Generating session key pair");
    my $rsa = Crypt::OpenSSL::RSA->generate_key(ASYMMETRIC_KEY_SIZE());
    my $publicSession = $rsa->get_public_key_string();
    my $privateSession = $rsa->get_private_key_string();
    
    #my $rsa_test = Crypt::OpenSSL::RSA->new_private_key($privateSession);
    
    # DEBUG
    #$log->debug("private key is:\n", $privateSession);
    #$log->debug("public key (in PKCS1 format) is:\n", $publicSession);
    

    # Generate timestamp
    my $timestamp = time;
    #Debug
    my $humanTime = localtime($timestamp);
    $log->debug("timestamp: $timestamp which is $humanTime");
    
    #Compute sessionid
    my $sessionid = compute_sessionid($publicSession, \@pathSet, $timestamp);
    
    my $sizeSessionid = length($sessionid);
    $log->debug("Truncated sessionid to size: $sizeSessionid");
    
    #my $debugIVLength = bytes::length(IV_FIXED());
    #$log->debug("Length of IV for MAC: $debugIVLength");
    
    # Derive symmetric keys for S and D for both directions
    # Alternative key derivation perl: Crypt::KeyDerivation pbkdf2
    my $CBCAESKEYS = Crypt::CBC->new(
    -key    => $presharedKey,
    -iv => IV_FIXED(),
    -header => 'none',#no salt
    -cipher => "Crypt::OpenSSL::AES"
    );

    
    # Block size 16 of CBC ensures key length of 128b = 16B
    my $keySD = $CBCAESKEYS->encrypt("SD$sessionid");
    my $keyDS = $CBCAESKEYS->encrypt("DS$sessionid");;
    # debug keys
    my $sizekeySD = length($keySD);
    $log->debug("Length of derived keys: $sizekeySD");

    
    # Encrypt to create AUTH
    my $CBCAESSource = Crypt::CBC->new(
    -key    => $keySD,
    # Alternative implementation is Crypt::Cipher::AES
    -header => 'salt',
    -cipher => "Crypt::OpenSSL::AES"
    );
    
    my $AUTH = $CBCAESSource->encrypt("$sessionid$privateSession");
    #debug AUTH
    #$log->debug("Created AUTH from:\n$sessionid$privateSession");
    my $sizeAUTH = bytes::length($AUTH);
    $log->debug("Length of AUTH: $sizeAUTH");
    my $sizeprivateSession = bytes::length($privateSession);
    $log->debug("Length of private session key: $sizeprivateSession");

    
    #########################################################################
    # send packets to first node
    #########################################################################
    
    # For each path
    foreach (@allPaths)
    {
        my @path = @{ $_ };
        $log->debug("Working with path: @path");
        
        #FUTURE WORK lookup ip for $path[1] for now have 1 to 1 mapping
        
        # call IO::Socket::INET->new() to create the UDP Socket
        # and bind with the PeerAddr.
        # Note: Sending is instantly
        $socket = new IO::Socket::INET (
        PeerAddr => $path[1],
        PeerPort => PORT(),
        Proto    => PROTOCOL(),
        Timeout  => TIMEOUT()
        ) or die "Error opening socket: $!\n";
    
        # send operation
        #$data = "Hello world from client!\n";
        #Send data, next position is 1 (first intermediate node) use - for separation

        # DEBUG for timeout!
        # sleep 2;
    
        $data = "1-@path$publicSession@pathSet-$timestamp$AUTH";
        $socket->send($data);
    
        # DEBUG
        #$log->debug("send:\n$data");
        #$log->debug("Sent data to first node $path[1]");
        #print STDOUT "Sent data to first node $path[1]";
        #print STDOUT "send:\n$data";
        
        # close socket
        $socket->close();
    }
    #########################################################################
    # receive packet from destination
    #########################################################################
    $log->debug("Wait for destination packet");
    
    # Need to implement timeout, since not supported in IO::Socket::INET
    eval {
        local $SIG{ALRM} = sub { die "alarm\n"; };
        alarm TIMEOUT();
        # Wait for destination until timeout
        $socket = new IO::Socket::INET (
        LocalPort => PORT_SRC(),
        Proto => PROTOCOL(),
        Timeout  => TIMEOUT()
        ) or die "Error opening socket: $!\n";
    
        # read operation on the socket Note size read.
        $socket->recv($data,READ_SIZE_MAX());
    
    
        #get the peerhost and peerport from which recent data was received.
        my $peer_address = $socket->peerhost();
        my $peer_port = $socket->peerport();
        $log->info("($peer_address , $peer_port) received answer from destination");
        # DEBUG, binary data
        #$log->debug("($peer_address , $peer_port) received: $data");
        
        #Close socket
        $socket->close();
        alarm 0;
    };
    if ($@) {
        die unless $@ eq "alarm\n"; # propagate unexpected errors
        # timed out
        $log->error("No answer from destination within time");
        # check if additional output values needed to indicate errror
        exit PACKET_NOT_RECEIVED();
    }

    #########################################################################
    # check received data and output it
    #########################################################################
    
    # decrypt data
    # autentucally decrypt information for Destination
    my $CBCAESDestination = Crypt::CBC->new(
    -key    => $keyDS,
    -header => 'salt',
    -cipher => "Crypt::OpenSSL::AES"
    );
    # add all keys make array
    my $decryptedData = $CBCAESDestination->decrypt("$data");
    
    # DEBUG, binary data
    #$log->debug("Decrypted data: $decryptedData");
    
    # read keys, remove AUTH, keys for all but source
    my @allKeys;
    my $i = 0;
    for($i = 0; $i < $#pathSet; $i++) {
        $log->debug("i is: $i");
        #careful with space seperators
        push(@allKeys, substr($decryptedData, ($i*SYMMETRIC_KEY_SIZE()/8)+$i, (SYMMETRIC_KEY_SIZE()/8)) );
    }
    #note $i has been increased once more, after last key no space
    my $receivedAUTH = substr($decryptedData, ($i*SYMMETRIC_KEY_SIZE()/8)+$i-1 );#read rest
    $log->debug("Read number of keys (start at 0): $#allKeys");
    # DEBUG, binary data
    #$log->debug("Keys: @allKeys");
    #$log->debug("AUTH: $receivedAUTH");
    
    # DEBUG
    my $debugAUTH = bytes::length($AUTH);
    my $debugreceivedAUTH = bytes::length($receivedAUTH);
    $log->debug("AUTH length: $debugAUTH");
    $log->debug("AUTH received length: $debugreceivedAUTH");
    
    # check receivedAUTH
    if($AUTH eq $receivedAUTH) {
        $log->info("Received AUTH verified");
        # output session information
        my $n = $#pathSet + 1;
        print STDOUT "$n\n";            #read by line n
        print STDOUT "$timestamp\n";    #read by line timestamp
        foreach (@pathSet) {            #read by line path set entities
            print STDOUT "$_\n";
        }                               #read by line
        print STDOUT "$destinationid\n"; #read by line destination id within the scheme Note: original destination not needed since already in nfqueue
        
        binmode(STDOUT);
        
        print STDOUT "$sessionid";      #read by size session id
        # DEBUG
        #$log->info("Sessionid ", unpack('H*', "$sessionid"));
        foreach (@pathIndicator) {
            print STDOUT "$_";          #read by size, no spaces path indicator
        }
        # DEBUG
        #$log->info("Output Keys: ");
        foreach (@allKeys) {
            print STDOUT "$_";          #read by size, no spaces all keys in path set order
            #$log->info("\n", unpack('H*', "$_"));
        }
    }
    else {
        $log->error("Received AUTH did not match!");
        #print STDOUT "AUTH did not match";
        exit AUTH_MISSMATCH();
    }
}

#########################################################################
# Read preshared symmetric key, folder presharedKeys must exist.
# 1st arg $debugKey
# 2nd arg $destination
#########################################################################
sub parse_received_data {
    my $received_data = shift;
    my $i;
    my @path;
    my @pathSet;
    my $timestamp;
    my $AUTH;
    my $position;
    my $publicSession;
    my @derivedKeysandSignatures = ();
    
    my $encryptedMatch = ENCRYPTED_AUTH_SIZE()-8;
    if ($received_data =~ /
        #Match current position (delimiter -)
        (\d+)-
        #Match Path
        ((?:(?:$RE{RegIP}{net}{IP4})\s?)+)
    #Match Session Public key
    (-----BEGIN\sRSA\sPUBLIC\sKEY.+-----END\sRSA\sPUBLIC\sKEY-----\s)
    #Match Path Set (delimiter -)
    ((?:(?:$RE{RegIP}{net}{IP4})\s?)+)-
    #Match timestamp
    (\d+)
    #Match AUTH (fixed size)
    (Salted__.{$encryptedMatch})
    /sx)
    {
        $log->debug("matched position: $1");
        $position = $1;
        
        $log->debug("matched path: $2");
        @path = split(/ /, $2);
        
        #$log->debug("matched session pk:\n$3");
        $publicSession = $3;
        
        $log->debug("matched path set: $4");
        @pathSet = split(/ /, $4);
        
        $log->debug("matched path timestamp: $5");
        $timestamp = $5;
        
        #$log->debug("matched path AUTH: $6");
        $AUTH = $6;
        my $sizeAUTH = bytes::length($AUTH);
        $log->debug("Length of AUTH: $sizeAUTH");
    }
    else {
        $log->error("Could not parse input!");
        goto START;
    }
    
    my $sizeInput = bytes::length($received_data);
    # DEBUG
    $log->debug("Length of Input: $sizeInput");
    $log->debug("Last match at: $+[6]");
    
    # extract derived keys and signatures
    @derivedKeysandSignatures = ();
    my $encryptedKeySize = ASYMMETRIC_KEY_SIZE()/8; #Bytes
    $log->debug("EncryptedKeySize is: $encryptedKeySize");
    # Skip the two seperating spaces
    for($i = $+[6]; $i < $sizeInput; $i += (64 + 2 + $encryptedKeySize) ) {
        push(@derivedKeysandSignatures, substr($received_data, $i, $encryptedKeySize) );
        #skip the separating space
        push(@derivedKeysandSignatures, substr($received_data, $i + $encryptedKeySize + 1, 64) );
        #DEBUG
        $log->debug( "Length key read:", bytes::length($derivedKeysandSignatures[0]));
        $log->debug( "Length signature read:", bytes::length($derivedKeysandSignatures[1]));
    }
    #$log->debug( "DerivedKeysandSignatures $#derivedKeysandSignatures:\n@derivedKeysandSignatures");
    # $log->debug( "$#pathSet:", join(", ", @pathSet));
    
    return ($position, \@path, $publicSession, \@pathSet, $timestamp, $AUTH, \@derivedKeysandSignatures);
}


#########################################################################
# Compute sessionid
# 1st arg $publicSession
# 2nd arg @pathSet
# 3rd arg $timestamp
#########################################################################
sub compute_sessionid {
    my $publicSession = shift;
    my $ref = shift;
    my @pathSet = @{$ref};
    my $timestamp = shift;
    # DEBUG
    #return pack('H*', 'ffffffffffffffffffffffff');
    #return pack('H*', 'f0f0f0f0f0f0f0f0f0f0f0f0');
    #return pack('H*', '0123456789abcdef01234567');

    # Generate sessionid
    my $digest = Crypt::Digest::SHA1->new;
    $digest->add("$publicSession", "@pathSet", "$timestamp");
    my $sha1_raw = $digest->digest;
    my $sha1_hex = $digest->hexdigest;
    $log->debug("Full SHA1 for sessionid (hex):\n", $sha1_hex);
    
    #Truncate SHA1 hash of 20 bytes to desired bytes
    return substr( $sha1_raw, 0, SESSIONID_SIZE() );
}


#########################################################################
# Read preshared local signing key, folder presharedKeys must exist.
# 1st arg $debugKey
# 2nd arg $identity FUTURE WORK used to load public keys from others
#########################################################################
sub read_signing_keys {
    my ($pubkey, $privkey);
    my $debugKey = shift;
    #my $identity = shift; #FUTURE WORK needed to load public keys from others
    
    if($debugKey) {
        #"The public key is always 32 octets,
        #the private key is always 64 octets long."
        #Note of course they depend on each other.
        $pubkey =  pack('H*', '14d14d7e89a92abc5e92f63b34fff11607b504bf236675427dbc8735766325b4');
        $privkey = pack('H*', '000ba2edef6308cb9da6653543c4245e16508e69ff6166a2b43a11bf0685537864abaf8ff35659ad2b41d0abe4bed43575229547b3b3710c50594eb2cf8918e6');
        
        $log->debug("Read debug signing keys!");
    }
    else {

        my $file = file('presharedKeys', "localSigningPublic.bin"); #presharedKeys/NAME.bin
        my $file2 = file('presharedKeys', "localSigningPrivate.bin");
        my $file_handle = $file->openr() or die "Can't read $file: $!";
        my $file_handle2 = $file2->openr() or die "Can't read $file: $!";

        $pubkey = $file_handle->getline();
        $privkey = $file_handle2->getline();
        
        $log->debug("Load local signing keys");
    }
    
    return ($pubkey, $privkey);
}


#########################################################################
# Read preshared symmetric key, folder presharedKeys must exist.
# 1st arg $debugKey
# 2nd arg $destination
#########################################################################
sub read_preshared_key {
    $log->debug("Reading preshared key (in sub)");
    my $presharedKey;
    my $debugKey = shift;
    my $destination = shift;
    
    if($debugKey) {
        $presharedKey = DEBUG_SHAREDKEY();
        $log->debug("Read debug preshared key:\n", "$presharedKey");
    }
    else {
        # Preshared keys with destination ID (OSPF router id, unique)
        my $file = file('presharedKeys', "$destination.bin"); #presharedKeys/NAME.key
        
        # Read in the entire contents of a file
        my $content = $file->slurp()or die "Can't read $file: $!";
        
        # openr() returns an IO::File object to read from
        my $file_handle = $file->openr() or die "Can't read $file: $!";
        
        $presharedKey = $file_handle->getline();
        #$log->debug("Read preshared key:\n", "$presharedKey");
    }
    
    return $presharedKey;
}

#########################################################################
# Read local symmetric key
# 1st arg $debugKey
#########################################################################
sub read_local_key {
    $log->debug("Reading local key (in sub)");
    my $localKey;
    my $debugKey = shift;
    
    if($debugKey && !ALWAYS_LOAD_LOCAL_KEY()) {
        $localKey = DEBUG_SHAREDKEY();
        $log->debug("Read debug local key:\n", "$localKey");
    }
    else {
        # Local key
        my $file = file("localKey.bin");
        
        # Read in the entire contents of a file
        my $content = $file->slurp() or die "Can't read $file: $!";
        
        # openr() returns an IO::File object to read from
        my $file_handle = $file->openr() or die "Can't read $file: $!";
        
        $localKey = $file_handle->getline();
        $log->debug("Read local key:\n", "$localKey");
    }
    
    return $localKey;
}


#########################################################################
# Compute paths and corresponding path set and k-shortest d-path set algorithm
# 1st arg $destination (ip, the ospf router id, will be looked up)
#########################################################################
sub calculate_paths_and_path_set {
    my $destinationOriginal = shift;
    my $source = get_my_router_id();
    my @pathSet;
    my @allPaths;
    my @supportLinks;
    my @pathIndicator;
    
    $log->debug("My router id is: $source");
    $log->debug("My original destination is: $destinationOriginal");
   
    
    # Update destination to correct ospf router id
    my %lookup;
    $lookup{ip} = $destinationOriginal;
    get_advertising_router(\%lookup);
    my $destination = $lookup{target_node};
    $log->debug("OSPF router id destination is: $destination");
    
    if ($source eq $destination) {
        $log->info("Destination and Source same: ", "$source $destination\nAbort run.");
        exit(-1);
    }
    
    # build tree out of OSPF database
    my $topo = create_single_graph();
    #$log->debug("The test topo is: ", Dumper($topo));
    $log->debug("Printed topo is: $topo");
    
    #########################################################################
    # k-shortest d-path set algorithm
    #########################################################################
    
    # calculate shortest path with dijkstra
    my @shortestPath = $topo->SP_Dijkstra($source, $destination);
    $log->debug("Shortest Path is: @shortestPath");
    
    # check size
    if ($#shortestPath > MAX_N()) {
        $log->error("No shortest path, cannot support more nodes for path set than ", MAX_N());
        exit -2;
    }
    
    # Create lookup hash for shortest path nodes for O(1) lookup
    # and to order unreliable link towards D (therefore $i+1)
    my %shortestPathHash;
    for my $i (0 .. $#shortestPath)
    {
        $shortestPathHash{$shortestPath[$i]} = ($i+1);
        $log->debug("Create shortest path hash of $shortestPath[$i] as: ", $shortestPathHash{$shortestPath[$i]});
    }
    # calculate unreliable link on shortest path
    my @unreliableLink = get_unreliable_link(\@shortestPath, \%shortestPathHash);
    $log->debug("unreliable link is: @unreliableLink");
    
    #remove unreliable link from topo
    my $topo_new = $topo->delete_edge($unreliableLink[0], $unreliableLink[1]);
    #DEBUG
    #$log->debug("The new topo is: ", Dumper($topo_new));
    $log->debug("Printed new topo is: $topo_new");
    
    my @backupPath;
    # check if graph connected, complexity is ok (from docu):
    # For an undirected graph, return true if the vertices are in the same connected component.
    # If the graph has been created with a true unionfind parameter, the time complexity is (essentially) O(1), otherwise O(V log V)
    my $isConnected = $topo_new->same_connected_components($source, $destination);
    if ($isConnected && CALC_BACKUP_PATH()) {
        $log->debug("Source and destination are connected in new graph, compute backup path");
        
        #Get k shortest paths
        my ($ref_one, $ref_two) = get_kshortest_paths($topo_new, $source,
                $destination, K_SHORTEST_PATH_ALG());
        my @kshortestPaths = @{$ref_one};
        my @pathCosts = @{$ref_two}; #note: currently not needed to optimize.
        
        
        # only if we found any possible backup path
        if (@kshortestPaths) {
            # minimize over the k-shortest paths to find the least number of additional path set entitites d
            # Note: To do this here is more generic but little slower than right after
            # the eppstein or yen algorithm
            $log->debug("Minimizing over path set size to choose backup path");
            @backupPath = @{$kshortestPaths[0]};
            #$log->debug("Choose initial backup path: @backupPath");
            my @minimal = uniq (@shortestPath, @backupPath);
            foreach (@kshortestPaths) {
                my @current = @{$_};
                #$log->debug("Current potential backup path: @current");
                my @tmp = uniq (@shortestPath, @current);
                $log->debug(" Current path set size: $#tmp");
                #note: desecending cost ordering ensures that if the number
                #of entities is the same, the path with the lowest cost is first
                if ($#tmp < $#minimal) {
                    @minimal = @tmp;
                    @backupPath = @current;
                    $log->debug(" Choose new backup path: @backupPath");
                }
            }
            # check size
            my @check = uniq (@shortestPath, @backupPath);
            if ($#check > MAX_N()) {
                $log->info("Dropping backup path, cannot support more nodes for path set than ", MAX_N());
                @backupPath = ();
            }
            else {
                $log->debug("Calculate support links");
                # check where to start, only add links to nodes on
                # backup path after fork of shortest path and backup path
                # i.e. if unreliable link start node is contained on backup path,
                # then begin checking two nodes after it (since first node
                # after unreliable link then always connceted) or
                # if the path is distinct, start with the second node on the shortest path
                # NOTE: fork can be before unreliable link starting node
                my $start = 1;
                for my $i (0 .. $#backupPath)
                {
                    if ($i <= $#shortestPath && $backupPath[$i] ne $shortestPath[$i]) {
                        $start = $i;
                        $log->debug("Fork of shortest path and backup path at $i stop at: $start");
                        last; # leave loop, we found start.
                    }
                    elsif ($backupPath[$i] eq $unreliableLink[0]) {
                        #if fork is at unreliable link start, start one later such that the link is not added twice in path indicator
                        $start = $i+2;
                        $log->debug("Unreliable link on backup path at $i stop at: $start");
                        last; # leave loop, we found start.
                    }
                }
                # Add support links, links connecting to the end of
                # the backup path are preferred, therefore traverse in reverse order
                for my $i (reverse $start..$#backupPath) {
                    my $current = $backupPath[$i];
                    $log->debug(" Currently looking at $current");
                    # note ordering of $unreliablelLink makes sure
                    # the first node is the node before the unreliable link
                    if ($topo->has_edge($unreliableLink[0], $current)) {
                        if ($#supportLinks < MAX_SUPPORT_LINKS()) {
                            my @newSupportLink = ($unreliableLink[0], $current);
                            push(@supportLinks, \@newSupportLink);
                            $log->debug(" Add support link $unreliableLink[0] -> $current");
                        }
                        else {
                            $log->debug(" Maximal number of support links reached!");
                        }
                    }
                }
            }
        }
        elsif (CALC_BACKUP_PATH()) {
            $log->debug("No k shortest Path within threshold. No backup path.");
        }
        else {
            $log->debug("Backup Path Calculation deactivated.");
        }
    }
    else {
        $log->debug("Source and Destination not connected. No backup path.");
    }
   
    # Set final allPaths and pathSet
    if (@backupPath) {
        $log->debug("Backup Path is: @backupPath");
        
        @allPaths = ([@shortestPath], [@backupPath]);
        @pathSet = uniq (@shortestPath, @backupPath);
    }
    else {
        #$log->debug("No backup path.");
        @allPaths = ([@shortestPath]);
        @pathSet = uniq (@shortestPath);
    }
    
    # cunstructed path set: union of the two path's identities
    $log->debug("Path set is:", "@pathSet");
    $log->debug("All paths is:", "@allPaths");
    
    # Calculate Path Indicator in bit representation as vectors for each node!
    $log->debug("Calculate Path Indicator");
    # init hash table for node labeling / pointers
    # init offsets
    # init pathIndicator
    # assume 16 bits per node path indicator, assume 4 bits per pointer / label
    my @currentOffset;
    my %nodePointers;
    for my $i (0 .. $#pathSet)
    {
        $nodePointers{$pathSet[$i]} = $i;
        $log->debug(" Create node pointer of $pathSet[$i] as: ", $nodePointers{$pathSet[$i]});
        $currentOffset[$i] = 0;
        #init with 16 bits
        my $current;
        vec($current,  0, PATH_INDICATOR_SIZE()*4) = 0; #0x00..
        push(@pathIndicator, $current);
    }
    #init with shortest path as default (destination has no indicator)
    for my $i (0 .. ($#shortestPath-1))
    {
        # shortest path labels correspond to labeling in pathSet by construction
        # all offsets are 0 here
        vec($pathIndicator[$i], 0, 4) = $i+1;
        #$nodePointers{$shortestPath[$i]}
        $log->debug(" initialized indicator [entity $i]: ", unpack("h*", $pathIndicator[$i]) );
        $currentOffset[$i]++;
    }
    # add backup path
    if (@backupPath) {
        for my $i (0 .. ($#backupPath-1))
        {
            # only add additional links if shortest path reused
            my $currentPointer = $nodePointers{$backupPath[$i]};
            my $nextPointer = $nodePointers{$backupPath[$i+1]};
            if (vec($pathIndicator[$currentPointer], 0, 4) != $nextPointer) {
                # new next node, add to indicator
                vec($pathIndicator[$currentPointer],
                $currentOffset[$currentPointer], 4) = $nextPointer;
                $currentOffset[$currentPointer]++;
                $log->debug(" changed indicator [entity $currentPointer]: ",
                unpack("h*", $pathIndicator[$currentPointer]) );
            }
        }
    }
    # add support links
    $log->debug(" add support links");
    if (@supportLinks) {
        foreach (@supportLinks)
        {
            
            my @currentLink = @{ $_ };
            # only add additional links if shortest path reused
            #always node before unreliable link
            my $currentPointer = $nodePointers{$currentLink[0]};
            #connected node on backup path
            my $nextPointer = $nodePointers{$currentLink[1]};
            
            # add to indicator
            # Note: checked number of support links already before
            vec($pathIndicator[$currentPointer],
            $currentOffset[$currentPointer], 4) = $nextPointer;
            $currentOffset[$currentPointer]++;
            $log->debug(" changed indicator [entity $currentPointer]: ",
            unpack("h*", $pathIndicator[$currentPointer]) );
        }
    }
    # DEBUG
    $log->debug("Created Path Indicator (hex):");
    for my $i (0 .. ($#pathIndicator))
    {
        $log->debug(" [entity $i]: ",
        unpack("h*", $pathIndicator[$i]) );
    }
    $log->debug("Created Path Indicator (bin):");
    for my $i (0 .. ($#pathIndicator))
    {
        $log->debug(" [entity $i]: ",
        unpack("b*", $pathIndicator[$i]) );
    }
    
    # DEBUG
    #$pathSet[0] = '192.168.1.1';
    #$pathSet[1] = '192.168.1.2';
    #$pathSet[2] = '192.168.2.2';
    # DEBUG
    #@allPaths = @pathSet;
    #$log->debug("Path set debug is:", "@pathSet");
    
    # return pathSet, paths and path indicator, destinationid return array references!
    return (\@pathSet, \@allPaths, \@pathIndicator, $destination);
}


#########################################################################
# Compute k shortest paths and costs with eppstein or yen's algorithm
# 1st arg $topo
# 2nd arg $source
# 3rd arg $destination
# 4th arg $kshortestPathAlg - Algorithm to use: 'yen' or 'eppstein'
# Important: Source and destination need to be in the same component!
#########################################################################
sub get_kshortest_paths {
    my $topo = shift;
    my $source = shift;
    my $destination = shift;
    my $kshortestPathAlg = shift;
    my @kshortestPaths;
    my @pathCosts;
    # Get components of source and destination, i.e. nodes for our graph
    my $compontentsIndex = $topo->connected_component_by_vertex($source);
    my @nodes = $topo->connected_component_by_index($compontentsIndex);
    # DEBUG
    $log->debug("Connected components new graph: @nodes");
    #my @cc = $topo->connected_components();
    #$log->debug("Connected components new graph: @cc");
    #$log->debug("Connected components Dump: ", Dumper(@cc));
    
    # Create lookup hash for mapping node ospf router id to node id (number)
    my %nodesHash;
    for my $i (0 .. $#nodes)
    {
        $nodesHash{$nodes[$i]} = $i;
        $log->debug("Create node mapping from node $nodes[$i] to id: $i");
    }
    
    # Variables needed for the c programs
    my $n = $#nodes + 1;
    my $m = 0;
    my $s = $nodesHash{$source};
    my $t = $nodesHash{$destination};
    # Set k to n unless its smaller than MIN_K or bigger than threshold MAX_K
    my $k = ( $n < MAX_K() ) ? (($n < MIN_K()) ? MIN_K() : $n) : MAX_K();
    
    my @from;
    my @to;
    my @costs;
    
    # parse and translate links
    my @allLinks = split ',', "$topo";
    foreach (@allLinks)
    {
        my @line = split '=', "$_";
        my $hashOne = $nodesHash{$line[0]};
        my $hashTwo = $nodesHash{$line[1]};
        
        # DEBU
        if (! defined $hashOne || ! defined $hashTwo) {
            $log->debug("Nodes not part of component with source and destination");
        }
        elsif ($#line != 1) {
            $log->error("Error while parsing backup path tree!");
        }
        else {
            $m += 2;
            my $currentCost = $topo->get_edge_weight($line[0], $line[1]);
            
            #insert both directions
            push(@costs, $currentCost);
            push(@costs, $currentCost);
            push(@from, $hashOne);
            push(@to, $hashTwo);
            push(@from, $hashTwo);
            push(@to, $hashOne);
        }
    }
    
    #DEBUG
    $log->debug("Translated following tree for k shortest path algorithm:");
    for my $i (0 .. $#costs)
    {
        $log->debug("$from[$i] -> $to[$i] cost: $costs[$i]");
    }
    
    #call k-shortest path algorithm
    if ($kshortestPathAlg eq 'eppstein') {
        $log->debug("Calling Eppstein's Algorithm");
        # Note: Careful, Eppstein usually gives always $k shortest path's back
        # since it will reuse nodes and edges -> careful with max k.
        # Format used by the Eppstein algorithm
        # Note: indexing starts at 1, different from perl, need to adapt.
        # Example:
        # n 6
        # m 18
        # s 1
        # t 6
        # a 1 2 100
        # a 1 3 10
        # a 2 3 100
        # a 2 4 100
        # a 2 1 100
        # a 3 1 10
        # a 3 2 100
        # a 3 4 10
        # a 3 5 100
        # a 4 2 100
        # a 4 3 10
        # a 4 5 100
        # a 4 6 10
        # a 5 3 100
        # a 5 4 100
        # a 5 6 100
        # a 6 4 10
        # a 6 5 100
        # q
        my $pid = open3(\*CHLD_IN, \*CHLD_OUT, 0, "./EPPSTEIN stdin $k -paths");
        
        my $tmps = $s+1;
        my $tmpt = $t+1;
        print CHLD_IN "n $n\n";
        print CHLD_IN "m $m\n";
        print CHLD_IN "s $tmps\n";
        print CHLD_IN "t $tmpt\n";

        for my $i (0 .. $#costs)
        {
            my $tmpfrom = $from[$i]+1;
            my $tmpto = $to[$i]+1;
            print CHLD_IN "a $tmpfrom $tmpto $costs[$i]\n";
        }
        print CHLD_IN "q\n";# all input done
        
        #get output from child #in case of problems use select method
        my $answer;
        my $c = undef;
        my @current;
        #neeed to read all lines
        while(<CHLD_OUT>){
            $answer .= $_;#DEBUG
            my $line = $_;
            if ($line =~ /-/) {
                @current = split '-', "$line";
                #remove empty element
                pop @current;
                #shift back node labeling
                grep(($_)--, @current);
                #$log->debug("My current path $#current: @current");
            }
            elsif ($line =~ /Cost: (\d+)/) {
                $c = $1;#current path costs
                if ($c >= COST_THRESHOLD()) {
                    #reached threshold, stop reading.
                    last;
                }
                #$log->debug("My current path: @current");
                #convert back to original node names
                @current = grep(s/(\d)+/$nodes[$1]/, @current);
                my @copyCurrent = @current;
                push(@pathCosts, $c);
                push(@kshortestPaths, \@copyCurrent);
                $log->debug("Added path: @copyCurrent");
            }
        }
        waitpid($pid, 0 );
        my $child_exit_status = $? >> 8;
        
        if($child_exit_status) {
            $log->error("Eppstein's Algorithm returned error code $child_exit_status!");
        }
        $log->debug("Answer from Eppstein's Algorithm: return value: $child_exit_status\n$answer");
    }
    else {
        # Call yen's algorithm
        $log->debug("Calling Yen's Algorithm");
        # Note: If there are less than $k shortest paths, yen will give back all.
        # Format used by Yen's algorithm
        # Note: indexing starts at 0, as in perl, default
        # 0     #like s-1 from Eppstein
        # 5     #like t-1 from Eppstein
        # 6     #like k from Eppstein
        # 6     #like n from Eppstein
        #
        # 0 1 100
        # 0 2 10
        # 1 2 100
        # 1 3 100
        # 1 0 100
        # 2 0 10
        # 2 1 100
        # 2 3 10
        # 2 4 100
        # 3 1 100
        # 3 2 10
        # 3 4 100
        # 3 5 10
        # 4 2 100
        # 4 3 100
        # 4 5 100
        # 5 3 10
        # 5 4 100
        #if \*CHLD_ERR is 0, STDERR is sent to STDOUT
        my $pid = open3(\*CHLD_IN, \*CHLD_OUT, 0, './yen');
        
        print CHLD_IN "$s\n";
        print CHLD_IN "$t\n";
        print CHLD_IN "$k\n";
        print CHLD_IN "$n\n\n";
        for my $i (0 .. $#costs)
        {
            print CHLD_IN "$from[$i] $to[$i] $costs[$i]\n";
        }
        print CHLD_IN "\0";# all input done
        
        #get output from child #in case of problems use select method
        my $answer;
        my $c = undef;
        #my $l = undef;
        #neeed to read all lines
        while(<CHLD_OUT>){
            $answer .= $_;#DEBUG
            my $line = $_;
            if ($line =~ /Cost: (\d+) Length: (\d+)/) {
                $c = $1;#current path costs
                #$l = $2;#current path length
            }
            elsif ($line =~ /->/) {
                if ($c >= COST_THRESHOLD()) {
                    #reached threshold, stop reading.
                    last;
                }
                my @current = split '->', "$line";
                #remove empty element
                pop @current;
                #$log->debug("My current path: @current");
                #convert back to original node names
                @current = grep(s/(\d)+/$nodes[$1]/, @current);
                push(@pathCosts, $c);
                push(@kshortestPaths, \@current);
                $log->debug("Added path: @current");
            }
        }
        waitpid($pid, 0 );
        my $child_exit_status = $? >> 8;
        
        if($child_exit_status) {
            $log->error("Yen's Algorithm returned error code $child_exit_status!");
        }
        $log->debug("Answer from Yen's Algorithm: return value: $child_exit_status\n$answer");
    }
    
    return (\@kshortestPaths, \@pathCosts);
}


#########################################################################
# get unreliable link on shortest path
# 1st arg \@shortestPath
#########################################################################
sub get_unreliable_link {
    my $shortestPathRef = shift;
    my @shortestPath = @{$shortestPathRef};
    my $shortestPathHashRef = shift;
    my %shortestPathHash = %{$shortestPathHashRef};
    my @unreliableLink = undef;
    my $lowestWeight = 2;
    my $lowestCost = undef;
    
    my $from;
    my $to;
    my $cost;
    my $weight;
    
    open(STATUSFILE, $tunnel_final_state);
    # DEBUG
    #open(STATUSFILE, "testdata/tunnel_link_by_router_id.txt");
    while(<STATUSFILE>){
        my $line = $_;
        
        # read current tunnel status;
        if ($line =~ /($RE{RegIP}{net}{IP4}) - ($RE{RegIP}{net}{IP4}) : (\d+) : ([\d\.]+)/) {
            $from = $1;
            $to = $2;
            $cost = $3;
            $weight = $4;
            $log->debug("Tunnel status matched: $from -> $to cost: $cost weight: $weight");
        }
        else {
            $log->error("Could not parse tunnel status file!");
        }
        # check if current ids in shortest path contained
        # Slower alternative (for big lists) check if in list:
        # $from ~~ @shortestPath && $to ~~ @shortestPath
        if ($shortestPathHash{"$from"} && $shortestPathHash{"$to"}) {
            # take most unreliable one
            if ($lowestWeight > $weight) {
                $lowestWeight = $weight;
                $lowestCost = $cost;
                $unreliableLink[0] = $from;
                $unreliableLink[1] = $to;
                $log->debug("Set unreliable link to: @unreliableLink");
            }
            # if same weight consider path with lower costs
            # adapt if multiple tunnels between same nodes -> choose smaller cost
            elsif ($lowestWeight == $weight && $lowestCost > $cost) {
                $lowestWeight = $weight;
                $lowestCost = $cost;
                $unreliableLink[0] = $from;
                $unreliableLink[1] = $to;
                $log->debug("Set unreliable link to: @unreliableLink");
            }
        }
    }
    close(STATUSFILE);
    
    if (! @unreliableLink ) {
        # otherwise take any one, e.g., the last one
        $unreliableLink[0] = $shortestPath[-2];
        $unreliableLink[1] = $shortestPath[-1];
        $log->debug("Unreliable link was undefined");
        # FUTURE WORK could use heuristic otherwise
    }
    else {
        # check if the unreliablel link is towards D
        # make use of the increasing hash on the path towards D
        if (! ($shortestPathHash{$unreliableLink[0]} < $shortestPathHash{$unreliableLink[1]}) ) {
            # wrong order, swap it
            my $tmp = $unreliableLink[0];
            $unreliableLink[0] = $unreliableLink[1];
            $unreliableLink[1] = $tmp;
        }
    }
    
    return @unreliableLink;
}


#########################################################################
# get which router advertises a certain network
# 1st arg \%lookup - the ospf router id will be looked up
# Use:
# my %lookup;
# $lookup{ip} = $ip_adr;
#########################################################################
sub get_advertising_router {
    my $lookup = shift;
    my $ip = NetAddr::IP->new($lookup->{ip});
    
    my %routers = get_adv_routers();
    
    my $bestmatch = NetAddr::IP->new('0.0.0.0/0');
    my $wan_traffic = 0;
    for (keys %routers) {
        my $net = NetAddr::IP->new($_);
        if ( $ip->within($net) && $net->masklen() > $bestmatch->masklen() ) {
            $bestmatch = $net;
            $wan_traffic = 1;
        }
    }
    $lookup->{wan_traffic} = $wan_traffic;
    $lookup->{target_node} = $routers{$bestmatch};
}


#########################################################################
# get router advertising a certain network
# - called internally by get_advertising_router
#########################################################################
sub get_adv_routers {
    my %routers;
    my $external_section = 0;
    open(VTY_NETWORKS, "$VTYSH -e '$CMD_DATABASE'|");
    # DEBUG
    #open(VTY_NETWORKS, "testdata/ospfdatabasedemo.txt");
    while(<VTY_NETWORKS>) {
        my $line = $_;
        
        next until ($external_section || /AS External Link States/);
        $external_section = 1;
        
        if ($line =~ m{
            $RE{RegIP}{net}{IP4}\s+          # Link ID
            ($RE{RegIP}{net}{IP4})\s+        # ADV Router ($1)
            \d+\s+                          # Age
            0x\w+\s+                        # Seq#
            0x\w+\s+                        # ChSum
            \w\d\ ($RE{RegIP}{net}{IP4}/\d+) # Route ($2)
        }x ) {
            my $router = $1;
            my $network = $2;
            
            $routers{$network} = $router;
            
        }
    }
    return %routers;
}


#########################################################################
# create single topology graph with weighted edges
# built out of OSPF database
# we abstract the tree to have one link at most from each node to each one
# if there are multiple ones we take the minimum
#########################################################################
sub create_single_graph {
    my ($gre2host, $tunnels, $nodes_ref) = parse_vty_router_info();
    my @nodes    = @{$nodes_ref};
    
    my $topo     = Graph::Undirected->new;
    $topo->add_vertices(@nodes);
    
    for my $area (keys %{$tunnels}) {
        for my $tunnel (keys %{$tunnels->{$area}}) {
            my ($here, $there) = split ' - ', $tunnel;
            my $this_node = $gre2host->{$area}{$here};
            my $that_node = $gre2host->{$area}{$there};
            
            # If the ospf database did not converge yet it is possible
            # that router A announces a tunnel to router B, but we did not
            # receive the announcements from router B yet
            next if (! defined $this_node or ! defined $that_node);
            
            $topo->add_weighted_edge( $this_node, $that_node,
            min
            grep { defined $_ }
            ( $tunnels->{$area}{$tunnel}{cost},
            $topo->get_edge_weight($this_node, $that_node) )
            );
        }
    }
    return $topo;
}


#########################################################################
# parse router info into hashes (internal)
#########################################################################
sub parse_vty_router_info {
    my $vty_output = get_vtysh_router_info();
    
    my %gre2host;
    my %tunnels;
    my @nodes;
    
    my $area_id;
    my $router_id = undef;
    my $link_id;
    
    # Helper hash
    my %transit_networks;
    
    for my $line (split /\n/, $vty_output) {
        
        if ($line =~ /^$/) {
            $router_id = undef;
            next;
        }
        
        # match area header
        if ($line =~ /Router Link States \(Area ($RE{RegIP}{net}{IP4})\)/) {
            $area_id = $1;
        }
        # match router id header
        elsif ($line =~ /LS Type: router-LSA.*Advertising Router: ($RE{RegIP}{net}{IP4})/){
            $router_id = $1;
            $gre2host{$area_id}{$router_id} = $router_id;
            push (@nodes, $1);
        }
        elsif (defined $router_id &&
        $line =~ m{
            \QLink connected to: another Router (point-to-point)\E.*           # idenfifier
            \Q(Link ID) Neighboring Router ID: \E($RE{RegIP}{net}{IP4}).*       # $1: peer gre
            \Q(Link Data) Router Interface address: \E($RE{RegIP}{net}{IP4}).*  # $2: local gre
            \QMetric: \E(\d+)$                                                 # $3: metric/cost
        }x
        ) {
            $gre2host{$area_id}{$2} = $router_id;
            $tunnels{$area_id}{"$2 - $1"}{cost} = $3;
        }
        elsif (defined $router_id &&
        $line =~ m{
            \QLink connected to: a Transit Network\E.*                         # idenfifier
            \Q(Link ID) Designated Router address: \E($RE{RegIP}{net}{IP4}).*   # $1: DR address
            \Q(Link Data) Router Interface address: \E($RE{RegIP}{net}{IP4}).*  # $2: local address
            \QMetric: \E(\d+)$                                                 # $3: metric/cost
        }x
        ) {
            my $DR_id = $1;
            my $peer_id = $2;
            my $cost = $3;
            
            $gre2host{$area_id}{$peer_id} = $router_id;
            $transit_networks{$DR_id}{cost} = $cost;
            if (exists ($transit_networks{$DR_id}{peers})) {
                push ( @{$transit_networks{$DR_id}{peers}}, $peer_id );
            }
            else {
                $transit_networks{$DR_id}{peers} = [$peer_id];
            }
        }
        
    }
    
    # create links from transit networks:
    for my $network (keys %transit_networks) {
        my $cost = $transit_networks{$network}{cost};
        my @members = @{$transit_networks{$network}{peers}};
        while (@members) {
            my $start = shift @members;
            for my $end (@members) {
                $tunnels{$area_id}{"$start - $end"}{cost} = $cost;
                $tunnels{$area_id}{"$start - $end"}{transit} = 1;
            }
        }
    }
    
    return (\%gre2host, \%tunnels, \@nodes);
}


#########################################################################
# get local router id
#########################################################################
sub get_my_router_id {
    my $router_id = undef;
    
    open(VTY, "$VTYSH -c 'sh ip ospf'|");
    while(<VTY>) {
        if (/OSPF Routing Process, Router ID: ($RE{RegIP}{net}{IP4})/){
            $router_id = $1;
            last;
        }
    }
    close(VTY);
    # DEBUG OSPF Routing Process, Router ID: 213.156.234.1
    # DEBUG
    # $router_id = '213.156.234.1';
    return $router_id;
}


#########################################################################
# get vtysh router output, rearange blocks to single lines (internal)
#########################################################################
sub get_vtysh_router_info {
    my $vty_router_output = '';
    open(VTY_TOPO, "$VTYSH -e '$CMD_ROUTER'|");
    # DEBUG
    #open(VTY_TOPO, "testdata/ospfrouterdatabasedemo.txt");
     while(<VTY_TOPO>){
        my $line = $_;
        
        # skip uninteresting lines
        next if ($line =~ /Flags:|LS age:|Options:|LS Flags:|Checksum:|LS Seq Number:|Length:/);
        
        # remove linebreaks within blocks
        if ($line !~ /^\s*$/) {
            $line =~ s/\s*$//;
        }
        
        # write structured output into variable
        $vty_router_output .= $line;
    }
    close(VTY_TOPO);
    
    return $vty_router_output;
}

#########################################################################
# hash with info about active tunnels to neighbors (internal)
# Note: make simplification: map 1 peer id to 1 gre dst!
#########################################################################
sub get_neighbours {
    my @peers;
    my @destinations;
    #my @timestamps;
    
    open(VTY_NEIGH, "$VTYSH -c '$CMD_NEIGHBOR'|");
    # DEBUG
    #open(VTY_NEIGH, "testdata/ospfneighbordemo.txt");
    #only match lines with state Full/DROther which are really up
    while(<VTY_NEIGH>){
        if (/($RE{RegIP}{net}{IP4}).*Full\/DROther\s*(.+)\s+($RE{RegIP}{net}{IP4})\s.*/) {
            my $peer      = $1;
            my $gre_dst   = $3;
            my $timestamp = $2;
            #my $interface = $3;
            #my $gre_src   = $4;
            
            #my $seconds = 0;
            #parse timestamp
            #if ($timestamp =~ /(\d+)m(\d+)s/ ) {
            #    $seconds += $1 * 60;
            #    $seconds += $2;
            #}
            #elsif ($timestamp =~ /(\d+)s/ ) {
            #    $seconds += $1;
            #}
            #else {
            #    $log->error("Could not convert timestamp!");
            #    exit(-1);
            #}
            $log->debug("Matched $peer to dst $gre_dst");
            
            push(@peers, $peer);
            push(@destinations, $gre_dst);
            #push(@timestamps, $seconds);
        }
    }
    close(VTY_NEIGH);

    return (\@peers, \@destinations);
}


#########################################################################
# init logger
# 1st arg $debug
# 2nd arg $isServer
#########################################################################
sub init_logger {
    my %config;
    my $scriptname = 'sessionSetup';
    my $debug = shift;
    my $isServer = shift;
    my $logfile = $isServer ? "Server$LOGFILE_BASE.log" : "$LOGFILE_BASE.log";

    $config{'log4perl.rootLogger'} = $debug ? 'DEBUG, SCREEN' : 'INFO, LOGFILE';
    $config{'log4perl.appender.LOGFILE'}                           = 'Log::Log4perl::Appender::File';
    $config{'log4perl.appender.LOGFILE.filename'}                  = $logfile;
    $config{'log4perl.appender.LOGFILE.mode'}                      = 'append';
    $config{'log4perl.appender.LOGFILE.layout'}                    = 'PatternLayout';
    $config{'log4perl.appender.LOGFILE.layout.ConversionPattern'}  = "%d $scriptname\[%P] %p %m%n";
    $config{'log4perl.appender.LOGFILE.Threshold'}                 = 'INFO';#Note: can add DEBUG here if needed
    
    $config{'log4perl.appender.SCREEN.Threshold'}                  = 'DEBUG';
    $config{'log4perl.appender.SCREEN'}                            = 'Log::Log4perl::Appender::Screen';
    $config{'log4perl.appender.SCREEN.layout'}                     = 'PatternLayout'; #SimpleLayout
    $config{'log4perl.appender.SCREEN.layout.ConversionPattern'}   = "%d %p %m%n";
    
    Log::Log4perl::init(\%config);
    Log::Any::Adapter->set('Log::Log4perl');
    
    my $log = Log::Any->get_logger();
    return $log;
}