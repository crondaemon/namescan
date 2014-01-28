
namescan
========

Massive DNS open relay scanner

[![Build Status](https://travis-ci.org/crondaemon/namescan.png?branch=master)](https://travis-ci.org/crondaemon/namescan)

Namescan is a massive port scanner designed specifically for finding open relays.
An open relay is a DNS server that makes queries on behalf of another host.
When it makes them for any IP on the Internet, it is called a open relay.

Namescan works in a very similar way to `scanrand`, `zmap` or `masscan`. But
while they are port scanners, namescan is an application scanner. It doesn't
just checks that the port is open, but makes a recursive query for a custom
domain and checks for the answer.

It can also spoof the source address, making it the actual tool for a complete
DNS reflection attack.

COMPILATION
===========
To compile, just issue the following commands:

    autoreconf -i
    ./configure
    make

USAGE
=====

    namescan 0.1.2 - massive DNS scanner

    Usage: ./namescan [-i <iface>] [-v] [-s <source>] [-d <delay>] [-t <timeout>] [-o <outfile>]
           [-n <domain name>] [-q <type>] [-c <class>] [-r] [-l <level>] [-e] <addresses to scan>

 * -i: the interface to use. If not specified, the first available interface will be used
 * -v: verbose mode
 * -s: the source IP address to use. Default: the current interface IP.
 * -d: delay between packets. Deafault: 0.
 * -t: timeout after last probe. Default: 3 secs.
 * -o: optional output file for results.
 * -n: optional domain name to probe. Default: www.test.com.
 * -q: query type. Default: 1.
 * -c query class. Default: 1.
 * -r: do not randomize targets.
 * -l: show only relays that are above this amplification ratio.
 * -e: do not add EDNS0 record
 * ip address(es) to scan. See below.

The addresses to scan can be specified as a comma-separated list of CIDR addresses.
Example: `8.8.8.8/24,9.9.9.9/16`, or `8.8.4.4`.
