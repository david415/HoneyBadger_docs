
HoneyBadger
===========

.. image:: images/honey_badger-white-sm-1.png
|
.. image:: https://drone.io/github.com/david415/HoneyBadger/status.png
  :target: https://drone.io/github.com/david415/HoneyBadger/latest

.. image:: https://coveralls.io/repos/david415/HoneyBadger/badge.svg?branch=master
  :target: https://coveralls.io/r/david415/HoneyBadger?branch=master 

.. image:: https://api.flattr.com/button/flattr-badge-large.png
  :target: https://flattr.com/submit/auto?user_id=david415&url=https%3A%2F%2Fgithub.com%2Fdavid415%2FHoneyBadger
|

**TCP attack inquisitor and 0-day catcher.**

HoneyBadger is a comprehensive TCP stream analysis tool for detecting and recording TCP attacks.
HoneyBadger includes a variety of TCP stream injections attacks which will prove that the TCP attack detection is reliable.
HoneyBadger is modern software written in Golang to deal with TCP's very olde security issues.
It is free software, using the GPLv3 and the source code is available on github:

* https://github.com/david415/HoneyBadger


development status
------------------

HoneyBadger is useable right now... and I'm sure there are bugs.
We'd like to fix these problems; we've got an issue tracker that you
can use to submit bug reports and feature requests!

https://github.com/david415/HoneyBadger/issues


what does HoneyBadger do and **not** do?
----------------------------------------

HoneyBadger detects TCP injection attack attempts AND cannot know if an attack was successful.
However, I suspect that in the wild TCP attacks will have differing TTLs and other clues that
will help us determine if the attack was successful or not.

HoneyBadger does NOT do what snort and bro do. Nor does honeybadger do what wireshark does. HoneyBadger is a passively sniffing TCP protocol analyzer whose **ONLY** purpose in life is to detect (and optionally record) TCP injection attacks.


how do i use this thing?
------------------------

I will explain each commandline options and show usage examples below.

honeybadger usage::

 $ ./honeyBadger --help
 Usage of ./honeyBadger:
  -connection_max_buffer=0: 
 Max packets to buffer for a single connection before skipping over a gap in data
 and continuing to stream the connection after the buffer.  If zero or less, this
 is infinite.
  -detect_coalesce_injection=true: Detect coalesce injection attacks
  -detect_hijack=true: Detect handshake hijack attacks
  -detect_injection=true: Detect injection attacks
  -f="tcp": BPF filter for pcap
  -i="eth0": Interface to get packets from
  -l="honeyBadger-logs": log directory
  -log_packets=false: if set to true then log all packets for each tracked TCP connection
  -max_concurrent_connections=0: Maximum number of concurrent connection to track.
  -max_ring_packets=40: Max packets per connection stream ring buffer
  -metadata_attack_log=true: if set to true then attack reports will only include metadata
  -s=65536: SnapLen for pcap packet capture
  -tcp_idle_timeout=5m0s: tcp idle timeout duration
  -total_max_buffer=0: 
 Max packets to buffer total before skipping over gaps in connections and
 continuing to stream connection data.  If zero or less, this is infinite
  -w="3s": timeout for reading packets off the wire

  
my remarks about each of these options:
  
- **packet capture options:** Options '-f' and '-i' are used to determine which packets to pay attention to. Currently honeybadger only supports sniffing one network interface. We've got plans to remove the libpcap dependency so in that case the '-f' filter argument would go away. '-w' and '-s' are relevant here, you probably want to use the default options.
  
- **logging options:** you must specify a logging directory using '-l'. pcap logging is off by default. If you set -log_packets= to true then honeybadger will write one pcap file per connection. Upon connection close honeybadger will delete the pcap logfile unless a TCP attack was detected. **warning**: this will cause lots of filesystem churn when sniffing high traffic interfaces. If you are using Linux then I suggest turning off swap and using a reasonably sized tmpfs for the logs directory. By default honeybadger write metadata-only logs which will NOT contain any packet payload data but will have various sensitive information about attack attempts such as: source and destination IP addresses and TCP ports, the type of TCP injection attack (there are several), time of the attack, TCP Sequence number boundaries of the injection. If you set -metadata_attack_log=false then honeybadger will log the attack packet payload AND the stream overlap.

- **resource boundary options:** '-connection_max_buffer' and '-total_max_buffer' are used to limit the amount of page-cache pages that honeybadger can use for storing and reordering out-of-order-packets (much like TCP's mbuf datastructure). '-tcp_idle_timeout' is important as a stop-gap measure to prevent us from tracking connections that may have been closed without our knowing. '-max_ring_packets' is very important to set appropriately; it determines the size of the TCP reassembly ring buffer. This ring buffer is utilized for the retrospective analysis that allows us to determine if a given packet overlaps with previously reassembled stream segments. I estimate that this ring buffer should be set to a size that is roughly equivalent to the TCP window size of the connection... but maybe someone can help us pick a better heuristic? I usually set it to 40 and it works OK.


how does HoneyBadger work?
==========================


data flow
---------

HoneyBadger passively reads packets off a network interface or a pcap file and if detection is triggered writes
TCP attack reports, pcap packet log files and reasembled TCP streams.

Here's a data flow diagram that gives the basic idea of passively sniffing:

.. image:: images/honeybadger_dfd1.png
|

TCP injection attacks
---------------------

1. handshake hijack: the attacker responds to a SYN packet with their SYN/ACK packet before the legit server.

2. segment veto: the injected packet(s) are the exact same size as those sent out by the legit party. Client and server remain in sync.

3. sloppy injection: the injected packet(s) are different sizes than that of the legit party. Client and server fall out of sync.

4. out-of-order coalesce injection: injected packets are ahead of the next sequence. Injection of data takes place during coalescence.

Each of these TCP attacks are really broader categories of attack... for instance sloppy injection that gradually brings client and server back
into sequence synchronization.


attack detection
----------------

The Handshake hijack attack is a very well known TCP injection attack... and it's very simple to detect once you can track the state changes of the TCP handshake... so I won't bother explaining it here. Segment veto and sloppy injection attacks are detected by means of a retrospective analysis.
The endpoint of the TCP connection that receives the attack will also receive a packet from the legitimate
connection party. That packet's TCP segment will overlap with a previously transmitted stream segment.
Such an overlapping TCP stream segment could be due to a TCP retransmission.
Therefore to distinguish it as an injection attack we compare the overlapping stream segments of the new packet versus the previously assembly
TCP stream. If they are different then it's an injection attack. If they are equal then it's a TCP retransmission.

In principal HoneyBadger of course **cannot** determine which packet
was sent by an attacker and which was sent by the legit connection party. However we speculate that in the wild, injected packets
will have interesting and varying TTLs! This and other header parameters might make it possible to develop some heuristics for distinguishing
injected packets. That speculation aside... HoneyBadger's priority is to detect and record TCP attack attempts with the utmost precision.



autogenerated API documentation
-------------------------------
https://godoc.org/github.com/david415/HoneyBadger



manual "integration test" with netcat
=====================================

abstract
--------

This manual testing procedure proves that HoneyBadger's TCP injection detection is solid!
It only takes a few minutes to perform... and thus I highly recommend it to new users for
two reasons

1. to raise awareness about how insecure TCP is

2. to give you confidence that HoneyBadger has reliable TCP attack detection functionality


procedure
---------

1. build ``honeyBadger`` and ``sprayInjector`` (located under the ``cmd`` directory in the source repository) and (if you don't want to run them as root) run ``setcat`` to set capabilities on the binaries (eg, ``setcap cap_net_raw,cap_net_admin=eip honeyBadger`` as root).

2. run ``honeyBadger`` with these arguments... Note we are telling honeyBadger to write log files to the current working directory.

  .. code-block:: bash

    ./honeyBadger -i=lo -f="tcp port 9666"  -l="."

3. run ``sprayInjector`` with these arguments

  .. code-block:: bash

    ./sprayInjector -d=127.0.0.1 -e=9666 -f="tcp" -i=lo

4. start the netcat server

  .. code-block:: bash

    nc -l -p 9666

5. start the netcat client

  .. code-block:: bash

    nc 127.0.0.1 9666

6. In this next step we enter some data on the netcat server so that it will send it to the netcat client that is connected until the sprayInjector prints a log message containing "packet spray sent!" In that cause the TCP connection will have been sloppily injected. The injected data should be visible in the netcat client's output.

7. Look for the log files in honeyBadger's working directory. You should see two files beginning with "127.0.0.1"; the pcap file is a full packet log of that TCP connection which you can easily view in Wireshark et al. The JSON file contains attack reports. This is various peices of information relevant to each TCP injection attack. The ``sprayInjector`` tends to produce several injections... and does so sloppily in regards to keeping the client and server synchronized.

  .. code-block:: none

    $ ls 127*
    127.0.0.1:43716-127.0.0.1:9666.pcap  127.0.0.1:9666-127.0.0.1:43716.attackreport.json


It's what you'd expect... the pcap file can be viewed and analyzed in Wireshark and other similar tools.
The *127.0.0.1:9666-127.0.0.1:43716.attackreport.json* file contains JSON report structures.
The attack reports contains important information that is highly relevant to your interests such as:

  * type of TCP injection attack
  * flow of attack (meaning srcip:srcport-dstip:dstport)
  * time of attack
  * payload of packet with overlaping stream segment (in base64 format)
  * previously assembled stream segment that overlaps with packet payload (in base64 format)
  * TCP sequence of packet
  * end sequence of packet
  * overlap start offset is the number of bytes from the beginning of the packet payload that we have available among the reassembled stream segments for retrospective analysis
  * overlap end offset is the number of bytes from the end of the packet payload that we have in our reassembled stream segments...

https://godoc.org/github.com/david415/HoneyBadger#AttackReport


::

    $ cat 127.0.0.1:9666-127.0.0.1:43716.attackreport.json
    {"Type":"injection","Flow":"127.0.0.1:9666-127.0.0.1:43716","Time":"2015-01-30T08:38:14.378603859Z","Payload":"bWVvd21lb3dtZW93","Overlap":"aHJzCg==","StartSequence":831278445,"EndSequence":831278456,"OverlapStart":0,"OverlapEnd":4}
    {"Type":"injection","Flow":"127.0.0.1:9666-127.0.0.1:43716","Time":"2015-01-30T08:38:14.379005763Z","Payload":"bWVvd21lb3dtZW93","Overlap":"cnMK","StartSequence":831278446,"EndSequence":831278457,"OverlapStart":0,"OverlapEnd":3}
    ...


|
|
|

.. image:: images/honey_badger-white-sm-1.png
