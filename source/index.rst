
HoneyBadger
===========

.. image:: images/honey_badger-white-sm-1.png
| 
.. image:: https://travis-ci.org/david415/HoneyBadger.svg?branch=master
  :target: https://travis-ci.org/david415/HoneyBadger

.. image:: https://coveralls.io/repos/github/david415/HoneyBadger/badge.svg?branch=master
  :target: https://coveralls.io/github/david415/HoneyBadger

.. image:: https://godoc.org/github.com/david415/HoneyBadger?status.svg
  :target: https://godoc.org/github.com/david415/HoneyBadger

|


**TCP attack inquisitor and 0-day catcher.**

- HoneyBadger is a comprehensive passive TCP protocol analysis tool for detecting and recording TCP injection attacks, also known as a ``Quantum Insert`` detector.
- HoneyBadger includes a variety of TCP stream injection attacks prototypes also written in golang.
- Free as in GPLv3 (except for small sections of Google's BSD licensed code) and the source code is available on github:

* https://github.com/david415/HoneyBadger


what does HoneyBadger do and **not** do?
----------------------------------------

**DO**

- passive analysis of TCP (transmission control protocol) traffic, tries to detect evidence of a MOTS (man-on-the-side) attack

- optionally can produce TCP injection attack reports and record pcap files of connections with attacks

**NOT DO**

- HoneyBadger is not a ``honey pot`` even though it has the word ``honey`` in the name. But it could certainly be used with a ``honey pot``.

- HoneyBadger does not send packets on the network

- HoneyBadger does not try to determine if an attack attempt was successful



installation
------------

Before building and installing honeybadger you need a working golang.
You could build from source as described in the instructions here:

https://golang.org/doc/install/source

Or install Google's binary::

  wget https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz
  tar xzf go1.5.3.linux-amd64.tar.gz


Setup the golang environment variables::

  export GOROOT=/home/human/go
  export GOPATH=/home/human/gopath
  export PATH=/home/human/go/bin:/home/human/gopath/bin:$PATH


To build on Linux you'll need to install libpcap-dev::

  sudo apt-get install libpcap-dev


Use the "go get" tool to fetch, build and install honeybadger::

  go get -v github.com/david415/HoneyBadger/cmd/honeyBadger


If you run Linux and would like to use the **AF_PACKET** sniffer then you should
also disable the segment offloading options on the relavent network device(s) ::

  sudo apt-get install ethtool
  sudo ethtool -K eth0 gso off
  sudo ethtool -K eth0 tso off
  sudo ethtool -K eth0 gro off


Linux users should run honeyBadger as an unprivileged user. First run setcap as root like so::

  sudo setcap cap_net_raw,cap_net_admin=eip honeyBadger


capturing TCP traffic and attack reports on Linux
-------------------------------------------------

You can tell honeyBadger to analyze the wire with Linux's AF_PACKET capture mode::

  honeyBadger -max_concurrent_connections=1000 -max_pcap_log_size=100 -max_pcap_rotations=10 \
  -max_ring_packets=40 -metadata_attack_log=false -total_max_buffer=1000 -connection_max_buffer=100 \
  -archive_dir=/home/human/archive -l=/home/human/incoming -log_packets=true -i=eth0 -daq=AF_PACKET

  2016/02/07 14:16:32 HoneyBadger: comprehensive TCP injection attack detection.
  2016/02/07 14:16:32 PageCache: created 1024 new pages
  2016/02/07 14:16:32 Starting AF_PACKET packet capture on interface eth0


Or use it to analyze pcap files like this::

  honeyBadger -max_concurrent_connections=1000 -max_pcap_log_size=100 -max_pcap_rotations=10 \
  -max_ring_packets=40 -metadata_attack_log=false -total_max_buffer=1000 -connection_max_buffer=100
  -archive_dir=./archive -log_packets -l=./incoming -pcapfile=./tshark2.pcap


honeyBadger will spew lots of things to stdout. Using the above command,
it will write the following into the "archive" directory:

- pcap file(s) for each connection which triggered detection for a TCP injection attack

- attack report JSON file(s) which include relavant meta-data that can be used to refer
  to specific sections of the pcap file AND base64 blobs of payload data of the overlapping
  TCP stream segments


Here's an example output with a pcap file containing an ordered coalesce injection::

  2016/02/05 23:30:01 Starting libpcap packet capture on file ./tshark2.pcap
  2016/02/05 23:30:01 connected 127.0.0.1:59670-127.0.0.1:9666
  2016/02/05 23:30:01 race winner stream segment:
  2016/02/05 23:30:01 00000000  20 69 73 20 6e 65 63 65  73 73 61 72 79 20 66 6f  | is necessary fo|
  00000010  72 20 61 6e 20 6f 70 65  6e 20 73 6f 63 69 65 74  |r an open societ|
  00000020  79 20 69 6e 20 74 68 65  20 65 6c 65 63 74 72 6f  |y in the electro|
  00000030  6e 69 63 20 61 67 65 2e  20 50 72 69 76 61 63 79  |nic age. Privacy|
  00000040  20 69 73 20 6e 6f 74 20  73 65 63 72 65 63 79 2e  | is not secrecy.|
  00000050  20 41 20 70 72 69 76 61  74 65 20 6d 61 74 74 65  | A private matte|
  00000060  72 20 69 73 20 73 6f 6d  65 74 68 69 6e 67 20 6f  |r is something o|
  00000070  6e 65 20 64 6f 65 73 6e  27 74 20 77 61 6e 74 20  |ne doesn't want |
  00000080  74 68 65 20 77 68 6f 6c  65 20 77 6f 72 6c 64 20  |the whole world |
  00000090  74 6f 20 6b 6e 6f 77 2c  20 62 75 74 20 61 20 73  |to know, but a s|
  000000a0  65 63 72 65 74 20 6d 61  74 74 65 72 20 69 73 20  |ecret matter is |
  000000b0  73 6f 6d 65 74 68 69 6e  67 20 6f 6e 65 20 64 6f  |something one do|
  000000c0  65 73 6e 27 74 20 77 61  6e 74 20 61 6e 79 62 6f  |esn't want anybo|
  000000d0  64 79 20 74 6f 20 6b 6e  6f 77 2e 20 50 72 69 76  |dy to know. Priv|
  000000e0  61 63 79 20 69 73 20 74  68 65 20 70 6f 77 65 72  |acy is the power|
  000000f0  20 74 6f 20 73 65 6c 65  63 74 69 76 65 6c 79 20  | to selectively |
  00000100  72 65 76 65 61 6c 20 6f  6e 65 73 65 6c 66 20 74  |reveal oneself t|
  00000110  6f 20 74 68 65 20 77 6f  72 6c 64 2e              |o the world.|
  2016/02/05 23:30:01 race loser stream segment:
  2016/02/05 23:30:01 00000000  50 72 69 76 61 63 79 20  69 73 20 6e 65 63 65 73  |Privacy is neces|
  00000010  73 61 72 79 20 66 6f 72  20 61 6e 20 6f 70 65 6e  |sary for an open|
  00000020  20 73 6f 63 69 65 74 79  20 69 6e 20 74 68 65 20  | society in the |
  00000030  65 6c 65 63 74 72 6f 6e  69 63 20 61 67 65 2e 20  |electronic age. |
  00000040  50 72 69 76 61 63 79 20  69 73 20 6e 6f 74 20 73  |Privacy is not s|
  00000050  65 63 72 65 63 79 2e 20  41 20 70 72 69 76 61 74  |ecrecy. A privat|
  00000060  65 20 6d 61 74 74 65 72  20 69 73 20 73 6f 6d 65  |e matter is some|
  00000070  74 68 69 6e 67 20 6f 6e  65 20 64 6f 65 73 6e 27  |thing one doesn'|
  00000080  74 20 77 61 6e 74 20 74  68 65 20 77 68 6f 6c 65  |t want the whole|
  00000090  20 77 6f 72 6c 64 20 74  6f 20 6b 6e 6f 77 2c 20  | world to know, |
  000000a0  62 75 74 20 61 20 73 65  63 72 65 74 20 6d 61 74  |but a secret mat|
  000000b0  74 65 72 20 69 73 20 73  6f 6d 65 74 68 69 6e 67  |ter is something|
  000000c0  20 6f 6e 65 20 64 6f 65  73 6e 27 74 20 77 61 6e  | one doesn't wan|
  000000d0  74 20 61 6e 79 62 6f 64  79 20 74 6f 20 6b 6e 6f  |t anybody to kno|
  000000e0  77 2e 20 50 72 69 76 61  63 79 20 69 73 20 74 68  |w. Privacy is th|
  000000f0  65 20 70 6f 77 65 72 20  74 6f 20 73 65 6c 65 63  |e power to selec|
  00000100  74 69 76 65 6c 79 20 72  65 76 65 61 6c 20 6f 6e  |tively reveal on|
  00000110  65 73 65 6c 66 20 74 6f  20 74 68 65              |eself to the|
  2016/02/05 23:30:01 detected an ordered coalesce injection
  2016/02/05 23:30:01 FIN-WAIT-1: non-ACK packet received.
  2016/02/05 23:30:01 ReadPacketData got EOF
  2016/02/05 23:30:01 Close()
  2016/02/05 23:30:01 1 connection(s) closed.
  2016/02/05 23:30:01 Supervisor.Stopped()
  2016/02/05 23:30:01 graceful shutdown: packet-source stopped



Tor exit relay operator legal considerations
--------------------------------------------

- As far as my humble legal-system understanding is concerned it should be legal to operate an opt-in HoneyBadger service for users who consent to having their traffic recorded.

- It is the author's firm belief that it is definitely legal to monitor your own traffic using HoneyBadger with the full-take logging features.


what to do with HoneyBadger collected data
------------------------------------------

If your honeybadger generates an attack report and you have specified the CLI option `-metadata_attack_log=false` then you may be interested in the `honeybadgerReportTool`; it displays a dump output which includes ASCII and hex... this hex diff makes it **very** obvious what data was injected. This simple utility is located in the honeybadger code repo here: https://github.com/david415/HoneyBadger/blob/master/cmd/honeybadgerReportTool/main.go

Here's an example run::

  $ ./honeybadgerReportTool ../honeyBadger/archive/127.0.0.1:9666-127.0.0.1:59763.attackreport.json
  attack report: ../honeyBadger/archive/127.0.0.1:9666-127.0.0.1:59763.attackreport.json
  Event Type: ordered coalesce 2
  Flow: 127.0.0.1:9666-127.0.0.1:59763
  Time: 2016-02-07 10:09:49.2487 +0000 UTC
  Packet Number: 0
  HijackSeq: 0 HijackAck: 0
  Start: 1427250824 End: 1427250870
  Base Sequence: 1427250814

  Overlapping portion of reassembled TCP Stream:
  00000000  50 72 69 76 61 63 79 20  69 73 20 6e 65 63 65 73  |Privacy is neces|
  00000010  73 61 72 79 20 66 6f 72  20 61 6e 20 6f 70 65 6e  |sary for an open|
  00000020  20 73 6f 63 69 65 74 79  20 69 6e 20 74 68        | society in th|

  Injection packet whose contents did not coalesce into the TCP Stream:
  00000000  37 0a 36 0a 35 0a 35 34  0a 34 0a 34 0a 34 0a 36  |7.6.5.54.4.4.4.6|
  00000010  0a 34 36 33 32 36 33 34  0a 36 33 34 36 34 0a 33  |.4632634.63464.3|
  00000020  36 0a 34 33 36 0a 34 33  36 0a 34 33 36 0a        |6.436.436.436.|



honeyBadger commandline arguments and usage
-------------------------------------------


honeyBadger has a rather large commandline usage::

  $ ./honeyBadger -h
  Usage of ./honeyBadger:
  -archive_dir string
   archive directory for storing attack logs and related pcap files
  -connection_max_buffer int

  Max packets to buffer for a single connection before skipping over a gap in data
  and continuing to stream the connection after the buffer.  If zero or less, this
  is infinite.

  -daq string
    	Data AcQuisition packet source: libpcap, AF_PACKET or BSD_BPF (default "libpcap")
  -detect_coalesce_injection
    	Detect coalesce injection attacks (default true)
  -detect_hijack
    	Detect handshake hijack attacks (default true)
  -detect_injection
    	Detect injection attacks (default true)
  -f string
    	BPF filter for pcap (default "tcp")
  -i string
    	Interface to get packets from (default "eth0")
  -l string
    	incoming log dir used initially for pcap files if packet logging is enabled
  -log_packets
    	if set to true then log all packets for each tracked TCP connection
  -max_concurrent_connections int
    	Maximum number of concurrent connection to track.
  -max_pcap_log_size int
    	maximum pcap size per rotation in megabytes (default 1)
  -max_pcap_rotations int
    	maximum number of pcap rotations per connection (default 10)
  -max_ring_packets int
    	Max packets per connection stream ring buffer (default 40)
  -metadata_attack_log
    	if set to true then attack reports will only include metadata (default true)
  -pcapfile string
    	pcap filename to read packets from rather than a wire interface.
  -s int
    	SnapLen for pcap packet capture (default 65536)
  -tcp_idle_timeout duration
    	tcp idle timeout duration (default 5m0s)
  -total_max_buffer int
  
  Max packets to buffer total before skipping over gaps in connections and
  continuing to stream connection data.  If zero or less, this is infinite
  -w string timeout for reading packets off the wire (default "3s")


packet acquisition
``````````````````

There are three ethernet sniffers (also known as packet Data AcQuisition sources) that honeybadger currently uses:

- AF_PACKET (Linux only)
- BPF (BSD only)
- libpcap

Currently only our libpcap sniffer supports filtering... that is the ``-f`` flag only affects honeyBadger if you are using the lipcap ethernet sniffer... which is the default unless you specify the ``-daq`` option with either ``BSD_BPF`` or ``AF_PACKET``.

In any case you must definitely specify a network interface to sniff with ``-i``.
The options ``-w`` and ``-s`` are only relevant to the ``libpcap`` packet capture mode (``-daq``), you probably want to use the default values.


logging
```````

You must specify a logging directory using ``-l``.
packet logging to pcap file(s) is turned off by default. If you set ``-log_packets`` to ``true`` then honeybadger
will write one pcap file per connection. Upon connection close honeybadger will delete the pcap logfile
unless a TCP attack was detected.

**duly note**: this will cause lots of filesystem churn when sniffing high traffic interfaces.
Clever honeyBadger-Operators will use a RAM-based filesystem for their logs.


By default honeybadger write metadata-only logs which will NOT contain any packet payload data but will
have various sensitive information about attack attempts such as:

- source and destination IP addresses
- TCP ports
- the type of TCP injection attack (there are several)
- time of the attack
- TCP Sequence number boundaries of the injection

If you set ``-metadata_attack_log`` to ``false`` then honeybadger will log the attack packet payload AND the stream overlap.
This feature is expected to help honeyBadger-Operators to eliminate false positives. Our honeybadger attack report tool(s) can read the
json attack report files and print out and ASCII + hex color-coated diff of the injected data versus reassembled TCP stream overlap.


resource boundaries
```````````````````

``-connection_max_buffer`` and ``-total_max_buffer`` are used to limit the amount of page-cache pages
that honeybadger can use for storing and reordering out-of-order-packets (much like TCP's mbuf datastructure).

``-tcp_idle_timeout`` is important... each connection continues to be tracked even after a close so that we might detect certain types of atacks.

``-max_ring_packets`` is very important to set appropriately; it determines the size of the TCP reassembly ring buffer. This ring buffer is utilized for the retrospective analysis that allows us to determine if a given packet overlaps with previously reassembled stream segments. I estimate that this ring buffer should be set to a size that is roughly equivalent to the TCP window size of the connection... but maybe someone can help us pick a better heuristic? I usually set it to 40 and it works OK.

``-max_pcap_log_size`` and ``-max_pcap_rotations`` are used to adjust a simple log rotation scheme used limit the amount of disk utilized by pcap-packet logs.


for developers
--------------

autogenerated API documentation
```````````````````````````````
https://godoc.org/github.com/david415/HoneyBadger


run unit tests
``````````````

If you'd like to hack on the HoneyBadger source tree then please do!
You can run the unit tests like this::

  go test -v ./...


reproducible pcap-driven integration test
`````````````````````````````````````````

Currently we have a very simple pcap-driven integration test; located in ``pcap_integration_test.go``.
You can run it seperate from all the other tests like this::

  go test -run TestAllPcapFiles

It skips the test unless there's a symlink in the honeybadger root called ``pcap_archive``.
Make this a symlink to this git repository containing pcap files known to have TCP injection attacks:

- https://github.com/david415/honeybadger-pcap-files



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

   mkdir archive
   mkdir incoming
   ./honeyBadger -i=lo -f="tcp port 9666" -l="." -total_max_buffer=300 -connection_max_buffer=100 \
     -l ./incoming -archive_dir ./archive -max_concurrent_connections 1000


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
The attack reports contains important information that is highly relevant to your interests such as::

* type of TCP injection attack
* flow of attack (meaning srcip:srcport-dstip:dstport)
* time of attack
* payload of packet with overlaping stream segment (in base64 format)
* previously assembled stream segment that overlaps with packet payload (in base64 format)
* TCP sequence of overlap start
* TCP sequence of overlap end

https://godoc.org/github.com/david415/HoneyBadger/types#Event



|
|
|

.. image:: images/honey_badger-white-sm-1.png
| 
