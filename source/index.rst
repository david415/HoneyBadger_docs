
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

- HoneyBadger is a comprehensive passive TCP protocol analysis tool for detecting and recording TCP injection attacks, also known as a ``Quantum Insert`` detector.
- HoneyBadger includes a variety of TCP stream injection attacks prototypes also written in golang.
- Free as in GPLv3 (except for small sections of Google's BSD licensed code) and the source code is available on github:

* https://github.com/david415/HoneyBadger


what does HoneyBadger do and **not** do?
----------------------------------------

**DO**

- passively analyze of TCP (transmission control protocol) traffic, tries to detect evidence of a MOTS (man-on-the-side) attack

- optionally can produce TCP injection attack reports and record pcap files of connections with attacks

**NOT DO**

- HoneyBadger is not a ``honey pot`` even though it has the word ``honey`` in the name. Sorry ;-p

- HoneyBadger does not send packets on the network

- HoneyBadger does not try to determine if an attack attempt was successful



installation
------------

Before building and installing honeybadger I suggest building a modern version of golang from source as described in the instructions here:

https://golang.org/doc/install/source


Like this::

  cd $HOME
  git clone https://go.googlesource.com/go
  cd go
  git checkout go1.5
  cd src
  ./make.bash


Setup the golang environment variables::

  export GOPATH=$HOME/go/gopath
  export PATH=$PATH:$HOME/go/bin:$HOME/go/gopath/bin


Then after that you can build honeybadger and it's dependencies like this::

  cd $HOME/go
  mkdir -p gopath/src/github.com/google
  cd gopath/src/github.com/google
  git clone https://github.com/google/gopacket.git
  mkdir -p $HOME/go/gopath/src/github.com/david415
  cd $HOME/go/gopath/src/github.com/david415
  git clone https://github.com/david415/HoneyBadger.git
  cd HoneyBadger/cmd/honeyBadger
  go build


preparing to run HoneyBadger
----------------------------

If you run Linux and would like to use the AF_PACKET sniffer then you should
also disable the segment offloading options on the relavent network device(s) ::

  ethtool -K eth0 gso off
  ethtool -K eth0 tso off
  ethtool -K eth0 gro off


Linux users should run honeyBadger as an unprivileged user. First run setcap as root like so::

  setcap cap_net_raw,cap_net_admin=eip honeyBadger


Tor exit relay operator legal considerations
--------------------------------------------

- Telecommunications laws in your Tor exit relay country may prohibit recording user's content without their consent. HoneyBadger therefore does not record packets (pcap log) by default; and attack reports only record metadata. IP addresses and TCP ports are recorded in the attack metadata reports... this sensitive data should be anonymized before making it public.

- As far as my humble legal-system understanding is concerned it should be legal to operate an opt-in HoneyBadger service for users who consent to having their traffic recorded.

- It is the author's firm belief that it is definitely legal to monitor your own traffic using HoneyBadger with the full-take logging features.


how to sniff only your own traffic on a Tor exit you control
------------------------------------------------------------

Soon I'd like to write more here about various ways that you can isolate your own traffic on a Tor exit relay you control. Here's one such idea:

Client -> localsocks-proxy -> tor connection -> tor exit -> tor-exit-socks-proxy-server-> internet

However... Firefox/TBB currently does not support Socks Proxy username/password authentication... so we should probably use a different tactic to isolate our traffic?


what to do with HoneyBadger collected data
------------------------------------------

We expect HoneyBadger to have various false positive bugs... and furthermore there are in fact various ways in which network anomalies can appear to be injection attacks or accidentally inject data. I have seen in the wild misbehaving load balancers etc.

If your honeybadger generates an attack report and you have specified the CLI option `-metadata_attack_log=false` then you may be interested in the `honeybadgerReportTool`; it displays a dump output which includes ASCII and hex... this color coated hex diff makes it **very** obvious what data was injected. This simple utility is located in the honeybadger code repo here: https://github.com/david415/HoneyBadger/blob/master/cmd/honeybadgerReportTool/main.go


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


reproducible pcap-driven integration test
`````````````````````````````````````````

Currently we have a very simple pcap-driven integration test; located in ``pcap_integration_test.go``.
You can run it seperate from all the other tests like this::

  go test -run TestAllPcapFiles

It skips the test unless there's a symlink in the honeybadger root called ``pcap_archive``.
Make this a symlink to this git repository containing pcap files known to have TCP injection attacks:

- https://github.com/david415/honeybadger-pcap-files


Clearly the next step is break this up into multiple pcap-driven tests... one for each TCP injection attack type.


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

https://godoc.org/github.com/david415/HoneyBadger#AttackReport



|
|
|

.. image:: images/honey_badger-white-sm-1.png
| 
