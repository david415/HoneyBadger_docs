
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

- HoneyBadger is primarily a comprehensive TCP stream analysis tool for detecting and recording TCP attacks.

- HoneyBadger is modern software written in Golang to deal with TCP's very olde injection vulnerabilities.

- HoneyBadger includes a variety of TCP stream injection attacks written in golang. (2 so far)

- Free as in GPLv3 (except for small sections of Google's BSD licensed code) and the source code is available on github:

* https://github.com/david415/HoneyBadger


development status
------------------

Actively being developed.

This early development version of HoneyBadger is useable right now... and I'm sure there are bugs; we are aware of several. I recommend reviewing our current issues before deploying HoneyBadger into a "production environment". Please use the github issue tracker to submit bug reports and feature requests!

https://github.com/david415/HoneyBadger/issues


what does HoneyBadger do and **not** do?
----------------------------------------

**DO**

- one purpose in life... To detect (and optionally record) TCP injection attacks and attempts.

- passively analyze TCP traffic


**NOT DO**

- HoneyBadger is in fact not a "honey pot"

- HoneyBadger does not send packets

- HoneyBadger does not detect man-in-the-middle attacks

- HoneyBadger does not determine if an attack attempt was successful (I suspect that in the wild TCP attacks will have differing TTLs and other clues that will help us determine if the attack was successful or not)

- HoneyBadger is nothing like the more general purpose tools like Snort, Bro or Wireshark.


security considerations
-----------------------

- HoneyBadger is written in golang which should be much safer than C. However, we do currently depend on libpcap and we'd like to get rid of this dependency specifically to eliminate any security vulnerabilities that using libpcap might have. See github issue https://github.com/david415/HoneyBadger/issues/43

- HoneyBadger is designed to be somewhat denial-of-service resistant. We specifically allow the user to set resource boundary options for HoneyBadger so that continuous operation is possible.


Tor exit relay operator legal considerations
--------------------------------------------

- Telecommunications laws in your Tor exit relay country may prohibit recording user's content without their consent. HoneyBadger therefore does not record packets (pcap log) by default; and attack reports only record metadata. IP addresses and TCP ports are recorded in the attack metadata reports... this sensitive data should be anonymized before making it public.

- As far as my humble legal-system understanding is concerned it should be legal to operate an opt-in HoneyBadger service for users who consent to having their traffic recorded.

- It is the author's firm belief that it is definitely legal to monitor your own traffic using HoneyBadger with the full-take logging features.


simple Tor exit relay deployment
--------------------------------

- Linux users should run honeyBadger as an unprivileged user. First run setcap as root like so::

  setcap cap_net_raw,cap_net_admin=eip honeyBadger

- Create RAM backed filesystem for your honeyBadger log directory. if you use Linux then you chose between ramfs and tmpfs. I recommend turning off swap and using tmpfs... this way you can limit the size of the log directory.

- Here's an example running honeyBadger for a Tor exit relay with OR-port 443 and full-take logging::

  ./honeyBadger -max_concurrent_connections=100 -f="tcp port 443" -l=logs -log_packets=true -metadata_attack_log=false -connection_max_buffer=300 -total_max_buffer=3000 -tcp_idle_timeout=10m0s

- Alternatively, this would record only TCP injection attack metadata (includes IP addresses and TCP port numbers but not packet payloads)::

  ./honeyBadger -max_concurrent_connections=100 -f="tcp port 443" -l=logs -connection_max_buffer=300 -total_max_buffer=3000 -tcp_idle_timeout=10m0s


how to turn HoneyBadger into a honeyPot
---------------------------------------

In the context of TCP injection attacks, a honeypot would be a way to intentionally "attract" these injection attacks so that HoneyBadger can record the packet payloads and metadata about the attacks. This sort of tactic could be profitable for individuals trying to collect attack statistics or zero-days. It could very well be that searching for certain keywords or visiting certain websites and online forums puts individuals at a higher risk for targetted surveillance and thus more likely to be TCP injection attacked. If that's the case then your browser + HoneyBadger could be used as a honeypot for "interesting" data collection. It should be obvious that the browser should thoroughly sandboxed for experiments like this because it will most likely get pwned. For this type of scenario it seems better to not even run the browser on any of your own person computer equipment at all... but instead run the Tor Browser Bundle on a cheap remote VPS (virtual private server). You can use ssh + vnc to interact with the browser remotely. I am a fan of this pure python VNC client that a friend pointed me to:

https://code.google.com/p/python-vnc-viewer


You can also run the Tor Browser Bundle and other browsers on a Raspberry Pi 2 running archlinux arm. This hardware might be cheaper to deal with and easier to isolate. I've successfully built the Tor Browser Bundle for the Raspberry Pi 2 running ARM Archlinux; details here:

https://trac.torproject.org/projects/tor/ticket/12631#comment:6



how to sniff only your own traffic on a Tor exit you control
------------------------------------------------------------

Soon I'd like to write more here about various ways that you can isolate your own traffic on a Tor exit relay you control. Here's one such idea:

Client -> localsocks-proxy -> tor connection -> tor exit -> tor-exit-socks-proxy-server-> internet

However... Firefox/TBB currently does not currently support Socks Proxy username/password authentication... so we should probably use a different tactic to isolate our traffic?



what to do with HoneyBadger collected data
------------------------------------------

This data could expose tradecraft pwn-to-surveil secrets as well as botnet location information. These TCP injection botnet locations will of course not be the IP addresses that they spoof in their injection attack transmissions. However, by observing these fake botnet from various vantage points within the network topology it may be possible to increase the acuracy of our understanding of the attackers locations. (provide link to Nicholas Hopper's paper on circumventing censorship network infrastructure for relevant ideas)

The other reason to collect HoneyBadger data is to try an understand how the attack works... and to perhaps catch a zero day. Some of the more sophisticated attacks may have several attack phases meant to obscure the attackers locations or the attack zero-day itself.

HoneyBadger is very much a tool for hackers/software developers and as such doesn't provide you with any tools for analyzing the data that it collects.


honeyBadger commandline arguments and usage
-------------------------------------------

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


TCP injection attacks are man-on-the-side attacks (MOS) [1]_ and are not the same thing as man-in-the-middle attacks (MITM).
In the MOS scenario the attacker cannot prevent the propagation of packets between link A -> B or B -> A but instead can
read and write packets on the same network interface(s)... in other more eloquent words from Wikipedia: "Instead of completely
controlling a network node as in a man-in-the-middle attack, the attacker only has regular access to the communication
channel, which allows him to read the traffic and insert new messages, but not to modify or delete messages sent by other
participants." [1]_ Much of the classic literature about TCP injection attacks considers TCP injection in the context of probabilitistic
TCP Sequence number prediction. [2]_ [3]_ These olde school attacks focused more on exploiting TCP Sequence number prediction and side
channels, however TCP injection attacks are essentially a form of timing attack. Since the various improvements to the TCP's initial
Initial Sequence Numbers (ISNs) [4]_ [5]_, TCP was widely believed to not be vulnerable to injection attacks, however TCP has
remained vulnerable to various Sequence prediction based injection attacks, including side channel inference attacks [6]_ [7]_ [8]_.
Various so called classic and modern TCP injection attacks can involve an "off-path injection". These are remarkable deployment tactics where
the attack packets originate from distributed "puppet" computers that are not directly in either route between host Alice and host Bob.
Ingress filtering may make this IP spoofing between networks less commonly available than before but still feasible today [6]_.

These puppets behave as "write-ony network taps" in so far as they have the ability to inject packets but not read. It is my understanding
that the secret NSA documents refer to these puppet computers as "QUANTUM shooters" [9]_. According to a Der Spiegal article about leaked
NSA documents, these puppets create a layer of indirection that might be used to make TCP injection attacks harder to track down:
"And computers infected with Straitbizarre can be turned into disposable and non-attributable 'shooter' nodes." [10]_
We've also seen other code names for the shooters such as Straighbizarre and Daredevil. [11]_ According to a Guardian article the NSA
may be using a topologically advantageous placement of servers in the network to win the packet race: "the NSA places secret servers,
codenamed Quantum, at key places on the internet backbone. This placement ensures that they can react faster than other websites can." [12]_ [13]_
One Wired article mentions that the NSA could be using MoS attacks rather than MITM attacks because it fit's their security domain
isolation policy with regards to where attack logic is placed. [14]_ Any world class attacker such as the NSA would likely have measures
to prevent leaking their 0-day to security researchers and other attackers. [15]_

According to various security researchers and leaked documents, there is the so called lawful intercept industry where governments and
other orgranizations with known track records of human right violations can illegally purchase "hacking appliances". [16]_ [17]_ [18]_
These MoS appliances might offer an advantage over MITM attacks in that they may be very simple to deploy. Perhaps by plugging into
a mirrored switch port. [20]_

Details are not perfectly clear regarding how the packet race is actually won either for the NSA Quantum deployments nor for
the specialized MoS "hacking appliances", however it could be that these appliances posses a high probability
of success at winning the race due to being built with specialized high speed signal processing components that are capable of operating at
line speeds. [16]_ [17]_ [18]_ It should be obvious that there exist multiple "hacking" entities world wide that posses the capability to perform
these TCP injection attacks with a very high probability of success, however they may not all have the same operational security policies.
For instance if the NSA had a policy of not deploying attack logic to insecure systems or physical facilities then that might be a reason
for them to prefer an offsite MoS approach over an onsite MITM. The attacker might have an offsite command and control (C&C) center which passes
instructions to these "shooter" puppets, which then perform the actual TCP injection attack on behalf of the C&C.

Broadly speaking there are two categories of TCP injection attacks; handshake hijack and stream injection.
I've added a couple more injection attack categories to the list; here #2 "segment veto" and #3 "sloppy injection"
are nearly identical (honeybadger does not yet distinguish between them).


1. handshake hijack: the attacker responds to a SYN packet with their SYN/ACK packet before the legit server.

2. segment veto: the injected packet(s) are the exact same size as those sent out by the legit party. Client and server remain in sync after data is injected.

3. sloppy injection: the injected packet(s) are different sizes than that of the legit party. Client and server fall out of sync after injection.

4. out-of-order coalesce injection: injected packets are ahead of the next sequence. Injection of data takes place during coalescence.

Each of these TCP attacks are really broader categories of attack... for instance a sloppy injection could be followed up with a
procedure that gradually brings client and server back into TCP Sequence synchronization.


handshake hijack detection
--------------------------

We do some fairly simple state tracking to detect handshake hijack attacks. When a TCP connection receives a SYN/ACK packet during the handshake we record the Sequence and Acknowledgement numbers. A normal TCP SYN/ACK retransmission will have the exact same TCP Sequence number... however if we receive mulitple SYN/ACK packets with different Sequence numbers this indicates a handshake hijack attack attempt.


stream injection detection
--------------------------

Segment veto and sloppy injection attacks are detected by means of a retrospective analysis. HoneyBadger reassembles the TCP stream so that received packets with overlapping data can be compared. If their data is the same then of course the packet came from a normal TCP retransmission. However if their contents differ at all this must mean that a TCP injection attack attempt was made. HoneyBadger performs TCP directional state tracking, for each direction it keeps track of the "next Sequence" value. The reassembled TCP stream is written to a ring buffer... and this ring buffer is traversed for content comparison for each packet that has a Sequence proceeding the "next Sequence".

In principal HoneyBadger of course **cannot** determine which packet was sent by an attacker and which was sent by the legit connection party. However we speculate that in the wild, injected packets will have interesting and varying TTLs! This and other header parameters might make it possible to develop some heuristics for distinguishing injected packets. That speculation aside... HoneyBadger's priority is to detect and record TCP attack attempts with the utmost precision.


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
The attack reports contains important information that is highly relevant to your interests such as::

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
|



bibliographical references
--------------------------

.. [1] https://en.wikipedia.org/wiki/Man-on-the-side_attack
.. [2] https://en.wikipedia.org/wiki/TCP_sequence_prediction_attack
.. [3] http://www.tech-faq.com/tcp-sequence-prediction-attack.html
.. [4] https://tools.ietf.org/html/rfc1948
.. [5] https://tools.ietf.org/html/rfc6528
.. [6] http://arxiv.org/pdf/1208.2357.pdf
.. [7] http://www.ieee-security.org/TC/SP2012/papers/4681a347.pdf
.. [8] http://phrack.org/issues/64/13.html
.. [9] http://www.spiegel.de/media/media-35664.pdf
.. [10] http://www.spiegel.de/international/world/new-snowden-docs-indicate-scope-of-nsa-preparations-for-cyber-battle-a-1013409.html
.. [11] http://www.spiegel.de/media/media-35667.pdf
.. [12] http://www.theguardian.com/world/2013/oct/04/tor-attacks-nsa-users-online-anonymity
.. [13] http://www.spiegel.de/international/world/the-nsa-uses-powerful-toolbox-in-effort-to-spy-on-global-networks-a-940969-3.html
.. [14] https://www.wired.com/2014/03/quantum/
.. [15] https://www.schneier.com/blog/archives/2013/10/the_nsas_new_ri.html
.. [16] https://citizenlab.org/2014/08/cat-video-and-the-death-of-clear-text/
.. [17] https://cpunks.org/pipermail/cypherpunks/2014-August/005393.html
.. [18] https://wikileaks.org/spyfiles/files/0/296_GAMMA-201110-FinFly_Web.pdf
.. [19] http://www.washingtonpost.com/world/national-security/spyware-tools-allow-buyers-to-slip-malicious-code-into-youtube-videos-microsoft-pages/2014/08/15/31c5696c-249c-11e4-8593-da634b334390_story.html
.. [20] http://c-skills.blogspot.de/2013/11/killing-schrodingers-cat.html
