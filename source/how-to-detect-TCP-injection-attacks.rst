

how to detect TCP injection attacks
===================================

abstract
--------

HoneyBadger is a passive TCP protocol analyzer that detects and optionally records TCP injection attacks. HoneyBadger has been called a "Quantum-Insert detector" because it can detect the NSA's "Quantum" attacks on TCP. These TCP injection attacks are clearly not just used by the NSA, but by various entities around the world. [16]_

Many of these well-funded state/world-class adversaries are able to completely automate the compromising of computers using these TCP injection attacks against real people to violate their human rights. This could be especially dangerous when this auto-compromising happens based on key-word searches and participation in specific online forums.

Deployments of HoneyBadger could provide enlightening attack statistics that may prove useful to security researchers, contributing to the responsible disclosure of stock-piled zero-days that currently threaten our intellectual freedoms.


honeybadger source code:
https://github.com/david415/HoneyBadger

honeybadger documentation:
https://honeybadger.readthedocs.org/en/latest/


introduction
------------

Powerful entities world wide are stock piling zero-days. TCP injection attacks are used to deliver these attacks. The more sophisticated adversaries will use a security domain isolation policy to make sure their attack logic is located in a protected area of their network while they utilize multiple network taps and injection hosts in multiple locations. It is clear from the Snowden documents that at least in the past the NSA has utilized botnet (groups of compromised computers connected to the Internet) hosts as "Quantum Shooters", hosts that send the injection attack packets to the target upon receiving "injection tips" (recent TCP connection meta data including Sequence numbers read from a network tap).



TCP injection attacks
---------------------

TCP injection attacks are man-on-the-side attacks (MOTS) [1]_ and are not the same thing as man-in-the-middle attacks (MITM). MOTS is defined by a situation when the attacker controls one or more communications channels in the route. This much is stated in Wikipedia: "Instead of completely controlling a network node as in a man-in-the-middle attack, the attacker only has regular access to the communication channel, which allows him to read the traffic and insert new messages, but not to modify or delete messages sent by other participants." [1]_ Much of the classic literature about TCP injection attacks considers TCP injection in the context of probabilistic TCP Sequence number prediction. [2]_ [3]_  These olde school attacks focused more on exploiting TCP Sequence number prediction and side channels, however TCP injection attacks are essentially a form of timing attack. Since the various improvements to the TCP's initial Initial Sequence Numbers (ISNs) [4]_ [5]_, TCP was widely believed to not be vulnerable to injection attacks, however TCP has always been vulnerable to injection attacks... and additionally has remained vulnerable to various Sequence prediction based injection attacks, including side channel inference attacks [6]_ [7]_ [8]_. Various so called classic and modern TCP injection attacks can involve an "off-path injection". These are remarkable deployment tactics where the attack packets originate from hosts that are not directly in either route between host Alice and host Bob. Ingress filtering may make this IP spoofing between networks less commonly available than before but perhaps still feasible today [6]_.

These injection hosts behave as "write-only network taps" in so far as they have the ability to inject packets but not read. It is my understanding that the leaked NSA documents refer to these injection hosts as "QUANTUM shooters" [9]_.  According to a Der Spiegal article about leaked NSA documents, these shooters create a layer of indirection that might be  used to make TCP injection attacks harder to track down: "And computers infected with Straitbizarre can be turned into disposable and non-attributable 'shooter' nodes." [10]_ We've also seen other code names for the shooters such as Straightbizarre and Daredevil. [11]_  According to a Guardian article the NSA may be using a topologically advantageous placement of servers in the network to win the packet race: "the NSA places secret servers, codenamed Quantum, at key places on the internet backbone. This  placement ensures that they can react faster than other websites can." [12]_ [13]_ One Wired article mentions that the NSA could be using MOTS attacks  rather than MITM attacks because it fit's their security domain isolation policy with regards to where attack logic is placed. [14]_ Any world class attacker such as the NSA would likely have measures to prevent leaking their 0-day to security researchers and adversaries. [15]_

According to various security researchers and leaked documents, there is the so called lawful intercept industry where governments and other organizations (perhaps with known track records of human right violations) can purchase "hacking appliances". [16]_ [17]_ [18]_ These MOTS appliances might offer an advantage over MITM attacks in that they may be very simple to deploy. Perhaps by plugging into a mirrored switch port. [20]_

There exist multiple entities world wide that posses the capability to perform these TCP injection attacks with a very high probability of success, however they may not all have the same operational security policies. For instance perhaps the NSA has a policy of not deploying attack logic to insecure systems or physical facilities. I speculate that they have a security domain isolation policy that causes them to prefer an offsite MOTS approach over an onsite MOTS or MITM. The attacker might have an offsite command and control (C&C) center which passes instructions to these "shooters", who then perform the actual TCP injection attack on behalf of the C&C.



TCP injection attack categories
-------------------------------

Below I've outlined 5 categories of TCP injection attack... but more broadly speaking there are three categories of TCP injection attack: "handshake hijack", "post-handshake stream injection" and "censorship injection".

::

1. **handshake hijack:** After the client's initial SYN packet is sent, the attacker's SYN/ACK response packet is received by the client before the legitimate server's SYN/ACK packet. Finally the client responds to the SYN/ACK with it's ACK packet. After that, the attacker has control over the server side of the connection for a short period of time. When the legitimate server receives the client's ACK packet it will send an RST; the client will close the connection when it receives the RST packet, therefore the attacker has a very limited amount of time with which to send her malicious payload.
   
2. **segment veto:** the injected packet(s) have the precise TCP Sequence number needed for injection (the TCP statemachine's "next sequence") and are the exact same size as those sent out by the legit party. Client and server remain in sync after data is injected. To detect that these packets are not a TCP retransmission you can compare the payload. If the two packet's contain differing payloads then you know that one of them must have been injected.

3. **sloppy injection:** the injected packet(s) have the precise TCP Sequence number needed for injection, however the payload differs in size to that of the packet from the legit party. Client and server fall out of sync after injection, meaning the client's TCP statemachine's "next sequence" will differ from the server's TCP statemachine's "next sequence" for that flow. To detect this type of injection you must compare the same relative stream segments and not necessarily the entire packet payloads. HoneyBadger uses a ring buffer to store ordered stream segments. If for example the attacker's sloppy injection packet arrives first then the legit server's packet will overlap with previously recorded stream contents. The overlapping portion is compared so that we can eliminate TCP retransmissions.

4. **out-of-order coalesce injection:** injected packets with TCP Sequence numbers that come after the receiving TCP state-machine's "next sequence number". Injection of data into the application is slightly delayed by the TCP state-machine's coalesce of out-of-order packets. You can compare coalesced segments to overlapping portions of the ring buffer storing ordered stream segments. If the overlapping portion differs then this must be an injection attack.

5. **censorship injection:** injected packets are TCP FIN or RST which causes the TCP connection to close. This attack could be performed as an ordered or out-of-order coalesce injection attack.


**further remarks about the TCP injection attack categories:** Category 1; handshake hijack doesn't have any variations that I'm aware of. Categories 2 and 3 are essentially the same type of injection attack. Categories 2-4 could have many variations for instance a sloppy injection could be  followed up with a procedure that gradually brings client and server back into TCP Sequence  synchronization. An out-of-order coalesce injection could be used to slightly obscure the attack payload by sending overlapping future out-of-order packets. Due to the "selective acknowledgement" TCP option the first future out-of-order TCP segment received wins the privilege of it's payload being coalesced into the TCP stream. Category 5, a censorship injection is it's own category of injection attack because it doesn't actually inject anything into the TCP stream but still requires that precise TCP Sequence to perform the attack.


handshake hijack detection
--------------------------

HoneyBadger does some fairly simple state tracking to detect handshake hijack attacks. When a TCP connection receives a SYN/ACK packet during the handshake we record the Sequence and Acknowledgement numbers. A normal TCP SYN/ACK retransmission will have the exact same TCP Sequence number... however if we receive mulitple SYN/ACK packets with the correct Acknowledgement number but different Sequence numbers this indicates a handshake hijack attack attempt.


stream injection detection
--------------------------

Segment veto and sloppy injection attacks are detected by means of a retrospective analysis. HoneyBadger reassembles the TCP stream into a ring buffer so that received packets with overlapping data can be compared to the latest reassembled portion of our TCP stream. If their corresponding stream data is the same then of course the packet came from a normal TCP retransmission. However if their contents differ at all this must mean that a TCP injection attack attempt was made. HoneyBadger performs TCP directional state tracking, for each direction it keeps track of the "next Sequence" value. The reassembled TCP stream which is written to a ring buffer is traversed for content comparison for each packet that has a Sequence proceeding the TCP state-machine's "next Sequence".

In principal HoneyBadger of course cannot determine which packet was sent by an attacker and which was sent by the legit connection party. However we speculate that in the wild, injected packets will have interesting and varying TTLs. This and other header fields might make it possible to develop some heuristics for distinguishing injected packets. That speculation aside, HoneyBadger does detect and record TCP injection attack attempts with precision.


other projects
--------------

Recently it was brought to my attention that NetResec wrote another article
about TCP injection attacks entitled "Covert Man on the Side Attacks" [23]_
wherein they announce yet another tool written in golang called qisniff.

I tested qisniff with my archive of pcap files ( https://github.com/david415/honeybadger-pcap-files )
and it does detect segment veto and sloppy injection but not handshake hijack injection attacks.
https://github.com/zond/qisniff

Bro:
https://www.bro.org/index.html

FOX-IT's patch to snort:
https://github.com/fox-it/quantuminsert/tree/master/detection/snort

Suricata:
https://github.com/fox-it/quantuminsert/tree/master/detection/suricata
https://github.com/inliniac/suricata



future work and projects
------------------------

I hope that other software developers will create additional tools to detect TCP injection attacks. So far the only other group that has done so publicly is FOX-IT with their patch to Snort. [21]_ If language security is a concern then you might prefer to use HoneyBadger which is pure Golang (except for the optional usage of the libpcap for sniffing). Rust is also an excellent choice however there does not yet exist a low level networking library for Rust with a TCP decoding layer... however libpnet shows lots of promise. [22]_

In the context of TCP injection attacks, a honeypot might include two main sandboxed componenents; an application that will use a plaintext TCP protocol which may become compromised when it receives a TCP injection attack, and a TCP injection attack detection system with (optional) full-take logging (i.e. HoneyBadger).

We further speculate that HoneyBadger (and other passive protocol analyzers that detect TCP injection attacks) could assist computer security researchers who use various tactics to "attract" injection attacks. In that case, HoneyBadger can be used to record the packet payloads and metadata about the attacks. These attack attraction tactics could range from custom automated web crawlers or programs to control tbb/firefox to manually utilizing a sandboxed browser to visit "high risk" web sites and use "high risk" search terms. In this case we mean high risk to indicate that these may be XKeyscore "Selectors" utilized by the "five-eyes" for automated computer network exploitation. However, any ISP or country with Internet access should be able to perform these types of attacks upon traffic traversing their networks.

Tor exit relay operators may be interested in running HoneyBadger to collect statistics about attacks that are targetting users of the Tor network. Only the Tor exit relay operators will be able to detect if a Tor user's TCP traffic has been attacked by an injection... therefore it might make sense for there to be an "opt-in" mechanism for Tor users wishing to be alerted when their traffic has been attacked.

It is also possible for Tor users to operate their own Tor exit relays AND run honeybadger on them all to record attacks upon their own traffic. In this case even if the Tor exit's country's telecommunications laws are very strict it should still be legal given that the operator consents to recording her own traffic.



url references
--------------

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
.. [21] https://blog.fox-it.com/2015/04/20/deep-dive-into-quantum-insert/
.. [22] http://octarineparrot.com/assets/msci_paper.pdf
.. [23] http://www.netresec.com/?page=Blog&month=2015-09&post=Covert-Man-on-the-Side-Attacks
