

how to badger the puppet masters
================================

abstract
--------

HoneyBadger is a passive TCP protocol analyzer whose only purpose in life is to detect and optionally record TCP injection attacks. HoneyBadger has been called a "Quantum-Insert detector" because it can detect the NSA's "Quantum" attacks. However other researchers have already commented on various other entities who utilize these attacks [?] [?], and there are several kinds of attacks that are used with varying degrees of sophistication needed to perform them.

Many of these well-funded state/world-class adversaries are able to completely automate the compromising of computers using these TCP injection attacks. This is especially dangerous to journalists and activists when this auto-compromising happens based on key-word searches and participation in specific online forums.

Widespread adoption of TCP injection attack detection software such as HoneyBadger will diminish the effective secrecy of these attacks. Additionally, these deployments of HoneyBadger could provide enlightening attack statistics that may prove useful to security researchers, contributing to the responsible disclosure of stock-piled zero-days that currently threaten our intellectual freedoms.



introduction
------------

Powerful entities world wide are stock piling zero-days. TCP injection attacks are used to deliver these attacks. The more sophisticated adversaries will use a security domain isolation policy to make sure their attack logic is located in a protected area of their network while they utilize multiple network taps and injection hosts in multiple locations. It is clear from the Snowden documents that at least in the past the NSA has utilized botnets (large groups of compromise computers connected to the Internet) hosts as "Quantum Shooters", hosts that send the injection attack packets to the target upon receiving "injection tips" (recent TCP Sequence numbers read from a network tap).



TCP injection attacks
---------------------

TCP injection attacks are man-on-the-side attacks (MOTS) [1]_ and are not the same thing as man-in-the-middle attacks (MITM). The definition of MOTS is when the attack controls one or more communications channels in the route. That is, the ability to read or write packets; in other more eloquent words from Wikipedia: "Instead of completely controlling a network node as in a man-in-the-middle attack, the attacker only has regular access to the communication channel, which allows him to read the traffic and insert new messages, but not to modify or delete messages sent by other participants." [1]_ Much of the classic literature about TCP injection attacks considers TCP injection in the context of probabilistic TCP Sequence number prediction. [2]_ [3]_  These olde school attacks focused more on exploiting TCP Sequence number prediction and side channels, however TCP injection attacks are essentially a form of timing  attack. Since the various improvements to the TCP's initial Initial Sequence Numbers (ISNs) [4]_ [5]_, TCP was widely believed to not be vulnerable to injection attacks, however TCP has remained vulnerable to various Sequence prediction based injection attacks, including side channel inference attacks [6]_ [7]_ [8]_. Various so called classic and modern TCP injection attacks can involve  an "off-path injection". These are remarkable deployment tactics where the attack packets originate from hosts that are not directly in either route between host Alice and host Bob. Ingress filtering may make this IP spoofing between networks less  commonly available than before but still feasible today [6]_.

These injection hosts behave as "write-only network taps" in so far as they have the ability to inject packets but not read. It is my understanding that the secret NSA documents refer to these injection hosts as "QUANTUM shooters" [9]_.  According to a Der Spiegal article about leaked NSA documents, these shooters create a layer of indirection that might be  used to make TCP injection attacks harder to track down: "And computers infected with Straitbizarre can be turned into disposable  and non-attributable 'shooter' nodes." [10]_ We've also seen other code names for the shooters such as Straightbizarre and Daredevil. [11]_  According to a Guardian article the NSA may be using a topologically advantageous placement of servers in the network to win the packet race: "the NSA places secret servers, codenamed Quantum, at key places on the internet backbone. This  placement ensures that they can react faster than other websites can." [12]_ [13]_ One Wired article mentions that the NSA could be using MOTS attacks  rather than MITM attacks because it fit's their security domain isolation policy with regards to where attack logic is placed. [14]_ Any world class attacker such as the NSA would likely have measures to prevent leaking their 0-day to security researchers and adversaries. [15]_

According to various security researchers and leaked documents, there  is the so called lawful intercept industry where governments and other organizations with known track records of human right violations can illegally purchase "hacking appliances". [16]_ [17]_ [18]_ These MOTS appliances might offer an advantage over MITM attacks in that  they may be very simple to deploy. Perhaps by plugging into a mirrored switch port. [20]_

There exist multiple entities world wide that posses the capability to perform these TCP injection attacks with a very high probability of success, however they may not all have the same operational security policies. For instance perhaps the NSA has a policy of not deploying attack logic to insecure systems or physical facilities. I speculate that they have a security domain isolation policy that causes them to prefer an offsite MOTS approach over an onsite MOTS or MITM. The attacker might have an offsite command and control (C&C) center which passes instructions to these "shooters", who then perform the actual TCP injection attack on behalf of the C&C.



TCP injection attack categories
-------------------------------

Below I've outlined 5 categories of TCP injection attack... but more broadly speaking there are two categories of TCP injection attack: "handshake hijack" and "post-handshake stream injection".

::

1. **handshake hijack:** After the client's initial SYN packet is sent, the attacker's SYN/ACK response packet is received by the client before the legitimate server's SYN/ACK packet. Finally the client responds to the SYN/ACK with it's ACK packet. After that, the attacker has control over the server side of the connection. When the legitimate server receives the client's ACK packet it will send an RST; the client will close the connection when it receives the RST packet, therefore the attacker has a very limited amount of time with which to send her malicious payload.
   
2. **segment veto:** the injected packet(s) have the precise TCP Sequence number needed for injection and are the exact same size as those sent out by the legit party. Client and server remain in sync after data is injected.

3. **sloppy injection:** the injected packet(s) have the precise TCP Sequence number needed for injection, however the payload differs in size to that of the legit party. Client and server fall out of sync after injection.

4. **out-of-order coalesce injection:** injected packets with TCP Sequence numbers that come after the receiving TCP state-machine's "next sequence number". Injection of data into the application is slightly delayed by the TCP state-machine's coalesce of out-of-order packets.

5. **censorship injection:** injected packets are TCP FIN or RST which causes the TCP connection to close. This attack could be performed as an ordered or out-of-order coalesce injection attack.


**remarks about the TCP injection attack categories:** Category 1; handshake hijack doesn't have any variations that I'm aware of. Categories 2 and 3 are essentially the same type of injection attack. Categories 2-4 could have many variations for instance a sloppy injection could be  followed up with a procedure that gradually brings client and server back into TCP Sequence  synchronization. An out-of-order coalesce injection could be used to slightly obscure the attack payload by sending overlapping future out-of-order packets. Due to the "selective acknowledgement" TCP option the first future out-of-order TCP segment received wins the privilege of it's payload being coalesced into the TCP stream. Category 5, a censorship injection is it's own category of injection attack because it doesn't actually inject anything into the TCP stream but still requires that precise TCP Sequence to perform the attack.


handshake hijack detection
--------------------------

HoneyBadger does some fairly simple state tracking to detect handshake hijack attacks. When a TCP connection receives a SYN/ACK packet during the handshake we record the Sequence and Acknowledgement numbers. A normal TCP SYN/ACK retransmission will have the exact same TCP Sequence number... however if we receive mulitple SYN/ACK packets with different Sequence numbers this indicates a handshake hijack attack attempt.


stream injection detection
--------------------------

Segment veto and sloppy injection attacks are detected by means of a retrospective analysis. HoneyBadger reassembles the TCP stream into a ring buffer so that received packets with overlapping data can be compared to the latest reassembled portion of our TCP stream. If their corresponding stream data is the same then of course the packet came from a normal TCP retransmission. However if their contents differ at all this must mean that a TCP injection attack attempt was made. HoneyBadger performs TCP directional state tracking, for each direction it keeps track of the "next Sequence" value. The reassembled TCP stream which is written to a ring buffer is traversed for content comparison for each packet that has a Sequence proceeding the TCP state-machine's "next Sequence".

In principal HoneyBadger of course cannot determine which packet was sent by an attacker and which was sent by the legit connection party. However we speculate that in the wild, injected packets will have interesting and varying TTLs. This and other header fields might make it possible to develop some heuristics for distinguishing injected packets. That speculation aside, HoneyBadger's priority is to detect and record TCP attack attempts with the utmost precision.



how to turn HoneyBadger into a honeyPot
---------------------------------------

In the context of TCP injection attacks, a honeypot might include two main sandboxed componenents; an application that will use a plaintext TCP protocol which may become compromised when it receives a TCP injection attack, and a TCP injection attack detection system with (optional) full-take logging (i.e. HoneyBadger).

We further speculate that HoneyBadger could assist computer security researchers who use various tactics to "attract" injection attacks. In that case, HoneyBadger can be used to record the packet payloads and metadata about the attacks. These attack attraction tactics could range from custom automated web crawlers or programs to control tbb/firefox to manually utilizing a sandboxed browser to visit "high risk" web sites and use "high risk" search terms. In this case we mean high risk to indicate that these may be XKeyscore "Selectors" utilized by the "five-eyes" for automated computer network exploitation (CNE). However, any ISP or country with Internet access should be able to perform these types of attacks upon traffic traversing their networks.

Tor relay operators may be interested in running HoneyBadger to collect statistics about attacks that are targetting users of the Tor network. Only the Tor exit relay operators will be able to detect if a Tor user's TCP traffic has been attacked by an injection... therefore it might make sense for there to be an "opt-in" mechanism for Tor users wishing to be alerted when their traffic has been attacked.

It is also possible for Tor users to operate their own Tor exit relays AND run honeybadger on them all to record attacks upon their own traffic. In this case even if the Tor exit's country's telecommunications laws are very strict it should still be legal given that the operator consents to recording her own traffic.



sandboxing
----------

When conducting these experiments the application should be thoroughly sandboxed because it will most likely become compromised. Clearly Qubes OS is the most secure and convenient choice for software sandboxing on workstations with insecure applications such as web browsers.

https://www.qubes-os.org/

Perhaps some researchers will operate with the threat model assumption that for this type of scenario it is better to not even run the compromised application on any of your own person computer equipment  at all. If your goal is to expose the attacks upon Tor users then you have the option to instead run the Tor Browser Bundle on a  cheap remote VPS (virtual private server). You can use ssh + vnc to interact with the browser remotely. I am a fan of this pure python VNC client that a friend pointed me to:

https://code.google.com/p/python-vnc-viewer

You can also run the Tor Browser Bundle and other browsers on a Raspberry Pi 2 running archlinux arm. This hardware might be cheaper to replace and easier to isolate. I've successfully built the Tor Browser Bundle for the Raspberry Pi 2 running ARM Archlinux, details here:

https://trac.torproject.org/projects/tor/ticket/12631#comment:6




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
