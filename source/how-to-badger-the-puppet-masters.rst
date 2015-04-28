

how to badger the puppet masters
================================


abstract
--------

"Puppet masters" refers to well funded state/world-class adversaries that use botnets to
distribute TCP injection attacks. Puppets assist but do not lead attacks,
in these off-path TCP injection attack scenarios there are offsite command and control centers
that contain the attack logic. Puppets can also refer to the computers that get compromised by
the injection attacks because the attackers essentially become the true masters of the compromised computers.

Widespread adoption of TCP injection attack detection software such as honeyBadger will diminish the effective
secrecy of these attacks upon the Tor network and other networks as well. Additionally these deployments of
honeybadger could provide enlightening attack statistics that may prove useful to security researchers,
contributing to the collection of zero days for the purpose of further study by malware analysts
and responsible disclosure to software vendors.


how to turn HoneyBadger into a honeyPot
---------------------------------------

In the context of TCP injection attacks, a honeypot might include two main sandboxed componenents;
an application that will use a plain-text TCP protocol and may become compromised when it receives a TCP injection attack,
and a TCP injection attack detection system with (optional) full-take logging (i.e. HoneyBadger).

We further speculate that honeyBadger could assist computer security researchers who use various tactics to "attract"
injection attacks. In that case, HoneyBadger can be used record the packet payloads and metadata about the attacks.
These attack attraction tactics could range from custome automated web crawlers or programs to control tbb/firefox
to manually utilizing a sandboxed browser to visit "high risk" web sites and use "high risk" search terms. In this case
we mean high risk to indicate that these may be XKeyscore "Selectors" utilized by the "five-eyes" for automated
computer network exploitation (CNE). However, any country with Internet access should be able to perform these
types of attacks upon traffic traversing their networks.


sandboxing
----------

When conducting these experiments the application should be thoroughly sandboxed because it will most likely become compromised.
Clearly Qubes OS is the most secure and convenient choice for software sandboxing insecure applications such as web browsers.

https://www.qubes-os.org/

Perhaps some researchers will operate with the threat model assumption that for this type of scenario it is better to not even run
the compromised application on any of your own person computer equipment at all. If your goal is to expose the attacks upon Tor
users then you have the option to instead run the Tor Browser Bundle on a cheap remote VPS (virtual private server). You can use
ssh + vnc to interact with the browser remotely. I am a fan of this pure python VNC client that a friend pointed me to:

https://code.google.com/p/python-vnc-viewer

You can also run the Tor Browser Bundle and other browsers on a Raspberry Pi 2 running archlinux arm. This hardware might be
cheaper to replace and easier to isolate. I've successfully built the Tor Browser Bundle for the Raspberry Pi 2 running ARM
Archlinux, details here:

https://trac.torproject.org/projects/tor/ticket/12631#comment:6


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
the specialized MoS "hacking appliances", however there are plausible theories for both cases. It could be that these MoS appliances
posses a high success rate due to being built with specialized high speed signal processing components that are capable of operating at
line speeds. [16]_ [17]_ [18]_ The world-class state adversaries utilizing the backbone-sniffing->C&C->puppet shooter pipeline approach
may utilize their own network infrastructure to ensure their winning the packet latency race against the legitimate actors.

It should be obvious that there exist multiple entities world wide that posses the capability to perform
these TCP injection attacks with a very high probability of success, however they may not all have the same operational security policies.
For instance perhaps the NSA has a policy of not deploying attack logic to insecure systems or physical facilities. I speculate that
they have a security domain isolation policy that causes them to prefer an offsite MoS approach over an onsite MoS or MITM. The attacker
might have an offsite command and control (C&C) center which passes instructions to these "shooter" puppets, who then perform the actual
TCP injection attack on behalf of the C&C.


TCP injection attack categories
-------------------------------

Broadly speaking there are two categories of TCP injection attacks; handshake hijack and stream injection.
I've added a couple more stream injection attack sub-categories to the list; here #2 "segment veto" and #3 "sloppy injection"
are nearly identical (honeybadger does not yet distinguish between them), whereas coalesce injection is quite different in that
the injected packets are sent out of order with future TCP Sequence numbers.

::

1. **handshake hijack:** the attacker responds to a SYN packet with their SYN/ACK packet before
the legit server.

2. **segment veto:** the injected packet(s) are the exact same size as those sent out by the legit party.
Client and server remain in sync after data is injected.

3. **sloppy injection:** the injected packet(s) are different sizes than that of the legit party.
Client and server fall out of sync after injection.

4. **out-of-order coalesce injection:** injected packets are ahead of the next sequence.
Injection of data takes place during coalescence.


**note:** Each of these TCP attacks are really broader categories of attack... for instance a sloppy injection could be followed up with a
procedure that gradually brings client and server back into TCP Sequence synchronization.



handshake hijack detection
--------------------------

HoneyBadger does some fairly simple state tracking to detect handshake hijack attacks.
When a TCP connection receives a SYN/ACK packet during the handshake we record the Sequence and Acknowledgement numbers.
A normal TCP SYN/ACK retransmission will have the exact same TCP Sequence number... however if we receive mulitple SYN/ACK
packets with different Sequence numbers this indicates a handshake hijack attack attempt.


stream injection detection
--------------------------

Segment veto and sloppy injection attacks are detected by means of a retrospective analysis.
HoneyBadger reassembles the TCP stream so that received packets with overlapping data can be compared.
If their data is the same then of course the packet came from a normal TCP retransmission.
However if their contents differ at all this must mean that a TCP injection attack attempt was made.
HoneyBadger performs TCP directional state tracking, for each direction it keeps track of the "next Sequence" value.
The reassembled TCP stream is written to a ring buffer... and this ring buffer is traversed for content comparison
for each packet that has a Sequence proceeding the "next Sequence".

In principal HoneyBadger of course **cannot** determine which packet was sent by an attacker and which was sent by the legit connection party.
However we speculate that in the wild, injected packets will have interesting and varying TTLs. This and other header fields
might make it possible to develop some heuristics for distinguishing injected packets. That speculation aside, HoneyBadger's
priority is to detect and record TCP attack attempts with the utmost precision.



future work
-----------

*coming soon*


conclusion
----------

*coming soon*



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
