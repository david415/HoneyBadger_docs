
HoneyBadger
===========

.. image:: images/honey_badger-red-sm.png

**TCP attack inquisitor and 0-day catcher.**

HoneyBadger is a comprehensive TCP stream analysis tool for detecting and recording TCP attacks.
HoneyBadger includes a variety of TCP stream injections attacks which will prove that the TCP attack detection is reliable.
HoneyBadger is modern software written in Golang to deal with TCP's very olde security issues.
It is free software, using the GPLv3 and the source code is available on github:

* https://github.com/david415/HoneyBadger


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

1. build honey_badger.go and spray_injector.go (located in the tools directory in the source repository)

2. run **honey_badger** with these arguments... Note we are telling honey_badger to write log files to the current working directory.

  .. code-block:: bash

    ./honey_badger -i=lo -f="tcp port 9666"  -l="."

3. run **spray_injector** with these arguments

  .. code-block:: bash

    ./spray_injector -d=127.0.0.1 -e=9666 -f="tcp" -i=lo

4. start the netcat server

  .. code-block:: bash

    nc -l -p 9666

5. start the netcat client

  .. code-block:: bash

    nc 127.0.0.1 9666

6. In this next step we enter some data on the netcat server so that it will send it to the netcat client that is connected until the spray_injector prints a log message containing "packet spray sent!" In that cause the TCP connection will have been sloppily injected.

7. Look for the log files in honey_badger's working directory. You should see two files beginning with "127.0.0.1"; the pcap file is a full packet log of that TCP connection which you can easily view in Wireshark et al. The JSON file contains attack reports. This is various peices of information relevant to each TCP injection attack. The **spray_injector** tends to produce several injections... and does so sloppily in regards to keeping the client and server synchronized.

  .. code-block:: none

    $ ls 127*
    127.0.0.1:33962-127.0.0.1:9666.pcap  127.0.0.1:9666-127.0.0.1:33962.attackreport.json

