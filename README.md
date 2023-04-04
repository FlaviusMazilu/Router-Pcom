# Router
----
## Tasks solved
- Forwarding process
- Longest Prefix Match using trie
- ARP
- ICMP
---
## Structure
- ``router.c router.h`` -> main function
- ``icmp.c icmp.h`` -> functions for sending icmp packets
- ``arp.c arp.h`` -> contains arp queue, arp table, send and receive arp packets 
- ``trie.c trie.h`` -> search & insert in rtable
- ``utils.c utils.h`` -> auxiliary functions
---
## How it was implemented
- Firstly, we receive a frame and we (as in, the router) have to decide whether it's ``for us`` (check destionation mac address). If it's broadcast/our mac, we have to process it, otherwise, discard it.


- After we checked it's for us, we have to decide what kind of ``protocol`` the ethernet header ``encapsulates``.
    - And from here we have two options:
    - IP header, and it is called the ``hadle_ip_packet``
    - or ARP header, and it's called handle ``arp_packet``
- Handle_ip_packet *function*: 
    - recalculates ``checksum``
    - tests whether the ``IP destination is us``, the router, if it's true, calls handle_icmp, supposing it's an echo request kind of message for us.  
    - Updates the ``TTL`` -> if its 0 or 1 drops it and sends an icmp message notifying the sender why it has been dropped.
    - ``Updates checksum``, with the new TTL
    - Finds the ``next hoop`` where the packet has to go, for that is looked up in a ``trie`` in function ``search_next_hoop``. If there is no next hoop for the ip looked for, drops it and sends an icmp with the message Destination unreachable, otherwise, proceeds with sending it forward
    - With ``find_mac_address_in_arp`` gets the mac address of the next_hoop, because we only have it's ip, not the mac.
        - If there's ``no entry`` for it in the ``ARP table``, puts the packet on hold, in a queue, for it to be ``sent later`` when the mac address asociated with the ip is available. (create_arp_queue_entry() + arp_enq()) and sends an ``arp request``, broadcasting a message asking for the mac address of next_hoop->ip.
        - Otherwise, it proceeds with sending the frame forward, by now we know everything we need for sending it to the next hoop.
- handle_arp_packet *function*:
    - Tests to see if the received packet is a ARP Request or ARP Reply.
    - If it's an ``ARP Request``, calls function ``handle_arp_recv_request``, creates a new frame in which sourse and destination mac are swapped from the received frame, in ether_header, and completing the source ip and mac with it's own in arp header.
    - If it's an ``ARP Reply``, means that the router initiated an ARP Request beforehand. It ``saves the frame's source mac and ip address`` in it's ``ARP Table``. it Searches through the queue of packets waiting for a destination mac address and if the significant pachet was waiting for the arrived mac, all it has to do is ``complete the destination mac`` and ``send it``(it was put in queue with all the other informations it needed besides the destination mac). After that, it is removed from the queue.
- handle_icmp *function*:
    - It's the ``default function`` called when an ``icmp message`` needs to be sent (destination unreachable, ttl expired, echo reply) receiving as a ``parameter`` the type and code of the icmp message, being able to guide itself from these to send the right icmp message.
    - The ethernet and ip header it the same for all types of icmp messages, besides the ip len field, which is calculated separately considering icmp type.
    - For completing the icmp header and the payload, 2 functions are possibly called
        - ``icmp_echo_reply()``, which populates icmp header with the specific fields(id and sequence from the received icmp request) and the payload being the payload from original frame.
        - ``icmp_ttl_or_unrec()``, which sends ip header + 8 bytes after from original frame.
- For efficiency, ``searching`` the next hoop in the ``Routing Table`` by longest prefix, it was used a trie. Every node in the trie it's ``a bit`` from the ip address, the lowest being the ``longest prefix``. At the start of the router, the trie is populated with the entries from rtable.