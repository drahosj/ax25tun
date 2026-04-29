# AX.25 Stack in Userspace
RIP kernel AX.25 stack, you will be dearly missed.

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=64edfa65062d

This is the start of a stack to implement the necessary bits to connect a TUN
interface to a KISS TNC. The main goal will be to
support the Direwolf's KISS-over-TCP interface.

Honestly, it shouldn't be that much code:

### Transmit
- Create TUN interface (done)
- Lookup destination address from an internal ARP table (done for ipv4)
- Send ARP request for unresolved addresses (done)
- Enqueue packets pending ARP resolution (done)
- Encapsulate IP packets in AX.25 and KISS then send to Direwolf (done)

### Receive
- Synchronize to KISS stream (done)
- De-encapsulate KISS and process (done)
- Respond to ARP requests
- Populate ARP table from ARP responses and send queued packets
- De-encapsulate matching unicast frames and pass to TUN (done)


### Housekeeping
- epoll loop
- ARP housekeeping?
