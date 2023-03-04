OpenBSD TCP/IP overflow

Tested with latest OpenBSD 7.2

Details:

```
int
ip_dooptions(struct mbuf *m, struct ifnet *ifp)
{
	...
  for (; cnt > 0; cnt -= optlen, cp += optlen) {
                opt = cp[IPOPT_OPTVAL];
                if (opt == IPOPT_EOL)
                        break;
                if (opt == IPOPT_NOP)
                        optlen = 1;
                else {
                        if (cnt < IPOPT_OLEN + sizeof(*cp)) {
                                code = &cp[IPOPT_OLEN] - (u_char *)ip;
                                goto bad;
                        }
                        optlen = cp[IPOPT_OLEN];
[1]                     if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt) {
                                code = &cp[IPOPT_OLEN] - (u_char *)ip;
                                goto bad;
                        }
                }

                switch (opt) {

				  case IPOPT_LSRR:
                  case IPOPT_SSRR:
                        if (!ip_dosourceroute) {
                                type = ICMP_UNREACH;
                                code = ICMP_UNREACH_SRCFAIL;
                                goto bad;
                        }
                        if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
                                code = &cp[IPOPT_OFFSET] - (u_char *)ip;
                                goto bad;
                        }
 						...
						...	
						off--;                 
                        if ((off + sizeof(struct in_addr)) > optlen) {
                                save_rte(m, cp, ip->ip_src);
                                break;
                        }


	...
}

void
save_rte(struct mbuf *m, u_char *option, struct in_addr dst)
{
        struct ip_srcrt *isr;
        struct m_tag *mtag;
        unsigned olen;

        olen = option[IPOPT_OLEN];
        if (olen > sizeof(isr->isr_hdr) + sizeof(isr->isr_routes))
                return;

        mtag = m_tag_get(PACKET_TAG_SRCROUTE, sizeof(*isr), M_NOWAIT);
        if (mtag == NULL) {
                ipstat_inc(ips_idropped);
                return;
        }
        isr = (struct ip_srcrt *)(mtag + 1);

        memcpy(isr->isr_hdr, option, olen);
[2]     isr->isr_nhops = (olen - IPOPT_OFFSET - 1) / sizeof(struct in_addr);
        isr->isr_dst = dst;
        m_tag_prepend(m, mtag);
}



struct mbuf *
ip_srcroute(struct mbuf *m0)
{
        struct in_addr *p, *q;
        struct mbuf *m;
        struct ip_srcrt *isr;
        struct m_tag *mtag;

        if (!ip_dosourceroute)
                return (NULL);
		...
[3]		p = &(isr->isr_routes[isr->isr_nhops - 1]);
        *(mtod(m, struct in_addr *)) = *p--;

        /*
         * Copy option fields and padding (nop) to mbuf.
         */
        isr->isr_nop = IPOPT_NOP;
        isr->isr_hdr[IPOPT_OFFSET] = IPOPT_MINOFF;
        memcpy(mtod(m, caddr_t) + sizeof(struct in_addr), &isr->isr_nop,
            OPTSIZ);
        q = (struct in_addr *)(mtod(m, caddr_t) +
            sizeof(struct in_addr) + OPTSIZ);
#undef OPTSIZ
        /*
         * Record return path as an IP source route,
         * reversing the path (pointers are now aligned).
         */
[4]     while (p >= isr->isr_routes) {
                *q++ = *p--;
        }
	...
}

1. on line #1 - we can set optlen == 2
2. save_rte() will set isr_nhops to very large value, 
because (optlen - IPOPT_OFFSET - 1) equals to 0xffffffff (IPOPT_OFFSET=2)

3. ip_srcroute() call will trigger buffer overflow on loop #4
```

Preconditions:
```
1. source routing should be enabled for this to work.
2. we disable PF as it discards such packets
```

How to reproduce:
```
1. install OpenBSD
2. add the following line to /etc/sysctl.conf
net.inet.ip.sourceroute=1

3. run syspatch to install latest patches
4. reboot the system
5. disable pf
# pfctl -d

2. run proof of concept
```
