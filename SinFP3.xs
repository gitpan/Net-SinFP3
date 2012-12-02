/*
 * $Id: SinFP3.xs 2220 2012-12-02 16:56:10Z gomor $
 *
 *  /!\  DON'T NEVER EVER LOOK AT THIS CODE, YOU MAY DIE
 *
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

//#define DEBUG  1

#define TCP_LEN       40
#define TCP_OPT_LEN   20
#define TCP_PHDR4_LEN 12
#define TCP_PHDR6_LEN 36

#define MAXERRBUF 1024

char sinfp3_errbuf[MAXERRBUF];
int  sinfp3_isrand = 0;

struct tcphdr {
   u_int16_t th_sport;
   u_int16_t th_dport;
   u_int32_t th_seq;
   u_int32_t th_ack;
   u_int8_t  th_x2:4, th_off:4;
   u_int8_t  th_flags;
   u_int16_t th_win;
   u_int16_t th_sum;
   u_int16_t th_urp;
};

struct ptcphdr4 {
   in_addr_t ip_src;
   in_addr_t ip_dst;
   u_int16_t ip_p;
   u_int16_t tcp_len;
   struct tcphdr tcp_hdr;
   u_int8_t tcp_opt[TCP_OPT_LEN];
};

struct ptcphdr6 {
   struct in6_addr ip_src;
   struct in6_addr ip_dst;
   u_int16_t ip_p;
   u_int16_t tcp_len;
   struct tcphdr tcp_hdr;
   u_int8_t tcp_opt[TCP_OPT_LEN];
};

u_int16_t
_sinfp3_csum(u_int16_t *buf, int nwords)
{
   u_int32_t sum;

   for (sum = 0; nwords > 0; nwords--) {
      sum += *buf++;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);

   return ~sum;
}

int
_sinfp3_socket(int v6, struct addrinfo *asrc)
{
   int r;
   int fd;

   fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW, IPPROTO_TCP);
   if (fd < 0) {
      memset(sinfp3_errbuf, 0, MAXERRBUF);
      snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_socket: %s", strerror(errno));
      return(0);
   }

   if (asrc != NULL) {
      r = bind(fd, (const struct sockaddr *)asrc->ai_addr, asrc->ai_addrlen);
      if (r < 0) {
         memset(sinfp3_errbuf, 0, MAXERRBUF);
         snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_socket: bind: %s", 
            strerror(errno));
         return(0);
      }
   }

   return(fd);
}

int
_sinfp3_inet_addr(const char *ip)
{
   in_addr_t a;

   a = inet_addr(ip);
   if (a == INADDR_NONE) {
      memset(sinfp3_errbuf, 0, MAXERRBUF);
      snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_inet_addr: %s for [%s]",
               strerror(errno), ip);
      return(0);
   }

   return(a);
}

int
_sinfp3_sendto(int sockfd, const void *buf, size_t len, int flags,
            const struct sockaddr *dest_addr, socklen_t addrlen,
            char *ip_dst)
{
   int r;

   r = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
   if (r < 0) {
      memset(sinfp3_errbuf, 0, MAXERRBUF);
      snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_sendto: %s [to %s]",
               strerror(errno), ip_dst);
      return(0);
   }

   return(1);
}

void *
_sinfp3_malloc(size_t size)
{
   void *ptr;

   ptr = malloc(size);
   if (ptr == NULL) {
      memset(sinfp3_errbuf, 0, MAXERRBUF);
      snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_malloc: %s", strerror(errno));
      return(NULL);
   }

   return(ptr);
}

int
_sinfp3_getaddrinfo(const char *node, const char *service,
                 const struct addrinfo *hints, struct addrinfo **res)
{
   int r;

   r = getaddrinfo(node, service, hints, res);
   if (r < 0) {
      memset(sinfp3_errbuf, 0, MAXERRBUF);
      snprintf(sinfp3_errbuf, MAXERRBUF - 1, "_sinfp3_getaddrinfo: %s [%s]",
               gai_strerror(r), node);
      return(0);
   }

   return(1);
}

int
sinfp3_tcp_synscan(char *ip_src, char **ip_dst, int ndst, int *ports,
                   int nports, int pps, int n, int v6, int ip_as_int,
                   int *ip_dst_int, int level)
{
   int r;
   int fd;
   int i;
   int j;
   int k;
   int nwords;
   struct addrinfo hints;
   struct addrinfo *asrc;
   struct addrinfo *adst;
   struct sockaddr_in  *ptr4;
   struct sockaddr_in6 *ptr6;
   u_int8_t datagram[TCP_LEN];
   u_int8_t *pdatagram;
   time_t begin;
   time_t now;
   int count;
   int scount;
   int npackets = 0; // Total number of packets
   int runtime  = 0; // Estimated running time
   int us       = 0; // Sleep time in us (minimum 10ms, per classic OS)
   float every  = 0; // Sleep every number of packets
   struct ptcphdr4 *ptcph4;
   struct ptcphdr6 *ptcph6;
   struct tcphdr   *tcph;

   if (sinfp3_isrand == 0) {
      srandom(time(NULL) / getpid());
      sinfp3_isrand++;
   }

   if (! v6) {
      pdatagram = (u_int8_t *)_sinfp3_malloc(TCP_LEN + TCP_PHDR4_LEN);
      if (pdatagram == NULL)
         return(0);
      ptcph4    = (struct ptcphdr4 *)pdatagram;
      tcph      = (struct tcphdr *) (pdatagram + TCP_PHDR4_LEN);
   }
   else {
      pdatagram = (u_int8_t *)_sinfp3_malloc(TCP_LEN + TCP_PHDR6_LEN);
      if (pdatagram == NULL)
         return(0);
      ptcph6    = (struct ptcphdr6 *)pdatagram;
      tcph      = (struct tcphdr *) (pdatagram + TCP_PHDR6_LEN);
   }

   memset(&hints, 0, sizeof(hints));
   if (! v6) {
      hints.ai_family = AF_INET;
   }
   else {
      hints.ai_family = AF_INET6;
   }
   hints.ai_flags    = AI_NUMERICHOST;
   hints.ai_socktype = SOCK_RAW;
   hints.ai_protocol = IPPROTO_RAW;

   asrc = (struct addrinfo *)_sinfp3_malloc(sizeof(struct addrinfo));
   if (asrc == NULL) {
      free(pdatagram);
      return(0);
   }
   r = _sinfp3_getaddrinfo(ip_src, NULL, &hints, &asrc);
   if (r == 0) {
#ifdef DEBUG
      fprintf(stderr, "ERROR in _sinfp3_getaddrinfo\n");
#endif
      freeaddrinfo(asrc);
      free(pdatagram);
      return(0);
   }

   memset(datagram, 0, TCP_LEN);
   if (! v6) {
      memset(pdatagram, 0, TCP_PHDR4_LEN + TCP_LEN);
   }
   else {
      memset(pdatagram, 0, TCP_PHDR6_LEN + TCP_LEN);
   }

   if (! v6) {
      ptr4 = (struct sockaddr_in *)asrc->ai_addr;
      memcpy(&(ptcph4->ip_src), &(ptr4->sin_addr), 4);
      ptcph4->ip_p             = ntohs(6);
      ptcph4->tcp_len          = ntohs(TCP_LEN);
      ptcph4->tcp_hdr.th_ack   = 0;
      ptcph4->tcp_hdr.th_x2    = 0;
      ptcph4->tcp_hdr.th_off   = TCP_LEN >> 2;
      ptcph4->tcp_hdr.th_flags = 0x02;
      ptcph4->tcp_hdr.th_win   = htons(5840);
      ptcph4->tcp_hdr.th_sum   = 0;
      ptcph4->tcp_hdr.th_urp   = 0;
      // MSS 1460
      //memcpy(ptcph4->tcp_opt, "\x02\x04\x05\xb4", TCP_OPT_LEN);
      memcpy(ptcph4->tcp_opt, "\x02\x04\x05\xb4\x08\x0a\x44\x45\x41\x44\x00\x00\x00\x00\x03\x03\x01\x04\x02\x00", TCP_OPT_LEN);
   }
   else {
      ptr6 = (struct sockaddr_in6 *)asrc->ai_addr;
      memcpy(&(ptcph6->ip_src), &(ptr6->sin6_addr), 16);
      ptcph6->ip_p             = ntohs(6);
      ptcph6->tcp_len          = ntohs(TCP_LEN);
      ptcph6->tcp_hdr.th_ack   = 0;
      ptcph6->tcp_hdr.th_x2    = 0;
      ptcph6->tcp_hdr.th_off   = TCP_LEN >> 2;
      ptcph6->tcp_hdr.th_flags = 0x02;
      ptcph6->tcp_hdr.th_win   = htons(5840);
      ptcph6->tcp_hdr.th_sum   = 0;
      ptcph6->tcp_hdr.th_urp   = 0;
      // MSS 1460
      //memcpy(ptcph6->tcp_opt, "\x02\x04\x05\xb4", TCP_OPT_LEN);
      memcpy(ptcph6->tcp_opt, "\x02\x04\x05\xb4\x08\x0a\x44\x45\x41\x44\x00\x00\x00\x00\x03\x03\x01\x04\x02\x00", TCP_OPT_LEN);
   }

   fd = _sinfp3_socket(v6, asrc);
   if (fd == 0) {
#ifdef DEBUG
      fprintf(stderr, "ERROR in _sinfp3_socket\n");
#endif
      freeaddrinfo(asrc);
      free(pdatagram);
      return(0);
   }

   begin    = time(NULL);
   count    = 0;
   scount   = 0;
   npackets = nports * ndst * n;
   runtime  = npackets / pps;
   us       = 10000; // Minimum delay 10ms, per classic OS restiction
   every    = ((float)pps / (float)us) * 100.00;

   if (level >= 2) {
      fprintf(stderr, "[*] [XS] Sleeping for 10ms every %d packet(s) during %d seconds\n", (int)every, runtime);
   }

   for (i=0; i<nports; i++) {
      if (! v6) {
         ptcph4->tcp_hdr.th_sport = htons(random());
         ptcph4->tcp_hdr.th_dport = htons(ports[i]);
         ptcph4->tcp_hdr.th_seq   = random();
      }
      else {
         ptcph6->tcp_hdr.th_sport = htons(random());
         ptcph6->tcp_hdr.th_dport = htons(ports[i]);
         ptcph6->tcp_hdr.th_seq   = random();
      }

      for (j=0; j<ndst; j++) {
         //printf("Target [%s]:%d [ipv6:%d]\n", ip_dst[j], ports[i], v6);

         if (! ip_as_int) {
            adst = (struct addrinfo *)_sinfp3_malloc(sizeof(struct addrinfo));
            if (adst == NULL) {
#ifdef DEBUG
               fprintf(stderr, "ERROR in _sinfp3_malloc\n");
#endif
               freeaddrinfo(asrc);
               free(pdatagram);
               return(0);
            }
            r = _sinfp3_getaddrinfo(ip_dst[j], NULL, &hints, &adst);
            if (r == 0) {
#ifdef DEBUG
               fprintf(stderr, "ERROR in _sinfp3_getaddrinfo\n");
#endif
               freeaddrinfo(asrc);
               freeaddrinfo(adst);
               free(pdatagram);
               return(0);
            }
         }

         if (! v6) {
            if (! ip_as_int) {
               ptr4 = (struct sockaddr_in *)adst->ai_addr;
               memcpy(&(ptcph4->ip_dst), &(ptr4->sin_addr), sizeof(in_addr_t));
            }
            else {
               //fprintf(stderr, "DEBUG: IP: %d\n", ip_dst_int[j]);
               ptcph4->ip_dst = htonl(ip_dst_int[j]);
            }
            // Compute checksums
            nwords                 = (TCP_LEN + TCP_PHDR4_LEN) * 8 / 16;
            ptcph4->tcp_hdr.th_sum = _sinfp3_csum((u_int16_t *)ptcph4, nwords);
         }
         else {
            ptr6 = (struct sockaddr_in6 *)adst->ai_addr;
            memcpy(&(ptcph6->ip_dst), &(ptr6->sin6_addr), 16);
            // Compute checksums
            nwords                 = (TCP_LEN + TCP_PHDR6_LEN) * 8 / 16;
            ptcph6->tcp_hdr.th_sum = _sinfp3_csum((u_int16_t *)ptcph6, nwords);
         }

         memcpy(datagram, tcph, TCP_LEN);

         for (k=0; k<n; k++) {
            if (! ip_as_int) {
               r = _sinfp3_sendto(fd, (u_int8_t *)datagram, TCP_LEN, 0,
                                  adst->ai_addr, adst->ai_addrlen,
                                  ip_dst[j]);
            }
            else {
               struct sockaddr_in sin;
               memset(&sin, 0, sizeof(sin));
               sin.sin_family = AF_INET;
               sin.sin_addr.s_addr = htonl(ip_dst_int[j]);
               r = _sinfp3_sendto(fd, (u_int8_t *)datagram, TCP_LEN, 0,
                                  (const struct sockaddr *)&sin, sizeof(sin),
                                  NULL);
            }
            if (r == 0) {
#ifdef DEBUG
               fprintf(stderr, "WARNING: %s\n", sinfp3_errbuf);
#endif
               continue;
            }
            count++;
            scount++;

            // Sleep every X packet
            if (scount > (int)every) {
               usleep(us);
               scount = 0;
            }

            if (level >= 1) {
               // Print stats and reset count
               now = time(NULL);
               if (now - begin >= 1) {
                  fprintf(stderr, "[+] [XS] Sent %d pps (i/o %d pps), time to sleep %d ms (total packets: %d)\n",
                          count, pps, us / 1000, npackets);
                  begin = time(NULL);
                  count = 0;
               }
            }
         }

         // Reset checksum for next round
         if (! v6) {
            ptcph4->tcp_hdr.th_sum = 0;
         }
         else {
            ptcph6->tcp_hdr.th_sum = 0;
         }
         if (! ip_as_int) {
            freeaddrinfo(adst);
         }
      }
   }
   freeaddrinfo(asrc);
   free(pdatagram);

   close(fd);

   return(1);
}

char *
sinfp3_geterror(void)
{
   return((char *)sinfp3_errbuf);
}

MODULE = Net::SinFP3  PACKAGE = Net::SinFP3
PROTOTYPES: DISABLE

int
sinfp3_tcp_synscan(src, dst, ports, pps, n, v6, ip_as_int, level)
      char *src
      SV   *dst
      SV   *ports
      int   pps
      int   n
      int   v6
      int   ip_as_int
      int   level
   PREINIT:
      if (!SvROK(ports) || SvTYPE((SV *)SvRV(ports)) != SVt_PVAV) {
         croak("Argument ports shall be an ARRAYREF");
      }
      if (!SvROK(dst) || SvTYPE((SV *)SvRV(dst)) != SVt_PVAV) {
         croak("Argument dst shall be an ARRAYREF");
      }
   INIT:
      int i;
      AV *p = (AV *)SvRV(ports);
      AV *d = (AV *)SvRV(dst);
      int plen = av_len(p) + 1;
      int dlen = av_len(d) + 1;
      int *cports;
      char *targets[dlen];
      int  *targets_int;
      Newx(cports, plen, int);
      Newx(targets_int, dlen, int);
   CODE:
      for (i=0; i<plen; i++) {
         SV **e = av_fetch(p, i, 0);
         cports[i] = SvIV(*e);
      }
      if (! ip_as_int) {
         for (i=0; i<dlen; i++) {
            STRLEN l;
            targets[i] = SvPV(*av_fetch(d, i, 0), l);
         }
      }
      else {
         for (i=0; i<dlen; i++) {
            SV **e = av_fetch(d, i, 0);
            targets_int[i] = SvIV(*e);
         }
      }
      RETVAL = sinfp3_tcp_synscan(src, targets, dlen, cports, plen, pps, n,
                                  v6, ip_as_int, targets_int, level);
   OUTPUT:
      RETVAL

char *
sinfp3_geterror()
