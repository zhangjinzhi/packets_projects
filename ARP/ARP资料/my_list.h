#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#undef __FAVOR_BSD
#include <errno.h>


struct fib_address
{
    struct in_addr       ip_dst;
    struct fib_address   *next;
    struct fib_address   *prev;
    int    chipnum;
};
typedef enum
{

    FIB_INTERNEL_NETWORK = 0,
    FIB_EXTERNEL_NETWORK

};
 
typedef struct fib_rules
{
    struct    in_addr         ip_src;            /* need's to be handled next step */
    unsigned  char             direction; /* to network or internel's network */
    struct    fib_address      *pdstaddr;        /* next address */
    struct    fib_rules        *next; 
    struct    fib_rules        *prev;
}FIB_RULE;
 
 
struct fib_key
{
    struct   in_addr  ip_dst;
    struct   in_addr  ip_src;
    unsigned char     direction;
    int     chipnum; 
};


extern int rules_memcmp(const void * cs,const void * ct,size_t count);
extern void rules_print();
extern int fib_rules_init(void);
extern int fib_rules_destroy(void);
extern int fib_rules_length(void);
extern int fib_rules_insert(struct fib_key *pfib_key);
extern int fib_rules_remove(struct fib_key *pfib_key);
extern int rules_memcmp(const void * cs,const void * ct,size_t count);
extern int fib_rules_removeRule(struct  in_addr *pip_src);
extern FIB_RULE *rules_isExist(struct in_addr *ip_src);
extern  int  getfilename(unsigned char chipNum, unsigned char *filename);  
