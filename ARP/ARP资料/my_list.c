/**********************************************************
* 版权所有 (C)2007, 深圳市中兴通讯股份有限公司。
*
* 文件名称：my_list.c
* 文件标识：
* 内容摘要： 转发表的处理函数
* 其它说明：
* 当前版本：
* 作    者：丁 鹏
* 完成日期：2007/12/11
*
* 修改记录1：   
*    修改日期： 
*    版 本 号：
*    修 改 人：                    
*    修改内容：
**********************************************************/

/***********************************************************
 *                      头文件                             *
***********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include "packet_gen.h"
#include "my_list.h"



/***********************************************************
 *                     全局变量                            *
***********************************************************/ 
struct fib_rules  *g_fibTable;
struct fib_rules  *fibTableHead;


/***********************************************************
 *                     全局函数                            *
***********************************************************/
int rules_memcmp(const void * cs,const void * ct,size_t count);
void rules_print();
int fib_rules_init(void);
int fib_rules_destroy(void);
int fib_rules_length(void);
int fib_rules_insert(struct fib_key *pfib_key);
int fib_rules_remove(struct fib_key *pfib_key);
int rules_memcmp(const void * cs,const void * ct,size_t count);
int fib_rules_removeRule(struct  in_addr *pip_src);
FIB_RULE *rules_isExist(struct in_addr *ip_src);

/**********************************************************************
* 函数名称：fib_rules_init
* 功能描述：转发表初始化
* 输入参数：
* 输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_init(void)
{
    fibTableHead = malloc(sizeof(struct fib_rules));
    if(fibTableHead == NULL)
    {
        printf("fib_rules_int: malloc fib memory err\n");
        return -1;
    }
    memset(fibTableHead, 0x00, sizeof(struct fib_rules));
    fibTableHead->next = fibTableHead->prev = NULL;
    return 1;
}

/**********************************************************************
* 函数名称：fib_rules_destroy
* 功能描述：转发表销毁
* 输入参数：
* 输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_destroy(void)
{
    struct fib_rules    *pFibRule, *pNode = fibTableHead;
    struct  fib_address *pAddr, *pAddNode;
    int i=0;
    int j = 0;
    pNode = pNode->next;
    while(pNode != NULL)
    {
        pFibRule = pNode;
          /* find dst address */
        pAddr = pNode->pdstaddr;
        while(pAddr != NULL)
        {
            pAddNode = pAddr;
            pAddNode->next = NULL;
            free(pAddNode);
            pAddr = pAddr->next;
            i++;
            printf("i = %d\n" , i);
        }    
        
        pNode->pdstaddr  = NULL;
        free(pNode);
        pNode    = pFibRule->next;
        j++;
        printf("j = %d\n" , j);
    }
    free(fibTableHead);
    fibTableHead = NULL;
    return 1;
}


/**********************************************************************
* 函数名称：fib_rules_length
* 功能描述：取得转发表长度
* 输入参数：
* 输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_length(void)
{
    unsigned int num = 0;
    struct fib_rules *pNode = fibTableHead;
     
    while(pNode != NULL)
    {
        num ++;
        pNode = pNode->next;
    }
    
    return num;
}

/**********************************************************************
* 函数名称：fib_rules_insert
* 功能描述：在转发表中插入一个规则
* 输入参数：pfib_key  规则关键字
* 输出参数：无
* 返 回 值：无
* 其它说明：转发表 转发项中根据src 源ip地址确定转发策略
            转发策略有 转发给外网
                            1. 转发到一个外网口
                            2. 转发到多个外网口
                       转发给内网
                            1. 转发到一个内网口
                            2. 转发到一个内网口
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_insert(struct fib_key *pfib_key)
{  
    struct fib_rules *pNode = fibTableHead;
     struct fib_rules *pTail = fibTableHead;
    
    struct fib_rules *new_rules;
    struct fib_address *fib_addr = NULL;
    struct fib_address *fib_addr_next;
    struct fib_address *new_addr;

    unsigned char *key;
    unsigned char *rule_key;
    int            keylen;
    /*链表头为空,说明链表还没有初始化*/
    
    if (fibTableHead == NULL)
    {
        printf("error! fibtable has not been inited! \n");
        fib_rules_init();
    }    
    
    /* 第一个链表元素 */
    /* 第一次创建 */
    if(fibTableHead->next == NULL)
    {
        printf("the fist creat----\n");
        /* 在链表尾部插入 */
        new_rules = (struct fib_rules *)malloc(sizeof(struct fib_rules));
        if(new_rules == NULL)
        {
            printf("fib_rules_insert: malloc the fib_rules err\n");
            return 0;
        }
        new_addr = (struct fib_address *)malloc(sizeof(struct fib_address));
        if(new_addr == NULL)
        {
            printf("fib_rules_insert: malloc the fib_address err\n");
            free(new_rules);
            return 0;
        }
        
        pTail->next = new_rules;
        
        new_rules->direction = pfib_key->direction;
      
   
        memcpy((unsigned char *)&new_rules->ip_src, (unsigned char *)&pfib_key->ip_src, sizeof(struct in_addr));
        new_rules->pdstaddr = (struct fib_address *)new_addr;
        new_rules->next = NULL;
        new_rules->prev = pTail;
        
        if (pfib_key->direction == FIB_EXTERNEL_NETWORK)
        {
            memcpy(&new_addr->ip_dst, &pfib_key->ip_dst, sizeof(struct fib_address));  
        }
        else if(pfib_key->direction == FIB_INTERNEL_NETWORK)
        {
            memcpy(&new_addr->chipnum, &pfib_key->chipnum, sizeof(int));
        }
         
        new_addr->next = NULL;
        new_addr->prev = new_addr;
        new_rules->pdstaddr = new_addr;
        printf("fib_rules_insert: insert a new rule\n");
        return 1;
    }/*end if(fibTableHead->next == NULL) */
    
    pNode = fibTableHead->next;
    while (pNode != NULL)
    {
        printf("1----\n");
        pTail = pNode;
      
        /* 遍历链表,判断是否有满足条件的节点,有则再判断添加的dst是否存在,若dst不存在,则只添加对应的dst */
        if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0)
        { 
       
            printf("ip_src equal----\n");
            /* 从一个ip地址来的只能是转给外网或内网中的一种策略 */
            if(pNode->direction != pfib_key->direction)
            {
                printf("the fib rules's  direction is't equal to pfib_key's direction\n");
                return 0;
            }
                  
            /* 再比较dst */
            printf("direction FIB_EXTERNEL_NETWORK----\n");
            fib_addr_next = pNode->pdstaddr;
            while(fib_addr_next != NULL)
            {
                printf("fib addr != null---\n");
                fib_addr = fib_addr_next;
      
                if (pNode->direction == FIB_EXTERNEL_NETWORK)
                {
                    rule_key = (unsigned char *)&fib_addr->ip_dst;
                    key      = (unsigned char *)&pfib_key->ip_dst;
                    keylen   = sizeof(struct in_addr);
                    /* 再比较dst */
                    printf("direction FIB_INTERNEL_NETWORK----\n");
                }
                else if(pNode->direction == FIB_INTERNEL_NETWORK)
                {
                    rule_key = (unsigned char *)&fib_addr->chipnum;
                    key      = (unsigned char *)&pfib_key->chipnum;
                    keylen   = sizeof(int);
                }/*end  if (pNode->direction == FIB_EXTERNEL_NETWORK) */
   
                if(rules_memcmp(rule_key, key, keylen) == 0)
                {
                    printf("the dst address exist\n");
                    return -1;
                }
                fib_addr_next =   fib_addr_next->next;
            } /* end while */
            new_addr = (struct fib_address *)malloc(sizeof(struct fib_address));
            if(new_addr == NULL)
            {
                printf("fib_rules_insert: malloc the fib_address err\n");
                return 0;
            }
                          
            if (pNode->direction == FIB_EXTERNEL_NETWORK)
            {
                memcpy(&new_addr->ip_dst, &pfib_key->ip_dst, sizeof(struct fib_address));  
            }
            else if(pNode->direction == FIB_INTERNEL_NETWORK)
            {
                memcpy(&new_addr->chipnum, &pfib_key->chipnum, sizeof(int));
            } /* end direction */
            new_addr->next  = NULL;
            /* 这种情况一般不会发生,pdstaddr is null----no fib_address, else has pdstaddr */
            if(fib_addr == NULL)
            {
                printf("unlikely pdstadd null");
                pNode->pdstaddr = new_addr; 
                new_addr->prev = new_addr;
                printf("fib_rules_insert: creat a new dst  list\n");
            }
            else
            {
                fib_addr->next = new_addr;
                new_addr->prev = fib_addr;
                printf("fib_rules_insert: insert a new dst into the list\n");
            } /*end fib_addr */
    
        } /* if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0) */
        pNode = pNode->next;
    } /* end while */
    /* create a new rules */
    if(pNode == NULL)
    {
        printf("create a new rules----\n");
        /* 在链表尾部插入 */
        new_rules = (struct fib_rules *)malloc(sizeof(struct fib_rules));
        if(new_rules == NULL)
        {
            printf("fib_rules_insert: malloc the fib_rules err\n");
            return 0;
        }
        new_addr = (struct fib_address *)malloc(sizeof(struct fib_address));
        if(new_addr == NULL)
        {
            printf("fib_rules_insert: malloc the fib_address err\n");
            free(new_rules);
            return 0;
        }
        new_rules->direction = pfib_key->direction;
        memcpy((unsigned char *)&new_rules->ip_src, (unsigned char *)&pfib_key->ip_src, sizeof(struct in_addr));
        new_rules->pdstaddr = (struct fib_address *)new_addr;
        new_rules->next = NULL;
        new_rules->prev = pTail;
        
        pTail->next = new_rules;

        if (pfib_key->direction == FIB_EXTERNEL_NETWORK)
        {
            memcpy(&new_addr->ip_dst, &pfib_key->ip_dst, sizeof(struct fib_address));  
        }
        else if(pfib_key->direction == FIB_INTERNEL_NETWORK)
        {
            memcpy(&new_addr->chipnum, &pfib_key->chipnum, sizeof(int));
        }
        
        new_addr->next = NULL;
        new_addr->prev = new_addr;
        new_rules->pdstaddr = new_addr;
        printf("fib_rules_insert: insert a new rule\n");
    } /* end null */
    
    return 0;
}
/**********************************************************************
* 函数名称：fib_rules_remove
* 功能描述：删除指定符合特征的链表节点
* 输入参数：pfib_key  规则关键字
* 输出参数：无
* 返 回 值：无
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_remove(struct fib_key *pfib_key)
{
    struct fib_rules *pNode = fibTableHead;
    struct fib_rules *pTail = fibTableHead;
    
    struct fib_rules *new_rules;
    struct fib_address *fib_addr = NULL;
    struct fib_address *fib_addr_next;
    struct fib_address *new_addr;
    unsigned char *key;
    unsigned char *rule_key;
    int            keylen;

    /*链表头为空,说明链表还没有初始化*/
    
    if (fibTableHead == NULL)
    {
        printf("error! fibtable has not been inited! \n");
        fib_rules_init();
    }    
   
    pNode = fibTableHead->next;
    while (pNode != NULL)
    {
        pTail = pNode;
      
        /* 遍历链表,判断是否有满足条件的节点,有则再判断添加的dst是否存在,若dst不存在,则只添加对应的dst */
        if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0)
        { 
       
            printf("ip_src equal----\n");
            /* 从一个ip地址来的只能是转给外网或内网中的一种策略 */
            if(pNode->direction != pfib_key->direction)
            {
                printf("the fib rules's  direction is't equal to pfib_key's direction\n");
                return 0;
            }
           
            if (pNode->direction == FIB_EXTERNEL_NETWORK)
            {
                rule_key = (unsigned char *)&fib_addr->ip_dst;
                key      = (unsigned char *)&pfib_key->ip_dst;
                keylen   = sizeof(struct in_addr);
                /* 再比较dst */
                printf("direction FIB_EXTERNEL_NETWORK----\n");
            }
            else if(pNode->direction == FIB_INTERNEL_NETWORK)
            {
                rule_key = (unsigned char *)&fib_addr->chipnum;
                key      = (unsigned char *)&pfib_key->chipnum;
                keylen   = sizeof(int);
            }
            fib_addr_next = pNode->pdstaddr;
            while(fib_addr_next != NULL)
            {
                printf("fib addr != null---\n");
                fib_addr = fib_addr_next;
                if(rules_memcmp(rule_key,key, keylen) == 0)
                {
                   printf("now delete the given address ...\n");
                   /* 链表中的第一个元素 */
                   if(fib_addr->prev == fib_addr)
                   {
                       /* 后面还有其他元素 */
                       if(fib_addr_next->next != NULL)
                       {
                           fib_addr_next->next->prev=fib_addr_next->next;
                           pNode->pdstaddr = fib_addr_next->next;
                           free(fib_addr);
                           return;
                       }
                       else
                       {
                           pNode->pdstaddr = NULL;
                           /* 删除一整项 */
                           fib_rules_removeRule((struct in_addr *)&pfib_key->ip_src);
                           return 1;
                       } /*end if(fib_addr_next->next)...*/
                   } /*end if(fib_addr->prev ..) */
                   /* 链表最后一个元素 */
                   else if (fib_addr->next == NULL)
                   {
                       fib_addr->prev->next = NULL;
                       free(fib_addr);
                   } 
                   else
                   {
                       
                       fib_addr_next->next->prev=fib_addr_next->prev;
                       fib_addr_next->prev->next = fib_addr_next->next;
                       free(fib_addr);
                   }/* end if(fib_addr->prev )...*/
                      
                } /* end id(rules_memcmp)... */
                fib_addr_next =   fib_addr_next->next;
            } /* end while */
        } /* if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0) */
        pNode = pNode->next;
    }/*end while */
    return 0;
}
/**********************************************************************
* 函数名称：fib_rules_removeRule
* 功能描述：删除指定以源ip为关键字的链表节点
* 输入参数：pfib_key  规则关键字
* 输出参数：无
* 返 回 值：无
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int fib_rules_removeRule(struct  in_addr *pip_src)
{
    struct fib_rules    *pFibRule, *pNode;
    struct  fib_address *pAddr,    *pAddNode;
    int i=0;
    int j = 0;
    pNode = fibTableHead->next;
    
    while(pNode != NULL)
    {
        pFibRule = pNode;
       
        if (rules_memcmp(&pNode->ip_src, pip_src, sizeof(struct in_addr)) == 0)
        {
            pAddr = pNode->pdstaddr;
            while(pAddr != NULL)
            {
                pAddNode = pAddr;
                pAddr = pAddr->next;
                pAddNode->next = NULL;
                free(pAddNode);
                i++;
                printf("i = %d\n" , i);
            }
           
            pNode->pdstaddr  = NULL;
            pNode->prev->next = pNode->next;
            /* rules最后一个元素 */
            if(pNode->next != NULL)
                pNode->next->prev = pNode->prev;
            free(pNode);
           
            j++;
            printf("j = %d\n" , j);
            return 1; 
           
        }
        pNode = pNode->next;
           
    }    
}

/**********************************************************************
* 函数名称：rules_isExist
* 功能描述：根据源ip地址来判断转发表中是否有对应的转发规则
* 输入参数：
    ip_src  收到的数据包的源ip地址
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
FIB_RULE *rules_isExist(struct in_addr *ip_src)
{
    struct fib_rules *pNode;
    struct fib_rules *pTail;
    
    /*链表头为空,说明链表还没有初始化*/
    
    if ((fibTableHead == NULL) || (fibTableHead->next == NULL))
    {
        printf("rule is null \n");
        return NULL;
    }    
   
    pNode = fibTableHead->next;
    while (pNode != NULL)
    {
        pTail = pNode;
        /* 遍历链表,判断是否有满足条件的节点,有则再判断添加的dst是否存在,若dst不存在,则只添加对应的dst */
        if (rules_memcmp(&pNode->ip_src, ip_src, sizeof(struct in_addr)) == 0)
        { 
            return pNode;
        }
        pNode = pNode->next;
    }
    return NULL;    

}
/**********************************************************************
* 函数名称：rules_print
* 功能描述：将转发表内容打印出来
* 输入参数： 
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
void rules_print()
{
    struct fib_rules *pNode = fibTableHead;
    struct fib_rules *pFibRule;
    struct fib_address *fib_addr; 
    struct fib_address *fib_addr_next;


     /*链表头为空,说明链表还没有初始化*/
    if (fibTableHead == NULL)
    { 
        printf("error! fibtable has not been inited! \n");
        return ;
    }    
    printf("src()  direct(0--out  1---intern)  dst()     \n");
        
    while(pNode->next != NULL)
    {
        pFibRule = pNode;
        pNode    = pNode->next;
        
        printf("src:%s,  direct:%x \n", inet_ntoa(pNode->ip_src), pNode->direction);


    
        if(pNode->direction == 1)
        {
            fib_addr_next = pNode->pdstaddr;
            while(fib_addr_next != NULL)
            {
                fib_addr = fib_addr_next;
                printf("    the dst address :%s\n", inet_ntoa(fib_addr->ip_dst));
                fib_addr_next =   fib_addr_next->next;
            }
        }    
    }
    return;
    
}
/**********************************************************************
* 函数名称：rules_memcmp
* 功能描述：getfilename
* 输入参数：
     chipNum  对应哪个内网口
* 输出参数：
      pFile   文件名
* 返 回 值：
    对应的内网口序列号
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int  getfilename(unsigned char chipNum, unsigned char *pFile)
{
  int ret = 0;

  if(chipNum == 1)
  {
    strcpy(pFile, "8360_1");
    ret = 1;
  }
  else if(chipNum == 2)
  {
    strcpy(pFile, "8360_2");
    ret =2;
  }
  else if(chipNum == 3)
  {
    strcpy(pFile, "8360_3");
    ret = 3; 
  }
  else if(chipNum == 4)
  {
    strcpy(pFile, "8360_4");
    ret = 4;
  }

  return ret;
  
}

/**********************************************************************
* 函数名称：rules_memcmp
* 功能描述：内存块比较函数
* 输入参数：
     cs  内存块1
     ct  内存块2
     count 大小
* 输出参数：无
* 返 回 值：
    0  内存块内容一样
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int rules_memcmp(const void * cs,const void * ct,size_t count)
{
  const unsigned char *su1, *su2;
  signed char res = 0;

  for( su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
    if ((res = *su1 - *su2) != 0)
      break;
  return res;
}
