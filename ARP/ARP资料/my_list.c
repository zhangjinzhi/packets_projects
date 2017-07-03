/**********************************************************
* ��Ȩ���� (C)2007, ����������ͨѶ�ɷ����޹�˾��
*
* �ļ����ƣ�my_list.c
* �ļ���ʶ��
* ����ժҪ�� ת����Ĵ�����
* ����˵����
* ��ǰ�汾��
* ��    �ߣ��� ��
* ������ڣ�2007/12/11
*
* �޸ļ�¼1��   
*    �޸����ڣ� 
*    �� �� �ţ�
*    �� �� �ˣ�                    
*    �޸����ݣ�
**********************************************************/

/***********************************************************
 *                      ͷ�ļ�                             *
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
 *                     ȫ�ֱ���                            *
***********************************************************/ 
struct fib_rules  *g_fibTable;
struct fib_rules  *fibTableHead;


/***********************************************************
 *                     ȫ�ֺ���                            *
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
* �������ƣ�fib_rules_init
* ����������ת�����ʼ��
* ���������
* �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�fib_rules_destroy
* ����������ת��������
* ���������
* �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�fib_rules_length
* ����������ȡ��ת������
* ���������
* �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�fib_rules_insert
* ������������ת�����в���һ������
* ���������pfib_key  ����ؼ���
* �����������
* �� �� ֵ����
* ����˵����ת���� ת�����и���src Դip��ַȷ��ת������
            ת�������� ת��������
                            1. ת����һ��������
                            2. ת�������������
                       ת��������
                            1. ת����һ��������
                            2. ת����һ��������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
    /*����ͷΪ��,˵������û�г�ʼ��*/
    
    if (fibTableHead == NULL)
    {
        printf("error! fibtable has not been inited! \n");
        fib_rules_init();
    }    
    
    /* ��һ������Ԫ�� */
    /* ��һ�δ��� */
    if(fibTableHead->next == NULL)
    {
        printf("the fist creat----\n");
        /* ������β������ */
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
      
        /* ��������,�ж��Ƿ������������Ľڵ�,�������ж���ӵ�dst�Ƿ����,��dst������,��ֻ��Ӷ�Ӧ��dst */
        if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0)
        { 
       
            printf("ip_src equal----\n");
            /* ��һ��ip��ַ����ֻ����ת�������������е�һ�ֲ��� */
            if(pNode->direction != pfib_key->direction)
            {
                printf("the fib rules's  direction is't equal to pfib_key's direction\n");
                return 0;
            }
                  
            /* �ٱȽ�dst */
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
                    /* �ٱȽ�dst */
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
            /* �������һ�㲻�ᷢ��,pdstaddr is null----no fib_address, else has pdstaddr */
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
        /* ������β������ */
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
* �������ƣ�fib_rules_remove
* ����������ɾ��ָ����������������ڵ�
* ���������pfib_key  ����ؼ���
* �����������
* �� �� ֵ����
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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

    /*����ͷΪ��,˵������û�г�ʼ��*/
    
    if (fibTableHead == NULL)
    {
        printf("error! fibtable has not been inited! \n");
        fib_rules_init();
    }    
   
    pNode = fibTableHead->next;
    while (pNode != NULL)
    {
        pTail = pNode;
      
        /* ��������,�ж��Ƿ������������Ľڵ�,�������ж���ӵ�dst�Ƿ����,��dst������,��ֻ��Ӷ�Ӧ��dst */
        if (rules_memcmp(&pNode->ip_src, &pfib_key->ip_src, sizeof(struct in_addr)) == 0)
        { 
       
            printf("ip_src equal----\n");
            /* ��һ��ip��ַ����ֻ����ת�������������е�һ�ֲ��� */
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
                /* �ٱȽ�dst */
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
                   /* �����еĵ�һ��Ԫ�� */
                   if(fib_addr->prev == fib_addr)
                   {
                       /* ���滹������Ԫ�� */
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
                           /* ɾ��һ���� */
                           fib_rules_removeRule((struct in_addr *)&pfib_key->ip_src);
                           return 1;
                       } /*end if(fib_addr_next->next)...*/
                   } /*end if(fib_addr->prev ..) */
                   /* �������һ��Ԫ�� */
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
* �������ƣ�fib_rules_removeRule
* ����������ɾ��ָ����ԴipΪ�ؼ��ֵ�����ڵ�
* ���������pfib_key  ����ؼ���
* �����������
* �� �� ֵ����
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
            /* rules���һ��Ԫ�� */
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
* �������ƣ�rules_isExist
* ��������������Դip��ַ���ж�ת�������Ƿ��ж�Ӧ��ת������
* ���������
    ip_src  �յ������ݰ���Դip��ַ
* ���������
* �� �� ֵ��
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
FIB_RULE *rules_isExist(struct in_addr *ip_src)
{
    struct fib_rules *pNode;
    struct fib_rules *pTail;
    
    /*����ͷΪ��,˵������û�г�ʼ��*/
    
    if ((fibTableHead == NULL) || (fibTableHead->next == NULL))
    {
        printf("rule is null \n");
        return NULL;
    }    
   
    pNode = fibTableHead->next;
    while (pNode != NULL)
    {
        pTail = pNode;
        /* ��������,�ж��Ƿ������������Ľڵ�,�������ж���ӵ�dst�Ƿ����,��dst������,��ֻ��Ӷ�Ӧ��dst */
        if (rules_memcmp(&pNode->ip_src, ip_src, sizeof(struct in_addr)) == 0)
        { 
            return pNode;
        }
        pNode = pNode->next;
    }
    return NULL;    

}
/**********************************************************************
* �������ƣ�rules_print
* ������������ת�������ݴ�ӡ����
* ��������� 
* ���������
* �� �� ֵ��
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
void rules_print()
{
    struct fib_rules *pNode = fibTableHead;
    struct fib_rules *pFibRule;
    struct fib_address *fib_addr; 
    struct fib_address *fib_addr_next;


     /*����ͷΪ��,˵������û�г�ʼ��*/
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
* �������ƣ�rules_memcmp
* ����������getfilename
* ���������
     chipNum  ��Ӧ�ĸ�������
* ���������
      pFile   �ļ���
* �� �� ֵ��
    ��Ӧ�����������к�
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�rules_memcmp
* �����������ڴ��ȽϺ���
* ���������
     cs  �ڴ��1
     ct  �ڴ��2
     count ��С
* �����������
* �� �� ֵ��
    0  �ڴ������һ��
* ����˵����
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
