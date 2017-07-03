struct rip 
{
  /* RIP socket. */
  int sock;

  /* Default version of rip instance. */
  u_char version;

  /* Output buffer of RIP. */
  struct stream *obuf;

  /* RIP routing information base. */
  struct route_table *table;

  /* RIP only static routing information. */
  struct route_table *route;
  
  /* RIP neighbor. */
  struct route_table *neighbor;
  
  /* RIP threads. */
  struct thread *t_read;

  /* Update and garbage timer. */
  struct thread *t_update;

  /* Triggered update hack. */
  int trigger;
  struct thread *t_triggered_update;
  struct thread *t_triggered_interval;

  /* RIP timer values. */
  unsigned long update_time;
  unsigned long timeout_time;
  unsigned long garbage_time;

  /* RIP default metric. */
  int default_metric;

  /* RIP default-information originate. */
  u_char default_information;
  char *default_information_route_map;

  /* RIP default distance. */
  u_char distance;
  struct route_table *distance_table;

  /* For redistribute route map. */
  struct
  {
    char *name;
    struct route_map *map;
    int metric_config;
    u_int32_t metric;
  } route_map[ZEBRA_ROUTE_MAX];
};
//这个结构体包含ripd进程的所有信息，一个ripd进程只有一个struct rip对象作为全局变量。struct route_table *table是ripd进程维护的路由表的指针；struct thread *类型的数据为进程中的伪线程链表头指针（下文详细描述）；此外还包含其他各种信息。


struct rte
{
  u_int16_t family;		/* Address family of this route. */
  u_int16_t tag;		/* Route Tag which included in RIP2 packet. */
  struct in_addr prefix;	/* Prefix of rip route. */
  struct in_addr mask;		/* Netmask of rip route. */
  struct in_addr nexthop;	/* Next hop of rip route. */
  u_int32_t metric;		/* Metric value of rip route. */
};
//这个结构体保存rip报文的每个路由信息单元，按照rip协议规定的格式定义。


struct rip_packet
{
  unsigned char command;	/* Command type of RIP packet. */
  unsigned char version;/* RIP version which coming from peer. */
  unsigned char pad1;		/* Padding of RIP packet header. */
  unsigned char pad2;		/* Same as above. */
  struct rte rte[1];		/* Address structure. */
};
//这个结构体是包含一个路由信息单元的rip报文，也可以把它当做rip报文的首部，因为没有路由信息单元的报文是非法的。

union rip_buf
{
  struct rip_packet rip_packet;
  char buf[RIP_PACKET_MAXSIZ];
};
//这个联合体表示一个rip报文，rip_packet表示报文头，buf作为后续的空间，在代码流程中，这个数据通常伴随有一个值来表示其长度。

//1.2 RIP路由表相关
//1.2.1 struct rip_info
struct rip_info
{
  /* This route's type. */
  int type;

  /* Sub type. */
  int sub_type;

  /* RIP nexthop. */
  struct in_addr nexthop;
  struct in_addr from;

  /* Which interface does this route come from. */
  unsigned int ifindex;

  /* Metric of this route. */
  u_int32_t metric;

  /* Tag information of this route. */
  u_int16_t tag;

  /* Flags of RIP route. */
#define RIP_RTF_FIB      1
#define RIP_RTF_CHANGED  2
  u_char flags;

  /* Garbage collect timer. */
  struct thread *t_timeout;
  struct thread *t_garbage_collect;

  /* Route-map futures - this variables can be changed. */
  struct in_addr nexthop_out;
  u_char metric_set;
  u_int32_t metric_out;
  unsigned int ifindex_out;

  struct route_node *rp;

  u_char distance;

#ifdef NEW_RIP_TABLE
  struct rip_info *next;
  struct rip_info *prev;
#endif /* NEW_RIP_TABLE */
};
//这个结构体封装一个路由信息的各种元素，rip进程维护一个完整的路由表。

//1.2.2 struct route_node
struct route_node
{
  /* Actual prefix of this radix. */
  struct prefix p;

  /* Tree link. */
  struct route_table *table;
  struct route_node *parent;
  struct route_node *link[2];
#define l_left   link[0]
#define l_right  link[1]

  /* Lock of this radix */
  unsigned int lock;

  /* Each node of route. */
  void *info;

  /* Aggregation. */
  void *aggregate;
};
//这个结构体是RIP进程维护的路由表的表的节点。路由表是一个二叉树的结构，这个结构体就是二叉树的叶子。

//1.3 RIP线程相关
//1.3.1 struct thread_list
struct thread_list
{
  struct thread *head;
  struct thread *tail;
  int count;
};
//线程链表。

//1.3.2 struct thread_master
struct thread_master
{
  struct thread_list read;
  struct thread_list write;
  struct thread_list timer;
  struct thread_list event;
  struct thread_list ready;
  struct thread_list unuse;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  unsigned long alloc;
};
//顾名思义，这个结构体申明的对象管理所有线程，其中包括读写、计时器、触发、就绪以及废弃的线程，同时也包含用于轮询触发信号的文件描述符。

//1.3.3 struct thread
struct thread
{
  unsigned char type;		/* thread type */
  struct thread *next;		/* next pointer of the thread */
  struct thread *prev;		/* previous pointer of the thread */
  struct thread_master *master;	/* pointer to the struct thread_master. */
  int (*func) (struct thread *); /* event function */
  void *arg;			/* event argument */
  union {
    int val;			/* second argument of the event. */
    int fd;			/* file descriptor in case of read/write. */
    struct timeval sands;	/* rest of time sands value. */
  } u;
  RUSAGE_T ru;			/* Indepth usage info.  */
};
//这个结构体实际描述一个伪线程，其中包含了线程要执行的函数，还有一些内嵌链表的指针。线程要加入哪个队列，只要操作这些指针。
/*
第二章 接收与发送处理
2.1 请求报文处理
当收到一个rip请求报文（command字段为1），轮询程序（后文介绍）会调用rip_request_process()函数来处理这个报文。
请求报文分为两种，一种是请求整个路由表信息的报文（只有一个单元，度量为16，地址系列为0）。当收到此类报文时，直接调用rip_output_process()并制定参数发送整个路由表：rip_output_process (ifp, from, rip_all_route, packet->version)。
另一种是请求某一路由表项的报文。收到此类报文以后，遍历这个报文的每个单元，分别在路由表中查找每个单元的信息，如果找到则填入报文，找不到就把度量设置为16。然后调用rip_send_packet()来发送这个填充过的报文。

2.2 应答报文处理
当收到一个rip应答报文（command字段为2），轮询程序会调用rip_response_process()来处理这个报文。
这个函数先检查源端口、源地址，如果不符合协议规范就丢弃它，然后进入一个循环来遍历报文中的每个单元。对于每个单元中的信息，先进行一些检查，并根据路由表的信息对报文信息进行更改（例如已经有的表项，如果是rip的表项，则设置下一跳为源地址），然后进入rip_rte_process()来进行处理。
rip_rte_process()函数中，同样要进行一些检查和封装，然后把rte也就是路由信息作为依据在路由表中查找表项。
这里有两种结果，如果没有找到，则说明这个路由信息是新增的，我们需要在我们的路由表中创建这一项，所以通过rip_info_new()对他进行创建，并初始化它的计时器，注册一个新事件（讲线程机制时会详细说明），然后通过rip_zebra_ipv4_add()把这个新建的表项加入路由表。如果路由表中已经有关于这个地址的路由，这里就涉及一个简单的最短路径优先算法：在已有表项和新发来的信息中，选择一条最优的（最短的）。但是如果这个报文来自于和表项和告知者是同一个地址，那么说明这个路由发生了变化，无论谁最优，我们都需要进行更新。代码的实现依据这个算法，并在更新路由的同时进行计时器更新和线程注册。

第三章 RIP进程路由表
3.1 关于路由表
路由表是由内核维护的，作用于ISO层次模型的网络层的，被用于发送和转发数据包的，包含地址信息、度量、接口、源地址等元素的一张散列表。RIP进程为了提高效率和安全性，本身维护一张路由表的创建删除更新，从而避免了系统调用浪费的时间和新增内核接口造成的安全隐患。

3.2 RIP维护的路由表结构

图3-1 哈夫曼树
RIP的路由表结构是一个二叉树，类似“哈夫曼树”，如图3-1所示。
路由表结构以前缀（代码中是prefix，其实就是网络掩码）为哈夫曼编码依据，从xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx开始，分支出0xxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx和1xxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx，逐步类推。
struct route_node表示的就是哈夫曼树的叶子节点，其中struct route_node *link[2]这个变量分别指向此节点的左右两个子节点。如果一个叶子的左子节点或右子节点不存在（路由表暂时没有关于这个前缀的路由项），那么该指针为NULL。
在这样的结构中，查找一个节点是从树根开始，根据前缀的每一位为0或为1，找到下一个叶子。这个查找的时间复杂度为ln(n)同阶。

3.3 相关操作接口
这里只列出每个函数的功能，并稍微分析其实现，具体设计实现细节以及参数、返回值，见代码。

3.3.1 route_table_init()
初始化一张路由表，申请空间。

3.3.2 route_table_finish()
删除一张路由表。

3.3.3 route_node_new()
为一个节点申请空间。

3.3.4 route_node_set()
为一个节点赋值。

3.3.5 route_node_free()
释放一个节点的空间。

3.3.6 route_table_free()
释放一张表的空间，需要释放每个节点。

3.3.7 route_lock_node()
这个函数为一个路由表项加锁。

3.3.8 route_unlock_node()
解锁。

3.3.9 route_dump_node()
终端打印整个路由表。

3.3.10 route_node_match()
在表中找到匹配的前缀节点，执行这个函数如果找到对应节点，会将该节点加锁。

3.3.11 route_node_lookup()
这个函数和route_node_match()几乎一样。

3.3.12 route_node_get()
这个函数也是在表中查找，但是如果找不到会在适合的位置创建一个节点并返回。

3.3.13 route_node_delete()
删除一个节点，如果他的父节点不需要存在，而是为了它而存在，一并删除，递归调用。

第四章 RIP伪线程机制
RIP协议中的线程机制是一个“伪线程”机制，它没有创建真正的线程来运行，而是通过一些数据结构、指针的调度，来模拟一个多线程环境。

4.1 线程结构
RIP进程通过一个thread_master结构体的对象来管理所有进程。这个结构体包含6个链表头，read、write、timer、event、ready、unuse。其中，event队列的执行优先级最高，表示一个触发事件，比如路由表发生了变化；其次是timer队列，这个队列中存放的是计时用的线程；再次是ready队列；然后是read和write队列，这两个队列一起进行轮询。

图4-1 RIP线程结构
图4-1简单描述了上述结构。

4.2 线程创建与销毁
4.2.1 thread_get()
创建一个线程，先从unuse队列中寻找废弃的线程，如果有，直接从unuse队列中移除，如果没有，申请新的空间。注意这个函数是个静态局部函数，只能给本源文件使用。

4.2.2 thread_add_read()
创建一个线程，并加入read队列。

4.2.3 thread_add_write()
创建一个线程，并加入write队列。

4.2.4 thread_add_timer()
创建一个线程，并加入timer队列。

4.2.5 thread_add_event()
创建一个线程，并加入event队列。

4.2.6 thread_cancel()
销毁一个线程，将它从对应队列中取出并放入unuse队列。

4.2.7 thread_cancel_event()
销毁所有触发事件线程。
*/
//4.3 RIP进程执行过程
//rip_main.c中有如下代码：
int main (int argc, char **argv)
{
…………………………………………………
  /* Execute each thread. */
  while (thread_fetch (master, &thread)) 
    thread_call (&thread);
…………………………………………………
}
//这个循环执行RIP进程，我们来看thread_fetch()：
struct thread *
thread_fetch (struct thread_master *m, struct thread *fetch)
{
…………………………………………………
    while (1)
    {
      /* Normal event is the highest priority.  */
      if ((thread = thread_trim_head (&m->event)) != NULL)
	return thread_run (m, thread, fetch);

      /* Execute timer.  */
      gettimeofday (&timer_now, NULL);

      for (thread = m->timer.head; thread; thread = thread->next)
	if (timeval_cmp (timer_now, thread->u.sands) >= 0)
	  {
	    thread_list_delete (&m->timer, thread);
	    return thread_run (m, thread, fetch);
	  }

      /* If there are any ready threads, process top of them.  */
      if ((thread = thread_trim_head (&m->ready)) != NULL)
	return thread_run (m, thread, fetch);

      /* Structure copy.  */
      readfd = m->readfd;
      writefd = m->writefd;
      exceptfd = m->exceptfd;

      /* Calculate select wait timer. */
      timer_wait = thread_timer_wait (m, &timer_val);

      num = select (FD_SETSIZE, &readfd, &writefd, &exceptfd, timer_wait);

      if (num == 0)
	continue;

      if (num < 0)
	{
	  if (errno == EINTR)
	    continue;
#ifdef BRCM_RIP_DEBUG
	  zlog_warn ("select() error: %s", strerror (errno));
#endif
	  return NULL;
	}

      /* Normal priority read thead. */
      ready = thread_process_fd (m, &m->read, &readfd, &m->readfd);

      /* Write thead. */
      ready = thread_process_fd (m, &m->write, &writefd, &m->writefd);

      if ((thread = thread_trim_head (&m->ready)) != NULL)
	return thread_run (m, thread, fetch);
    }
}
//这个函数主要是一个循环，反复检查上述队列是否为空，如果不为空，则把这个线程从当前队列取出，返回这个线程。其中event队列最先检查，因为优先级最高，其次是timmer，然后是ready，最后是读写线程的轮询。RIP进程的所有操作，都是通过注册并增加一个线程加入这些队列。
//下面来看线程注册函数：
void rip_event (enum rip_event event, int sock)
{
  int jitter = 0;

  switch (event)
    {
    case RIP_READ:
      rip->t_read = thread_add_read (master, rip_read, NULL, sock);
      break;
    case RIP_UPDATE_EVENT:
      if (rip->t_update)
	{
	  thread_cancel (rip->t_update);
	  rip->t_update = NULL;
	}
      jitter = rip_update_jitter (rip->update_time);
      rip->t_update = 
	thread_add_timer (master, rip_update, NULL, 
			  sock ? 2 : rip->update_time + jitter);
      break;
    case RIP_TRIGGERED_UPDATE:
      if (rip->t_triggered_interval)
	rip->trigger = 1;
      else if (! rip->t_triggered_update)
	rip->t_triggered_update = 
	  thread_add_event (master, rip_triggered_update, NULL, 0);
      break;
    default:
      break;
    }
}
//这个函数注册线程，加入队列，等待执行。例如，轮询到read队列有线程，表示收到数据包，则会调用上面注册的rip_read()：

/* First entry point of RIP packet. */
int rip_read (struct thread *t)
{
  …………………………………………………
  switch (packet->command)
    {
    case RIP_RESPONSE:
      rip_response_process (packet, len, &from, ifp);
      break;
    case RIP_REQUEST:
    case RIP_POLL:
      rip_request_process (packet, len, &from, ifp);
      break;
    …………………………………………………
    }
  return len;
}
//这就进入了RIP报文的处理函数。
