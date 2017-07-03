服务器程序和客户端程序应当分别运行在两台计算机上。

在运行服务器端的计算机终端执行：./file_server

在运行客户端的计算终端上执行：./file_client   ipaddr_server

然后根据提示输入要传输的服务器上的文件，该文件必须在服务器的当前运行目录中，否则会提示找不到文件。
    ////////////////////////////////////////////////////////////////////////  
    // file_server.c -- socket文件传输服务器端示例代码   
    // /////////////////////////////////////////////////////////////////////  
    #include<netinet/in.h>   
    #include<sys/types.h>   
    #include<sys/socket.h>   
    #include<stdio.h>   
    #include<stdlib.h>   
    #include<string.h>   
      
    #define HELLO_WORLD_SERVER_PORT    6666  
    #define LENGTH_OF_LISTEN_QUEUE     20  
    #define BUFFER_SIZE                1024  
    #define FILE_NAME_MAX_SIZE         512  
      
    int main(int argc, char **argv)  
    {  
        // set socket's address information   
        // 设置一个socket地址结构server_addr,代表服务器internet的地址和端口  
        struct sockaddr_in   server_addr;  
        bzero(&server_addr, sizeof(server_addr));  
        server_addr.sin_family = AF_INET;  
        server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
        server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
      
        // create a stream socket   
        // 创建用于internet的流协议(TCP)socket，用server_socket代表服务器向客户端提供服务的接口  
        int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
        if (server_socket < 0)  
        {  
            printf("Create Socket Failed!\n");  
            exit(1);  
        }  
      
        // 把socket和socket地址结构绑定   
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
        {  
            printf("Server Bind Port: %d Failed!\n", HELLO_WORLD_SERVER_PORT);  
            exit(1);  
        }  
      
        // server_socket用于监听   
        if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
        {  
            printf("Server Listen Failed!\n");  
            exit(1);  
        }  
      
        // 服务器端一直运行用以持续为客户端提供服务   
        while(1)  
        {  
            // 定义客户端的socket地址结构client_addr，当收到来自客户端的请求后，调用accept  
            // 接受此请求，同时将client端的地址和端口等信息写入client_addr中  
            struct sockaddr_in client_addr;  
            socklen_t          length = sizeof(client_addr);  
      
            // 接受一个从client端到达server端的连接请求,将客户端的信息保存在client_addr中  
            // 如果没有连接请求，则一直等待直到有连接请求为止，这是accept函数的特性，可以  
            // 用select()来实现超时检测   
            // accpet返回一个新的socket,这个socket用来与此次连接到server的client进行通信  
            // 这里的new_server_socket代表了这个通信通道  
            int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
            if (new_server_socket < 0)  
            {  
                printf("Server Accept Failed!\n");  
                break;  
            }  
      
            char buffer[BUFFER_SIZE];  
            bzero(buffer, sizeof(buffer));  
            length = recv(new_server_socket, buffer, BUFFER_SIZE, 0);  
            if (length < 0)  
            {  
                printf("Server Recieve Data Failed!\n");  
                break;  
            }  
      
            char file_name[FILE_NAME_MAX_SIZE + 1];  
            bzero(file_name, sizeof(file_name));  
            strncpy(file_name, buffer,  
                    strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));  
      
            FILE *fp = fopen(file_name, "r");  
            if (fp == NULL)  
            {  
                printf("File:\t%s Not Found!\n", file_name);  
            }  
            else  
            {  
                bzero(buffer, BUFFER_SIZE);  
                int file_block_length = 0;  
                while( (file_block_length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0)  
                {  
                    printf("file_block_length = %d\n", file_block_length);  
      
                    // 发送buffer中的字符串到new_server_socket,实际上就是发送给客户端  
                    if (send(new_server_socket, buffer, file_block_length, 0) < 0)  
                    {  
                        printf("Send File:\t%s Failed!\n", file_name);  
                        break;  
                    }  
      
                    bzero(buffer, sizeof(buffer));  
                }  
                fclose(fp);  
                printf("File:\t%s Transfer Finished!\n", file_name);  
            }  
      
            close(new_server_socket);  
        }  
      
        close(server_socket);  
      
        return 0;  
    }  

[cpp] view plain copy

    ////////////////////////////////////////////////////////////////////////  
    // file_server.c -- socket文件传输服务器端示例代码  
    // /////////////////////////////////////////////////////////////////////  
    #include<netinet/in.h>  
    #include<sys/types.h>  
    #include<sys/socket.h>  
    #include<stdio.h>  
    #include<stdlib.h>  
    #include<string.h>  
      
    #define HELLO_WORLD_SERVER_PORT    6666  
    #define LENGTH_OF_LISTEN_QUEUE     20  
    #define BUFFER_SIZE                1024  
    #define FILE_NAME_MAX_SIZE         512  
      
    int main(int argc, char **argv)  
    {  
        // set socket's address information  
        // 设置一个socket地址结构server_addr,代表服务器internet的地址和端口  
        struct sockaddr_in   server_addr;  
        bzero(&server_addr, sizeof(server_addr));  
        server_addr.sin_family = AF_INET;  
        server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
        server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
      
        // create a stream socket  
        // 创建用于internet的流协议(TCP)socket，用server_socket代表服务器向客户端提供服务的接口  
        int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
        if (server_socket < 0)  
        {  
            printf("Create Socket Failed!\n");  
            exit(1);  
        }  
      
        // 把socket和socket地址结构绑定  
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
        {  
            printf("Server Bind Port: %d Failed!\n", HELLO_WORLD_SERVER_PORT);  
            exit(1);  
        }  
      
        // server_socket用于监听  
        if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
        {  
            printf("Server Listen Failed!\n");  
            exit(1);  
        }  
      
        // 服务器端一直运行用以持续为客户端提供服务  
        while(1)  
        {  
            // 定义客户端的socket地址结构client_addr，当收到来自客户端的请求后，调用accept  
            // 接受此请求，同时将client端的地址和端口等信息写入client_addr中  
            struct sockaddr_in client_addr;  
            socklen_t          length = sizeof(client_addr);  
      
            // 接受一个从client端到达server端的连接请求,将客户端的信息保存在client_addr中  
            // 如果没有连接请求，则一直等待直到有连接请求为止，这是accept函数的特性，可以  
            // 用select()来实现超时检测  
            // accpet返回一个新的socket,这个socket用来与此次连接到server的client进行通信  
            // 这里的new_server_socket代表了这个通信通道  
            int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
            if (new_server_socket < 0)  
            {  
                printf("Server Accept Failed!\n");  
                break;  
            }  
      
            char buffer[BUFFER_SIZE];  
            bzero(buffer, sizeof(buffer));  
            length = recv(new_server_socket, buffer, BUFFER_SIZE, 0);  
            if (length < 0)  
            {  
                printf("Server Recieve Data Failed!\n");  
                break;  
            }  
      
            char file_name[FILE_NAME_MAX_SIZE + 1];  
            bzero(file_name, sizeof(file_name));  
            strncpy(file_name, buffer,  
                    strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));  
      
            FILE *fp = fopen(file_name, "r");  
            if (fp == NULL)  
            {  
                printf("File:\t%s Not Found!\n", file_name);  
            }  
            else  
            {  
                bzero(buffer, BUFFER_SIZE);  
                int file_block_length = 0;  
                while( (file_block_length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0)  
                {  
                    printf("file_block_length = %d\n", file_block_length);  
      
                    // 发送buffer中的字符串到new_server_socket,实际上就是发送给客户端  
                    if (send(new_server_socket, buffer, file_block_length, 0) < 0)  
                    {  
                        printf("Send File:\t%s Failed!\n", file_name);  
                        break;  
                    }  
      
                    bzero(buffer, sizeof(buffer));  
                }  
                fclose(fp);  
                printf("File:\t%s Transfer Finished!\n", file_name);  
            }  
      
            close(new_server_socket);  
        }  
      
        close(server_socket);  
      
        return 0;  
    }  


 
[cpp] view plaincopyprint?

    //////////////////////////////////////////////////////  
    // file_client.c  socket传输文件的client端示例程序   
    // ///////////////////////////////////////////////////  
    #include<netinet/in.h>                         // for sockaddr_in  
    #include<sys/types.h>                          // for socket  
    #include<sys/socket.h>                         // for socket  
    #include<stdio.h>                              // for printf  
    #include<stdlib.h>                             // for exit  
    #include<string.h>                             // for bzero  
      
    #define HELLO_WORLD_SERVER_PORT       6666  
    #define BUFFER_SIZE                   1024  
    #define FILE_NAME_MAX_SIZE            512  
      
    int main(int argc, char **argv)  
    {  
        if (argc != 2)  
        {  
            printf("Usage: ./%s ServerIPAddress\n", argv[0]);  
            exit(1);  
        }  
      
        // 设置一个socket地址结构client_addr, 代表客户机的internet地址和端口  
        struct sockaddr_in client_addr;  
        bzero(&client_addr, sizeof(client_addr));  
        client_addr.sin_family = AF_INET; // internet协议族  
        client_addr.sin_addr.s_addr = htons(INADDR_ANY); // INADDR_ANY表示自动获取本机地址  
        client_addr.sin_port = htons(0); // auto allocated, 让系统自动分配一个空闲端口  
      
        // 创建用于internet的流协议(TCP)类型socket，用client_socket代表客户端socket  
        int client_socket = socket(AF_INET, SOCK_STREAM, 0);  
        if (client_socket < 0)  
        {  
            printf("Create Socket Failed!\n");  
            exit(1);  
        }  
      
        // 把客户端的socket和客户端的socket地址结构绑定   
        if (bind(client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr)))  
        {  
            printf("Client Bind Port Failed!\n");  
            exit(1);  
        }  
      
        // 设置一个socket地址结构server_addr,代表服务器的internet地址和端口  
        struct sockaddr_in  server_addr;  
        bzero(&server_addr, sizeof(server_addr));  
        server_addr.sin_family = AF_INET;  
      
        // 服务器的IP地址来自程序的参数   
        if (inet_aton(argv[1], &server_addr.sin_addr) == 0)  
        {  
            printf("Server IP Address Error!\n");  
            exit(1);  
        }  
      
        server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
        socklen_t server_addr_length = sizeof(server_addr);  
      
        // 向服务器发起连接请求，连接成功后client_socket代表客户端和服务器端的一个socket连接  
        if (connect(client_socket, (struct sockaddr*)&server_addr, server_addr_length) < 0)  
        {  
            printf("Can Not Connect To %s!\n", argv[1]);  
            exit(1);  
        }  
      
        char file_name[FILE_NAME_MAX_SIZE + 1];  
        bzero(file_name, sizeof(file_name));  
        printf("Please Input File Name On Server.\t");  
        scanf("%s", file_name);  
      
        char buffer[BUFFER_SIZE];  
        bzero(buffer, sizeof(buffer));  
        strncpy(buffer, file_name, strlen(file_name) > BUFFER_SIZE ? BUFFER_SIZE : strlen(file_name));  
        // 向服务器发送buffer中的数据，此时buffer中存放的是客户端需要接收的文件的名字  
        send(client_socket, buffer, BUFFER_SIZE, 0);  
      
        FILE *fp = fopen(file_name, "w");  
        if (fp == NULL)  
        {  
            printf("File:\t%s Can Not Open To Write!\n", file_name);  
            exit(1);  
        }  
      
        // 从服务器端接收数据到buffer中   
        bzero(buffer, sizeof(buffer));  
        int length = 0;  
        while(length = recv(client_socket, buffer, BUFFER_SIZE, 0))  
        {  
            if (length < 0)  
            {  
                printf("Recieve Data From Server %s Failed!\n", argv[1]);  
                break;  
            }  
      
            int write_length = fwrite(buffer, sizeof(char), length, fp);  
            if (write_length < length)  
            {  
                printf("File:\t%s Write Failed!\n", file_name);  
                break;  
            }  
            bzero(buffer, BUFFER_SIZE);  
        }  
      
        printf("Recieve File:\t %s From Server[%s] Finished!\n", file_name, argv[1]);  
      
        // 传输完毕，关闭socket   
        fclose(fp);  
        close(client_socket);  
        return 0;  
      
    }  

客户端不一定要bind()，服务端一定要bind()，为什么？不然客户端怎么知道服务器位置(IP+PORT)。 一般客户端不绑定端口，因为客户程序经常开关， 由于一些原因(这里我说不清楚，你碰到了自然理解)， 断开时端口很少立刻释放(一般要1、2分钟)。 所以客户端绑定端口容易出问题。
注：服务器绑定的是侦听端口，客户连接后，  新分配一个sock和它连接(这个sock的port是不同的，相当于没有bind的一个端口)  由于侦听端口是没有实际联接的，所以断开时不需握手，也就没有释放问题了。   (注这段是回答时突然想到的，自我感觉是正确的，大家来批判啊)