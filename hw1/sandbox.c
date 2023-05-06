#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <dlfcn.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAX_RULES 100

typedef struct 
{
    char *rules[MAX_RULES];
    int count;
} blacklist_content;

void add_path_to_blacklist(blacklist_content *blacklist, const char *path)
{
    if (blacklist->count < MAX_RULES) 
    {
        blacklist->rules[blacklist->count] = strdup(path);
        blacklist->count++;
    }
}

// 全域變數，用於存儲黑名單
blacklist_content blacklist_open;
blacklist_content blacklist_read;
blacklist_content blacklist_connect;
blacklist_content blacklist_getaddrinfo;

// 初始化黑名單
void init_blacklist()
{
    bzero(&blacklist_open, sizeof(blacklist_open));
    bzero(&blacklist_read, sizeof(blacklist_read));
    bzero(&blacklist_connect, sizeof(blacklist_connect));
    bzero(&blacklist_getaddrinfo, sizeof(blacklist_getaddrinfo));
    
    char *filename = getenv("SANDBOX_CONFIG");
    //printf("SANDBOX_CONFIG: %s\n\n\n", filename);
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) 
    {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        exit(1);
    }
    
    char *line = NULL;
    size_t len = 0;    
    while ((getline(&line, &len, fp)) != -1) 
    {
        line[strcspn(line, "\n\r")] = '\0';     
        if(strstr(line, "BEGIN open-blacklist") != NULL)
        {
            while ((getline(&line, &len, fp)) != -1) 
            {               
                line[strcspn(line, "\n\r")] = '\0';              
                if (strstr(line, "END open-blacklist") == NULL)    
                    add_path_to_blacklist(&blacklist_open, line);
                else
                    break;                   
            }        
        }
        else if(strstr(line, "BEGIN read-blacklist") != NULL)
        {
            while ((getline(&line, &len, fp)) != -1) 
            {               
                line[strcspn(line, "\n\r")] = '\0';              
                if (strstr(line, "END read-blacklist") == NULL)    
                    add_path_to_blacklist(&blacklist_read, line);
                else
                    break;                   
            }        
        }        
        else if(strstr(line, "BEGIN connect-blacklist") != NULL)
        {
            while ((getline(&line, &len, fp)) != -1) 
            {               
                line[strcspn(line, "\n\r")] = '\0';              
                if (strstr(line, "END connect-blacklist") == NULL)    
                    add_path_to_blacklist(&blacklist_connect, line);
                else
                    break;                   
            }        
        } 
        else if(strstr(line, "BEGIN getaddrinfo-blacklist") != NULL)
        {
            while ((getline(&line, &len, fp)) != -1) 
            {               
                line[strcspn(line, "\n\r")] = '\0';              
                if (strstr(line, "END getaddrinfo-blacklist") == NULL)    
                    add_path_to_blacklist(&blacklist_getaddrinfo, line);
                else
                    break;                   
            }        
        }                                 
    }   
    fclose(fp);     
}

// 檢查檔案是否在黑名單中
int is_file_blocked(const char *pathname, const char *blacklist[], int num_blacklist_entries)
{
    char resolved_path[256];
    if (realpath(pathname, resolved_path) == NULL)
    {
        return 0;
    }
    for (int i = 0; i < num_blacklist_entries; i++)
    {
        //printf("%s, %s\n", resolved_path, blacklist[i]);
        if (strcmp(resolved_path, blacklist[i]) == 0)
        {
            //printf("is_file_blocked\n\n");
            return 1;
        }
    }
    return 0;
}

// 自定義的 open 函數
int myopen(const char *pathname, int flags, mode_t mode)  //EACCES
{
    //printf("\nThis is myopen.\n");
    if(!(flags & O_CREAT)) mode = 0;
    // 檢查檔案是否在黑名單中
    if (is_file_blocked(pathname, blacklist_open.rules, blacklist_open.count))
    {
        //fprintf(stderr, "Access to file %s is blocked by sandbox\n", pathname);
        printf("[logger] open(\"%s\", %d, %hu) = %d\n", pathname, flags, mode, -1);
        errno = EACCES;
        return -1;
    }
   
    // 調用原始的 open 函數
    int (*original_open)(const char *, int, mode_t) = dlsym(RTLD_NEXT, "open");
    int ret = original_open(pathname, flags, mode);
    printf("[logger] open(\"%s\", %d, %hu) = %d\n", pathname, flags, mode, ret);
  
    return ret;
}

typedef struct 
{
    int fd;
    char log_file_name[128];
    char content[2048];
} my_read_function_content;

my_read_function_content read_content[1024];
int num_fds = 0;


ssize_t myread(int fd, void *buf, size_t count)  //EIO
{
    //printf("\nThis is myread.\n");
    int index = -1, i = 0;
    while (i < num_fds && index == -1) 
    {
        if (read_content[i].fd == fd) index = i;
        i++;
    }
    if(index == -1) 
    {
        read_content[num_fds].fd = fd;
        snprintf(read_content[num_fds].log_file_name, sizeof(read_content[num_fds].log_file_name), "%d-%d-read.log", getpid(), fd);
        //printf("%s\n", read_content[num_fds].log_file_name);
        index = num_fds;
        num_fds++;        
    }
    int log_fd = open(read_content[index].log_file_name, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (log_fd == -1) 
    {
        fprintf(stderr, "Failed to open file: %s\n", read_content[index].log_file_name);
        exit(1);        
    }
        
    ssize_t (*original_read)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    int ret = original_read(fd, buf, count);
    if (ret == -1) 
    {
        perror("read");
        close(fd);
        return ret;
    }    
    strncat(read_content[num_fds].content, (char *)buf, sizeof(read_content[num_fds].content) - strlen(read_content[num_fds].content) - 1);
    read_content[num_fds].content[sizeof(read_content[num_fds].content) - 1] = '\0';
    
    if(strstr(read_content[num_fds].content, blacklist_read.rules[0]) != NULL)
    {
        printf("[logger] read(%d, %p, %zu) = %d\n", fd, buf, count, -1); 
        errno = EIO;
        close(fd);
        return -1;    
    }
    else
    {
        write(log_fd, buf, ret);
        close(log_fd);
        printf("[logger] read(%d, %p, %zu) = %d\n", fd, buf, count, ret);    
        return ret;    
    }   
}

typedef struct 
{
    int fd;
    char log_file_name[128];
    char content[2048];
} my_write_function_content;

my_write_function_content write_content[1024];
int write_num_fds = 0;

ssize_t mywrite(int fd, const void *buf, size_t count)
{
    //printf("\nThis is mywrite.\n");
    int index = -1, i = 0;
    while (i < write_num_fds && index == -1) 
    {
        if (write_content[i].fd == fd) index = i;
        i++;
    }
    if(index == -1) 
    {
        write_content[write_num_fds].fd = fd;
        snprintf(write_content[write_num_fds].log_file_name, sizeof(write_content[write_num_fds].log_file_name), "%d-%d-write.log", getpid(), fd);
        //printf("%s\n", write_content[write_num_fds].log_file_name);
        index = write_num_fds;
        write_num_fds++;        
    }
    int log_fd = open(write_content[index].log_file_name, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (log_fd == -1) 
    {
        fprintf(stderr, "Failed to open file: %s\n", write_content[index].log_file_name);
        exit(1);        
    }
        
    ssize_t (*original_write)(int, const void * , size_t) = dlsym(RTLD_NEXT, "write");
    int ret = original_write(fd, buf, count);
    if (ret == -1) 
    {
        perror("write");
        close(fd);
        return ret;
    }    
    strncat(write_content[write_num_fds].content, (char *)buf, sizeof(write_content[write_num_fds].content) - strlen(write_content[write_num_fds].content) - 1);
    write_content[write_num_fds].content[sizeof(write_content[write_num_fds].content) - 1] = '\0'; 
    write(log_fd, buf, ret);
    close(log_fd);       
    printf("[logger] write(%d, %p, %zu) = %d\n", fd, buf, count, ret);
    return ret;
}

///////////////////////////  addr.  ///////////////////////////

int is_ip_blocked(const char *pathname, const char *blacklist[], int num_blacklist_entries)
{

    struct addrinfo hints, *res, *p;
    int status, temp = 0;
    char ip_str[INET6_ADDRSTRLEN];
    int rows = num_blacklist_entries * 5;
    char total_ip[rows][INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;



  for (int i = 0; i < num_blacklist_entries; i++)
  {
    char str[] = "";
    strcpy(str, blacklist[i]);
    char *token;
    //printf("%s\n\n\n\n", str);
    token = strtok(str, ":");
    //printf("%s\n\n\n\n", str);
    if ((status = getaddrinfo(token, NULL, &hints, &res)) != 0) 
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(2);
    }
    
    token = strtok(NULL, ":");
    //printf("%s\n", token);      

    for (p = res; p != NULL; p = p->ai_next) 
    {
        void *addr;
        char *ipver;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ip_str, sizeof ip_str);     
        //printf("%s: %s\n", ipver, ip_str);     
        sprintf(total_ip[temp], "%s:%s", ip_str, token);         //  
        //strcpy(total_ip[temp], ip_str);
        temp++;
    }
    freeaddrinfo(res);
  }
    
    
    
    for(int j=0;j<temp;j++)
    {
        //printf("%d: %s, pathname: %s\n", j, total_ip[j],pathname);
        if (strcmp(pathname, total_ip[j]) == 0)
        {
            //printf("is_file_blocked\n\n");
            return 1;
        }        
    }
        

    return 0;
}

int myconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)  //ECONNREFUSED
{
    //printf("\nThis is myconnect.\n");
    struct sockaddr_in *sin = (struct sockaddr_in *) addr;
    char *ip = inet_ntoa(sin->sin_addr);
    int port = ntohs(sin->sin_port);    
    char ip_port[30];
    sprintf(ip_port, "%s:%d", ip, port);
        
    //printf("%s, %d\n\n\n", ip, port);
    //printf("%s\n\n\n", ip_port);
    if (is_ip_blocked(ip_port, blacklist_connect.rules, blacklist_connect.count))
    {
        errno = ECONNREFUSED;
        printf("[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, -1);  
        return -1;
    }    
    int (*original_connect)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "connect");
    int ret = original_connect(sockfd, addr, addrlen);
    printf("[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, ret);  
    return ret;
}

int is_addr_blocked(const char *pathname, const char *blacklist[], int num_blacklist_entries)
{

    for (int i = 0; i < num_blacklist_entries; i++)
    {
        //printf("%s, %s\n", pathname, blacklist[i]);
        if (strcmp(pathname, blacklist[i]) == 0)
        {
            //printf("is_file_blocked\n\n");
            return 1;
        }
    }
    return 0;
}


int mygetaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) //EAI_NONAME
{
    //printf("\nThis is mygetaddrinfo.\n");
    if (is_addr_blocked(node, blacklist_getaddrinfo.rules, blacklist_getaddrinfo.count))
    {
        //errno = EAI_NONAME;
        printf("[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, *res, -2);  
        return EAI_NONAME;
    }
    
    
    //int (*original_open)(const char *, int, mode_t) = dlsym(RTLD_NEXT, "open");
    //int ret = original_open(pathname, flags, mode);   
    int (*original_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = dlsym(RTLD_NEXT, "getaddrinfo");
    int ret = original_getaddrinfo(node, service, hints, res);
    printf("[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, *res, ret);  
    return ret;
}

int mysystem(const char *command) 
{
    //printf("\nThis is mysystem.\n");
    int (*original_system)(const char*) = dlsym(RTLD_NEXT, "system"); 
    printf("[logger] system(\"%s\")\n", command); 
    return original_system(command);
    //return system(command);
    //return 0;
}


// Custom __libc_start_main function
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **ubp_av, 
                      void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end)) 
{
	char buffer[1024];
	char base_address[13];
	bool found_base_address = false;

	FILE* maps_fp = fopen("/proc/self/maps", "r");
	if (maps_fp == NULL) 
	{
		perror("Error opening file!\n");
		exit(EXIT_FAILURE); 
	}

	while (fgets(buffer, sizeof(buffer), maps_fp) != NULL) 
	{
		const int kBaseAddressLength = 12;
		if (strlen(buffer) < kBaseAddressLength) continue;
		strncpy(base_address, buffer, kBaseAddressLength);
		base_address[kBaseAddressLength] = '\0';
		found_base_address = true;
		break;		
	}
	//printf("base_address in string: %s\n", base_address);		
	fclose(maps_fp);    
        
    pid_t pid = fork();
	if(signal(SIGCHLD,SIG_IGN) == SIG_ERR)
	{
    	perror("signal error");
    	exit(EXIT_FAILURE);
	}        
	
    if(pid == 0) //child
    {
    	//printf("this is child process\n");
    	char parent_pid[20];
    	sprintf(parent_pid, "%d", getppid());
    	char *args[] = {"python3", "./GOT_table.py", parent_pid, NULL};
    	//char *args[] = {"./GOT_table", parent_pid, NULL};
    	putenv("LD_PRELOAD=");
    	int fd = open("/dev/null", O_WRONLY); 
		dup2(fd, STDOUT_FILENO); 
		dup2(fd, STDERR_FILENO); 
    	execvp("python3", args);
    	//execvp(args[0], args);
    	perror("execvp");
    	exit(0);
    }
    else if(pid > 0) //parent
    {
    	sleep(1);
    	//printf("this is parent process\n");
    	int status;
    	pid_t wpid;
		wpid = waitpid(pid, &status, WUNTRACED | WCONTINUED);        	
    }
    else
    {
    	perror("fork error");
    	exit(EXIT_FAILURE);
    }
    
    FILE *fp2 = fopen("GOT_offset.txt", "r");
    int hex_int, min = INT_MAX, max = INT_MIN, GOT_offset[6], i = 0;
    while (i < 6 && fscanf(fp2, "%x", &hex_int) == 1)
    {
    	GOT_offset[i] = hex_int;
    	if(hex_int != 0)
    	{
    	    min = (hex_int < min) ? hex_int : min;
    	    max = (hex_int > max) ? hex_int : max;
    	}
    	i++;
    }
        
    fclose(fp2);
    
    unsigned long int address_hex = strtol(base_address,NULL,16); //base address in hex
    //page size of x86_64 system is 4096 bytes (2^12)
    unsigned long int page_offset = min & ~(0xfff); // address of page entry
    void *page_address = (void*) address_hex + page_offset; //absolute address of GOT entry
    //printf("min: %x\n", min);
    //printf("address of page entry: %lx\n", page_offset);
    
    int page_number = ((max-min)/0x1000 == 0) ? 1 : (max-min)/0x1000;
    if (mprotect(page_address, page_number * 0x1000, PROT_READ | PROT_WRITE) == -1)
    {
	perror("Error mprotect!\n");
	exit(1);
    }
        
	void *fHandle = dlopen("./sandbox.so", RTLD_LAZY);
	if (!fHandle) 
	{
		fprintf (stderr, "%s\n", dlerror());
		exit(1);
    	}
	dlerror();
	
	const char *title[] = {"myopen", "myread", "mywrite", "myconnect", "mygetaddrinfo", "mysystem"};
	unsigned long int true_addr[1477];
	for(int i=0; i<6; i++)   
	{
		if(GOT_offset[i] == 0)  
			continue;	        
		true_addr[i] = (unsigned long int)dlsym(fHandle, title[i]); 
		unsigned long int GOT_address_hex = address_hex + GOT_offset[i];  
		*(unsigned long int *)GOT_address_hex = true_addr[i];	        
	}        
    	
	init_blacklist();


   	// Call the real __libc_start_main function
	int (*real_start_main)(int (*)(int, char **, char **), int, char **, void (*)(void), void (*)(void), void (*)(void), void *);
	real_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	return real_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}



