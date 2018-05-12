/**********************************************************************
*
*  FILE NAME	: mp1server.c
*
*  DESCRIPTION  : Implemention of a stream socket server.
* 
*  PLATFORM		: linux
*
*  DATE                 NAME                     REASON
*  05th Feb,2018        Shashi Shivaraju         ECE_6680_MP1_Q3
*                       [C88650674]
*  Reference	: Beej's Guide to Network Programming
*				  https://github.com/beejjorgensen/bgnet
***********************************************************************/

/*header inclusions*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

/*Macro definations */
#define PORT  "3490" //"6000" // the port users will be connecting to
#define MAXDATASIZE 1000 // max number of bytes we can get at once

#define ID_LENGTH 	6

#define BACKLOG 10	 // how many pending connections queue will hold

/*Function prototypes*/
void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);

/*Function definations*/
void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*main function of the program*/
int main(void)
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	
	/*Client Identification & Strings Table*/
	/*Need to change MAXDATASIZE value if ClientMessage strings are greater than MAXDATASIZE*/
	char ClientIdentity[5][6] = {{"123456"},\
	{"234561"},\
	{"345612"},\
	{"456123"},\
	{"561234"}};
	char ClientMessage[5][50] = {{"Namaskara !!! client 123456 from Bangalore :)"},\
	{"Hello !!! client 234561 from London :)"},\
	{"Hola !!! cli1ent 345612 form Madrid :)"},\
	{"Bonjour !!! client 456123 from Paris :)"},\
	{"yeoboseyo !!! client 561234 from Seoul :)"}}; 

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) 
		{
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
			sizeof(int)) == -1) 
		{
				perror("setsockopt");
				exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
		{
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL) 
	{
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) 
	{
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(1);
	}
	printf("server: waiting for connections...\n");
	while(1)
	{  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) 
		{
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) 
		{ // this is the child process

			/*variable declarations*/
			char buf[MAXDATASIZE];
			char len[10] = {0};
			char id_string[ID_LENGTH] = {0}; /*pointer to store the identification number as string*/ 
			unsigned char valid_id = 0;		/*Flag to indicate valid id or not*/
			int id_len = 0;	
			int i = 0;
			int numbytes = 0,totalbytes = 0;
			int ret = 0;
			

			close(sockfd); // child doesn't need the listener

			/*Recieve identification number string*/
			if ((numbytes = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) 
			{
				perror("recv");
				close(new_fd);
				exit(1);
			}
			buf[numbytes] = '\0';

			/*Validate the recieved string for identification number*/
			id_len = strlen(buf);
			if(ID_LENGTH != id_len)
			{
				printf("server:the identification number recieved from the client = %s;\nshould contain only 6 digits;Error Msg Sent\n",buf);
				memset(buf,0,MAXDATASIZE);
				strcpy(buf,"invalid [6 digit identification number]: should contain only 6 digits\n");

				/*Send error msg length to client*/
				memset(len,0,10);
				snprintf(len,10,"%d",(int)strlen(buf));
				ret = send(new_fd, len, strlen(len), 0);
				if ( ret == -1)
				{
					perror("send");
					close(new_fd);
					exit(0);
				}

				sleep(1);

				/*send error message to the client*/
				if (send(new_fd, buf, strlen(buf), 0) == -1)
					perror("send");
				close(new_fd);
				exit(1);
			}

			strncpy(id_string,buf,ID_LENGTH);

			for(i=0;i<ID_LENGTH;i++)
			{
				/*check if all the characters are digits [0-9]*/
				if(0x30 > id_string[i] || 0x39 < id_string[i])
				{
					printf("server:the identification number recieved from the client = %s;\nshould contain only digits;Error Msg Sent\n",id_string);
					memset(buf,0,MAXDATASIZE);
					strcpy(buf,"invalid [6 digit identification number]:should contain only digits\n");

					/*Send error msg length to client*/
					memset(len,0,10);
					snprintf(len,10,"%d",(int)strlen(buf));
					ret = send(new_fd, len, strlen(len), 0);
					if ( ret == -1)
					{
						perror("send");
						close(new_fd);
						exit(0);
					}

					sleep(1);

					/*send error message to the client*/
					if (send(new_fd, buf, strlen(buf), 0) == -1)
						perror("send");
					close(new_fd);
					exit(1);
				}
			}

			/*check the identification number from the lookup table*/
			for(i=0;i<5;i++)
			{
				if(0 == strncmp(id_string,ClientIdentity[i],ID_LENGTH))
				{
					valid_id = 1; /*Flag set to indicate valid ID*/
					break;
				}
			}

			memset(buf,0,MAXDATASIZE);

			/*Invalid  ID*/
			if(!valid_id)
			{
				printf("server:the identification number recieved from the client = %s;\nEntry Not found;Access denied;Error Msg Sent\n",id_string);

				strcpy(buf,"invalid [6 digit identification number]:Entry NOT found;access denied\n");

				/*Send error msg length to client*/
				memset(len,0,10);
				snprintf(len,10,"%d",(int)strlen(buf));
				ret = send(new_fd, len, strlen(len), 0);
				if ( ret == -1)
				{
					perror("send");
					close(new_fd);
					exit(0);
				}

				sleep(1);

				/*send error message to the client*/
				if (send(new_fd, buf, strlen(buf), 0) == -1)
					perror("send");

				close(new_fd);
				exit(0);
			}

			printf("server:the identification number recieved from the client = %s;Mesg Sent\n",id_string);

			/*send the reply message length to the client*/
			snprintf(len,10,"%d",(int)(strlen(ClientMessage[i])));
			ret = send(new_fd, len, strlen(len), 0);
			if ( ret == -1)
			{
				perror("send");
				close(new_fd);
				exit(0);
			}

			sleep(1);

			/*send the corresponding reply message to the client*/
			memset(buf,0,MAXDATASIZE);
			strncpy(buf,ClientMessage[i],strlen(ClientMessage[i]));
			numbytes = strlen(buf); /*bytes to be sent*/
			while(numbytes > 0)
			{
				ret = send(new_fd, buf+totalbytes, numbytes, 0);
				if ( ret == -1)
				{
					perror("send");
					break;
				}
				else
				{
					//printf("original size %d sent size %d\n",numbytes,ret);
					totalbytes = totalbytes+ret; /*increment the sent byte count*/
					numbytes = numbytes - ret;	/*increment the remaning byte count*/
				}
			}

			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}
