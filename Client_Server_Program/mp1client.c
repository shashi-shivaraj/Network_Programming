/**********************************************************************
*
*  FILE NAME	: mp1client.c
*
*  DESCRIPTION  : Implemention of a stream socket client.
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
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>


/*Macro definations*/
#define PORT "3490" /* "6000" */ // the port client will be connecting to 
#define MAXDATASIZE 50 // max number of bytes we can get at once

#define ID_LENGTH 	6
#define MAX_RETRY_COUNT 5 

/*Function prototypes*/
void *get_in_addr(struct sockaddr *sa);
int validate_digits_in_string(char * string,int length);

/*Function Definations*/
void *get_in_addr(struct sockaddr *sa)
{
	// get sockaddr, IPv4 or IPv6:
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int validate_digits_in_string(char * string,int length)
{
	int i = 0;
	for(i=0;i<length;i++)
	{
		/*check if all the characters are digits [0-9]*/
		if(0x30 > string[i] || 0x39 < string[i])
		{
			return -1; /*error*/
		}
	}

	return 0; /*no error*/
}

/*Main function of the program*/
int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	unsigned char *output = NULL;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	char id_string[ID_LENGTH] = {0}; /*pointer to store the identification number as string*/ 
	int id_len = 0;		/*variable to store the length of the identification number*/
	int i = 0;
	int ret = 0/* ,flags = 0 */;
	int snd_soc_buff_size = 0,rcv_soc_buff_size = 0;
	unsigned int m = sizeof(snd_soc_buff_size);

	if (argc != 3) {
		fprintf(stderr,"usage: ./[client] [hostname] [6 digit identification number]\n");
		exit(1);
	}

	/*Check for valid identification number*/
	id_len = strlen(argv[2]); /*string length of the cmdline id*/
	if(ID_LENGTH != id_len)
	{
		fprintf(stderr,"invalid [6 digit identification number]: should contain only 6 digits\n");
		exit(1);
	}

	strncpy(id_string,argv[2],ID_LENGTH);
	ret = validate_digits_in_string(id_string,ID_LENGTH);
	if(ret != 0)
	{
		printf("client: invalid [6 digit identification number]:should contain only digits %s\n",id_string);
		exit(1);
	}

	i = 0;
	/*Try MAX_RETRY_COUNT times to get proper message length 
	and message from the server  (triggered during mismatch)*/
	while(i < MAX_RETRY_COUNT)
	{
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
			return 1;
		}

		// loop through all the results and connect to the first we can
		for(p = servinfo; p != NULL; p = p->ai_next) {
			if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
					perror("client: socket");
					continue;
			}

			if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				perror("client: connect");
				if(sockfd)
					close(sockfd);
				continue;
			}


			/*find the socket buffer sizes*/
			getsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,(void *)&rcv_soc_buff_size, &m);
			getsockopt(sockfd,SOL_SOCKET,SO_SNDBUF ,(void *)&snd_soc_buff_size, &m);

		/*	printf("SO_RCVBUF = %d;SO_SNDBUF = %d\n",rcv_soc_buff_size,snd_soc_buff_size);
			flags = fcntl(sockfd, F_GETFL, 0);
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);*/
			break;
		}

		if (p == NULL) 
		{
			fprintf(stderr, "client: failed to connect\n");
			if(sockfd)
				close(sockfd);
			return 2;
		}

		inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
		printf("client: connecting to %s\n", s);

		freeaddrinfo(servinfo); // all done with this structure

		/*send the identification number to the server*/
		if (send(sockfd,id_string, ID_LENGTH, 0) == -1)
		{
			perror("send");
			if(sockfd)
				close(sockfd);
			exit(1);
		}

		/*receive the length of the message that the server will transmit*/
		memset(buf,0,MAXDATASIZE);
		numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0);
		if (numbytes < 0) 
		{
			perror("recv");
			if(sockfd)
				close(sockfd);
			exit(1);
		}
		buf[numbytes] = '\0';

		/*check if the message length is a valid string containing only  digits*/
		ret = validate_digits_in_string(buf,strlen(buf));
		if(ret != 0)
		{
			printf("client: invalid message length:should contain only digits %s;Will retry\n",buf);
			if(sockfd)
				close(sockfd);
			i++;
			continue; /*retry*/
		}

		numbytes = atoi(buf);
		/*allocate memory for the message from the server*/
		output = (unsigned char*)calloc(numbytes+1,sizeof(unsigned char));
		if(!output)
		{
			printf("client: memory allocation failed\n");
			if(sockfd)
				close(sockfd);
			exit(1);
		}

		/*receive the message from the server*/
		ret = recv(sockfd, output, numbytes, 0);
		if (ret < 0) 
		{
			perror("recv");
			close(sockfd);
			exit(1);
		}
		output[numbytes] = '\0';

		/*server sent lesser bytes than expected;retry*/
		if(ret != numbytes)
		{
			printf("client: msg not as per to expected message length;retrying!!!\n" );
			if(output)
			{
				free(output);
				output = NULL;
			}
			if(sockfd)
				close(sockfd);
			i++;
		}
		else /*server sent bytes as expected or more than expected*/
		{
			printf("client: Identification No.= %s\n",id_string);
			printf("client: Msg from Server = %s",output);

			/*check if there are any residual data in the buffer
			if the server has sent more data than indicated*/
			memset(output,0,numbytes);
			while(1)
			{
				memset(output,0,numbytes);
				ret = recv(sockfd, output, numbytes, MSG_DONTWAIT); /*Non blocking recv call*/
				if (ret <= 0) /*-1 for EAGAIN or EWOULDBLOCK; 0 for peer closed connection*/ 
				{
					break; /*no more data;clean up below*/
				}
				printf("%s",output);
			}

			break;
		}
	}			

	printf("\n");

	/*memory deallocation*/
	if(output)
		free(output);
	output = NULL;

	if(sockfd)
		close(sockfd);

	return 0; /*client exits*/
}
