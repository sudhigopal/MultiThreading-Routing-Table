 /*
 * Author: Sudhindra Gopal Krishna
 * Email: sudhi@ou.edu
 * Data Network
 * Project 4
 * Routing
 */


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#define _GNU_SOURCE
#define MaxLine 20000
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "pcap_server.h"

/*
 * This structure is used to store
 * local ip (first line of the text file)
 * lcoal port (second line of the text file)
 * Number of neighbors (Third line of the text file)
 */
struct sourceInfo{
	char myIP[10];
	int port;
	int NoOfNeig;

}srcInfo;

/*
 * This structure stores All neighbors detail
 * including Destination address and portnumber
 * of that destination
 */

struct neighborInfo{

    char destIP[10];
    char sourceIP[10];
    int portNo;
}neiInfo[15];

/*
 * This structure stores all routing detail
 * including Destination address and next hop
 * for that destination
 */
int numIps;
struct flowTable{
	char destIP[10];
	char nextHop[10];
}flows[20];
int packets = 0;
/*
 * This is one of the thread functions
 * which accepts the argument list provided
 * by the user and topollogy match
 *
 */
void *sender(void *args){

	// Wait till some of the hosts are up and running


	char **argList = (char**)args;
	// printf("Delay %d\n",atoi(argList[3]));
	sleep(10);
	int sockfd;
	struct sockaddr_in servaddr;
	u_char *data;
	char errBuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const char *fname = argList[1];


	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}


	memset(&servaddr, 0, sizeof(servaddr));

	//server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;


	int n;
	socklen_t len;

	// Read the Pcap file
	pcap_t *handle = pcap_open_offline(fname, errBuff);

	// Obtain the information of each frame of the captured packet one at a time.
	int returnValue = pcap_next_ex(handle, &header, &data);

	int capturedLen = header->caplen; // Total length of the captured data
	ip = (struct sniffIP*)(data + 16);

	while(returnValue>0){

		/*
		 * This part of the code reads through all the packets
		 * it first checks if the source address is same as my host address.
		 */
		// ip->ip_ttl = 10; //Dampening ttl
		// printf("%d\n", );
		if(strcmp(srcInfo.myIP, inet_ntoa(ip->ip_src))==0){
			/*
 			 * If that's true then it goes through all neighbors of that host
 			 */
			for(int i=0; i<numIps; i++){
				/* If their is match between destIP with the packet destination IP
				 * Then go through all the neighbours of that particular IP
				 * This will provide the broder insight for the packet for it rerouting
				 * Then we check if the next hop was one of those neighbor,
				 * This enables us to collect the port number and make a connection to the next hop
				 * The packet reroutes approximatly for ttl = diameter of the graph
				 */
				if(!strcmp(inet_ntoa(ip->ip_dst), flows[i].destIP)){
					for(int j=0; j<srcInfo.NoOfNeig; j++){
						if(!strcmp(flows[i].nextHop, neiInfo[j].destIP)){
							
							servaddr.sin_port = htons(neiInfo[j].portNo);
							sendto(sockfd, (const char*)data, 4096, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
						}
					}
				}
			}	
		}
		// To get next frame.
		returnValue = pcap_next_ex(handle, &header, &data);

	}
	close(sockfd);
	// return NULL;
}

void *receiver(){

    sleep(3);
	int sockfd;
	u_char buffer[20000];
	int i=0;
	struct sockaddr_in servaddr, cliaddr;
	int n = 0;
	// struct Stack *stack = createStack(50);
	socklen_t len;

	//creating socket
	//to connect sender and recceiver
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(srcInfo.port);

	if( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		perror("Binding failed");
		exit(EXIT_FAILURE);
	}
	// sleep(1);

	while(1){

		n = recvfrom(sockfd, (u_char *)buffer, sizeof(buffer), 0, (struct sockaddr *) &cliaddr, &len);
		buffer[n] = '\0';
		ip = (struct sniffIP*)(buffer + 16);
		/*
         * if that matches then I send that data frame to the specific
         * sender by connecting it with receiver's port number
		*/
		if(!strcmp(inet_ntoa(ip->ip_dst), srcInfo.myIP)){
			printIP(buffer);
			printData(buffer);
		}else{
			for(int i=0; i<numIps; i++){
				/* If their is match between destIP with the packet destination IP
				 * Then go through all the neighbours of that particular IP
				 * This will provide the broder insight for the packet for it rerouting
				 * Then we check if the next hop was one of those neighbor,
				 * This enables us to collect the port number and make a connection to the next hop
				 * The packet reroutes approximatly for ttl = diameter of the graph
				 */
				if(!strcmp(inet_ntoa(ip->ip_dst), flows[i].destIP)){
					for(int j=0; j<srcInfo.NoOfNeig; j++){
						if(!strcmp(flows[i].nextHop, neiInfo[j].destIP)){
							
							servaddr.sin_port = htons(neiInfo[j].portNo);
							sendto(sockfd, (const char*)buffer, 4096, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
						}
					}
				}
			}
		}

	}
	
}

int main(int argc, char *argv[]){

	FILE *myFile, *switchFile;
    myFile = fopen(argv[2], "r");
	switchFile = fopen(argv[4], "r");
    //read file into array
    char numberArray[100];
    int i;

    if (myFile == NULL){
        printf("Error Reading File\n");
        exit (0);
    }
    memset(numberArray, 0, 100);

    fscanf(myFile, "%100s", numberArray);
    strcpy(srcInfo.myIP, numberArray);
    // printf("%s\n",srcInfo.myIP );

    fscanf(myFile, "%100s", numberArray);
    srcInfo.port = atoi(numberArray);
    // printf("%d\n",srcInfo.port);

    fscanf(myFile, "%100s", numberArray);
    srcInfo.NoOfNeig = atoi(numberArray);
    // printf("%d\n", srcInfo.NoOfNeig);
    neiInfo[srcInfo.NoOfNeig];

    for(int i=0; i<srcInfo.NoOfNeig; i++){
        fscanf(myFile, "%100s", numberArray);
        strcpy(neiInfo[i].destIP, numberArray);

        fscanf(myFile, "%100s", numberArray);
        strcpy(neiInfo[i].sourceIP, numberArray);

        fscanf(myFile, "%100s", numberArray);
        neiInfo[i].portNo = atoi(numberArray);

        // printf("%s, %s, %d\n", neiInfo[i].destIP, neiInfo[i].sourceIP, neiInfo[i].portNo);
    }
	memset(numberArray, 0, 0);

	/*
	 * This is the additional part of the previous program where, it reads the routing table
	 * stores it as destination IP and Next_hop for that destination from the host.
	 */ 
	fscanf(switchFile, "%100s", numberArray);
	numIps = atoi(numberArray);
	for(int i=0;i<numIps;i++){
		fscanf(switchFile, "%100s", numberArray);
        strcpy(flows[i].destIP, numberArray);

        fscanf(switchFile, "%100s", numberArray);
        strcpy(flows[i].nextHop, numberArray);
	}

	pthread_t thread1, thread2;


/*
 * Call the client function
 */

	pthread_create(&thread1, NULL, sender, (void *)argv);

/*
 * call the server function
 */

	pthread_create(&thread2, NULL, receiver, NULL);
	sleep(10);
/*
 * Synchronize the threads
 */

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

}
