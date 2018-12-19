#include <stdio.h>
#include <stdlib.h>

struct sourceInfo{
	char myIP[9];
	int port;
	int NoOfNeig;
	char Neighbours[50];
};


int main(){

	FILE *infile; 
    struct sourceInfo input; 

    infile = fopen ("/Users/sudhigopal/Downloads/Project2Input/1.txt", "r"); 

     if (infile == NULL) 
    { 
        fprintf(stderr, "\nError opening file\n"); 
        exit (1); 
    } 
      
    // read file contents till end of file 
    while(fread(&input, sizeof(struct person), 1, infile)) 
        printf ("IP = %s port = %d NoOfNeig = %d Neighbours = %s\n", input.myIP, input.port, input.NoOfNeig, input.Neighbours); 
  
    // close file 
    fclose (infile); 
  
    return 0; 

}