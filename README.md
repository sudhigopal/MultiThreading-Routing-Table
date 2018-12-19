This project is used to run both server and client in a single code using multithreading. 

To compile this code run: 
gcc -o pcapTest  -lpthread -lpcap -w pcapPthreads.c

To run the code,
Please make sure to edit the bashtr.sh file with your directory path and run sh bashTr.sh

You can edit the bashTr file for any number of host.

Here each Host reads its own Routing table and then send the packets to its specified nextHop
