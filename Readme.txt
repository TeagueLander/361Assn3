CSC 361 Assignment 3
IP Analysis
Teague Lander
V00710026
July 22 2016


//REQUIREMENT 2

- Determine the number of probes per “ttl” used in each trace file
	There are 3 probes per ttl used in each trace file
- Determine whether or not the sequence of intermediate routers is the same in different trace files
	Files trace3 and trace4 take the exact same path of routers.  
	The other files follow similar paths with only 1 or two differences.
	This is likely due to hot-potatoe routing.
- TABLE:
	TTL		Avg RTT in trace3		Avg RTT in trace4
	 1				0.017529 s			0.016821 s
	 2				0.023598 s			0.023569 s
	 3				0.024471 s			0.023131 s
	 4				0.025737 s			0.025033 s
	 5				0.026872 s			0.026164 s
	 6				0.018170 s			0.017279 s
	 7				0.021609 s			0.020381 s
	 8				0.022773 s			0.021009 s
	 9				0.027128 s			0.025396 s
	 10				0.028297 s			0.027271 s
	 11				0.030154 s			0.029151 s
	 12				0.020755 s			0.020759 s
The biggest hop is from 8 to 9 (207.23.244.242) to (206.12.3.17)

//REQUIREMENT 1

Compiling the C files
----------------------------

- ip_analyzer.c and other C file compilation is done 
  using the included makefile.
  
- To run the makefile ensure you are in the assignment directory in your
  terminal window and run the simple command "make".
  
- Example of running the code: 
    ~/Assn3$ make

------------------------------------------------------------------------------------


Using ip_analyzer.c
----------------------------

- ip_analyzer.c is an pcap file parser.  It is able to extract ip packets and
  analyzer some statistics based on ip header information and ip data
  
- After the file has been compiled it can be run from the terminal window.
  This program takes 2 command line arguments which is the name of a pcap capture
  file.
  
- Examples of running the ip analyzer:
    ~/Assn3 ./ip_analyzer sample-capture-file > text.txt
    
------------------------------------------------------------------------------------


Sources
----------------------------

Codes based on samples provided for assignment 2 and 3

- Calculating the different between two timeval structs
    https://www.mpp.mpg.de/~huber/util/timevaldiff.c
- IP header
    unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
- ICMP header
	https://www.cymru.com/Documents/ip_icmp.h

