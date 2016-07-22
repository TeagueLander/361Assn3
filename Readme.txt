CSC 361 Assignment 3
TCP Analysis
Teague Lander
V00710026
July 22 2016



Compiling the C files
----------------------------

- tcp_analyzer.c and other C file compilation is done 
  using the included makefile.
  
- To run the makefile ensure you are in the assignment directory in your
  terminal window and run the simple command "make".
  
- Example of running the code: 
    ~/Assn3$ make

------------------------------------------------------------------------------------


Using tcp_analyzer.c
----------------------------

- tcp_analyzer.c is an pcap file parser.  It is able to extract tcp packets and
  analyzer some statistics based on tcp header information
  
- After the file has been compiled it can be run from the terminal window.
  This program takes 2 command line arguments which is the name of a pcap capture
  file.
  
- Examples of running the tcp analyzer:
    ~/Assn3 ./tcp_analyzer sample-capture-file > text.txt
    
------------------------------------------------------------------------------------


Sources
----------------------------

- Calculating the different between two timeval structs
    https://www.mpp.mpg.de/~huber/util/timevaldiff.c


