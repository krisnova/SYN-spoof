# FreeBSD-SYN-spoof

Tested and compiled on FreeBSD 10.2+
 
A simple C script to attempt to flood a server with SYN requests in the
hopes of determining the threshold for availability.
 
This is an isolated penetration test that will send requests via a unique
thread.

The premise of this proof is to demonstrate the dangers in not completing a TCP handshake, while spoofing the packet with a bogus client IP address. 

This script is designed to be a proof, and should be used for kernel development and testing purposes only.


# Pipeline / TODO

 * [ ] Need to abstract "interface" to .h file
 * [ ] Need to abstract configuration struct to .h file
 * [ ] Command line options could use a once over
 * [ ] Following UNIX parlance, this should be a lib and util (But do we `really` need that?)
