Users
=====

A set of Bro scripts to help pin users to the connections they make
A table (user_cache) describing users and their devices' MAC addresses is read in by Bro. On DHCP and ARP events, the user_cache table is updated.
When a new connection occurs, the user_cache table is checked to see if the originator of the connection is in the user_cache
When Bro exits, log the user_cache table to disk (this needs some work to make users.bro read from users.log and write to users.log)


Usage
-----
change a MAC address in users.dat to your eth0 (or whatever interface to be monitored)
wait for Bro to read in the users.dat table
dhclient eth0 
make a connection over eth0


ToDo
----
- make the script log in the EXACT format it reads as input (closed loop)
- check all connections across user_cache table, (not just outbound)
- better organize user_cache table for accessing by MAC addr or IP addr

