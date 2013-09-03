# This module helps associate users to the connections they make

@load base/protocols/dhcp

module Users;

export {

	redef enum Log::ID += { LOG };

	type Idx: record {
		mac: string;
	};
		
	type Info: record {
		ip:		addr &log &optional;
		name: 		string &log;
		#mac:		string &log;
 	        department: 	string &log;
 	        location:	string &log;
 	        email:		string &log;
	};

	global log_users: event(rec: Info);

	redef record connection += {
		user: Info &optional;
	};

	global user_cache: table[string] of Info;
}

# i shouldn't have to define this function again. it is alread defined in base/protocols/dhcp/utils and is loaded by base/protocols/dhcp/main
# fix this...
function reverse_ip(ip: addr): addr
{
        local octets = split(cat(ip), /\./);
	return to_addr(cat(octets[4], ".", octets[3], ".", octets[2], ".", octets[1]));
}

event new_connection(c: connection)
{
	local each: string;

	for (each in user_cache)
	{
		# this should check if is_orig OR something. 
		# it should work for more than connection made by IPs associated to MAC addrs in the users.dat table
		# it should also work for connections TO IPs associated with MAC addrs in the users.dat table
		#
		# this if statement bitches if the new_connection event occurs before Bro finished reading in the user.dat table
		
		if (user_cache[each]?$ip)
		{
			print "connection being made by: ";
			print user_cache[each];
		}
		
	#	if (user_cache[each]$ip == c$id$orig_h)
	#	{
	#		c$user = user_cache[each];
	#	}
	}
}

event bro_init()
{
	Log::create_stream(Users::LOG, [$columns=Users::Info, $ev=Users::log_users]);

	Input::add_table( [$source="users.dat", $name="users", $idx=Users::Idx, $val=Users::Info, $destination=Users::user_cache, $mode=Input::REREAD] );
	Input::remove("users");
}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
	if (msg$h_addr in Users::user_cache)
	{
		Users::user_cache[msg$h_addr]$ip = reverse_ip(msg$yiaddr);
	}
}

#event DHCP_release()
#{
#	remove entry from user_cache table
#}

# event ARP_something()
#{
#	update user_cache table
#}

event bro_done()
{

#	write the user_cache table to disk for rereading upon starting back up
	for (each in Users::user_cache)
	{
		Log::write(Users::LOG, Users::user_cache[each]);
	}
}
