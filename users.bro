# This module helps associate users to the connections they make

@load base/protocols/dhcp

module Users;
export {

	redef enum Log::ID += { LOG };

	type Idx: record {
		mac: string;
	};
		
	type Info: record {
		name: 		string &log;
		ip:		addr &log &optional;
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

#event new_connection()
#{
#	if orig_h is in user_cache
#	{
#		c$user = user_cache where c$orig_h is
#	}
#}

event bro_init()
{
	Log::create_stream(Users::LOG, [$columns=Info, $ev=log_users]);

	Input::add_table( [$source="users.dat", $name="users", $idx=Users::Idx, $val=Users::Info, $destination=Users::user_cache, $mode=Input::REREAD] );
	Input::remove("users");
}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
#	test if this IP address is in the user_cache first? 
#	if (user_cache[dhcp_msg$h_addr])
#	{
		print reverse_ip(msg$yiaddr);
		# i don't think the input framework has read in the table before this event is raised
		# therefor the user_cache hasn't been built yet and this command freaks out
		#user_cache[msg$h_addr]$ip = msg$yiaddr;
#	}
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
#	write the user_cache table to disk
	print Users::user_cache;
}
