@load base/protocols/conn
@load base/utils/time


# This is probably not so great to reach into the Conn namespace..
module Conn;

export {
function set_conn_log_data_hack(c: connection)
	{
	Conn::set_conn(c, T);
	}
}

# Now onto the actual code for this script...

module LongConnection;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## Notice for when a long connection is found.
		## The `sub` field in the notice represents the number
		## of seconds the connection has currently been alive.
		LongConnection::found
	};

	## Aliasing vector of interval values as
	## "Durations"
	type Durations: vector of interval;

	## The default duration that you are locally 
	## considering a connection to be "long".  
	const default_durations = Durations(10min, 30min, 1hr, 12hr, 24hrs, 3days) &redef;

	## These are special cases for particular hosts or subnets
	## that you may want to watch for longer or shorter
	## durations than the default.
	const special_cases: table[subnet] of Durations = {} &redef;
}

# The yield value on this is the current offset into the
# Durations value.
global tracking_conns: table[string] of count &default=0;

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Conn::Info, $path="conn_long"]);
	}

function get_durations(c: connection): Durations
	{
	local check_it: Durations;
	if ( c$id$orig_h in special_cases )
		check_it = special_cases[c$id$orig_h];
	else if ( c$id$resp_h in special_cases )
		check_it = special_cases[c$id$resp_h];
	else
		check_it = default_durations;

	return check_it;
	}

function long_callback(c: connection, cnt: count): interval
	{
	local check_it = get_durations(c);
	local offset = tracking_conns[c$uid];

	if ( offset < |check_it| && c$duration >= check_it[offset] )
		{
		Conn::set_conn_log_data_hack(c);
		Log::write(LongConnection::LOG, c$conn);

		local message = fmt("%s -> %s:%s remained alive for longer than %s", 
		                    c$id$orig_h, c$id$resp_h, c$id$resp_p, duration_to_mins_secs(c$duration));
		NOTICE([$note=LongConnection::found,
		        $msg=message,
		        $sub=fmt("%.2f", c$duration),
		        $conn=c]);
		
		++tracking_conns[c$uid];
		# We're only bumping the local offset value
		# here so we can use it below and don't need
		# to do the hash table lookup again.
		++offset;
		}

	# Keep watching if there are potentially more thresholds.
	if ( offset < |check_it| )
		return check_it[offset];
	else
		return 0secs;
	}

event connection_established(c: connection)
	{
	local check = get_durations(c);
	if ( |check| > 0 )
		{
		ConnPolling::watch(c, long_callback, 1, check[0]);
		}
	}
