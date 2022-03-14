Long Connections
----------------

Zeek normally logs connections at the end of the connection, but this 
can cause trouble for incident responders in the case of very long 
lived connections that end up being unknown to defenders until too
late.

This package provides a new log named `conn_long` which will log 
"intermediate" conn logs for long connections. It's logged into
a separate log stream to avoid confusing the semantics of the normal
Zeek conn log which users can assume only contains "complete" 
connections.

The script can also generate a `LongConnection::found` notice 
whenever it discovers a long connection.

Installation
------------

::

	zkg refresh
	zkg install zeek/corelight/zeek-long-connections

Configuration
-------------

The durations default to

::

	10min, 30min, 1hr, 12hr, 24hrs, 3days

And can be changed using

::

	redef LongConnection::default_durations = LongConnection::Durations(2min, 10mins, 30mins);

By default after the last duration is reached there will be no further
conn_long entries or notices.  This can be changed by using

::

	redef LongConnection::repeat_last_duration=T;

If that option is enabled, a duration list of

::

	(2min, 10mins, 30mins)

Will behave like

::

	(2min, 10mins, 30mins, 30mins, 30mins, 30mins, 30mins, ...)

The notices are enabled by default but can be disabled using

::

	redef LongConnection::do_notice=F;
