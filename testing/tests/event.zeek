# @TEST-DOC: long_conn_found
# @TEST-EXEC: zeek -Cr $TRACES/long_connection.pcap ../../../scripts %INPUT > output
# @TEST-EXEC: btest-diff output

redef LongConnection::default_durations = LongConnection::Durations(1min, 3min, 5min, 10min, 30min, 1hr, 12hr, 24hrs, 3days);

event LongConnection::long_conn_found(c: connection)
    {
    print c$uid, c$duration;
    }
