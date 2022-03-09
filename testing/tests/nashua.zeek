# @TEST-DOC: long_conn_found
# @TEST-EXEC: zeek -Cr $TRACES/NASHUA.pcap $PACKAGE %INPUT > output
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: btest-diff output

module LongConnection;

redef default_durations = Durations(1min, 3min, 5min, 10min, 30min, 1hr, 12hr, 24hrs, 3days);

event LongConnection::long_conn_found(c: connection)
    {
    print c$id, c$duration;
    }