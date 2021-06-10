# @TEST-EXEC: zeek -C -r $TRACES/long_connection.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut ts id.orig_h id.resp_h orig_pkts resp_pkts duration < conn_long.log > conn_long.tmp && mv conn_long.tmp conn_long.log
# @TEST-EXEC: zeek-cut ts note msg sub  < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff conn_long.log
# @TEST-EXEC: btest-diff notice.log
