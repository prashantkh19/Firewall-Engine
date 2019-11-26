
/*adapter*/
acceptAdapterList(['A','B']).
acceptAdapterRange('~','~').

rejectAdapterList(['F','G','H']).
rejectAdapterRange('C','E').	

dropAdapterList(['I','J']).
dropAdapterRange('C','E').

/*ether*/
acceptEtherVIDList([1,2]).
acceptEtherVIDRange(3,10).
acceptEtherProtocolList([1,2]).
acceptEtherProtocolRange(3,10).

rejectEtherVIDList([11,12]).
rejectEtherVIDRange(13,15).
rejectEtherProtocolList([11,12]).
rejectEtherProtocolRange(13,15).


dropEtherVIDList([16,17]).
dropEtherVIDRange('~','~').
dropEtherProtocolList([16,17]).
dropEtherProtocolRange('~','~').

/*ip*/

acceptIPSrcAddList(['1.2.3.1','1.2.3.2','1.2.3.3/12']).
acceptIPSrcAddRange('3.2.3.3','3.2.6.5').

acceptIPDstAddList(['1.2.3.1','1.2.3.2']).
acceptIPDstAddRange('1.2.3.3','1.2.3.5').

acceptIPProtocolList([1,2]).
acceptIPProtocolRange(3,5).

rejectIPSrcAddList(['1.2.3.6','1.2.3.7']).
rejectIPSrcAddRange('1.2.3.8','1.2.3.10').

rejectIPDstAddList(['1.2.3.6','1.2.3.7']).
rejectIPDstAddRange('1.2.3.8','1.2.3.10').

rejectIPProtocolList([6,7]).
rejectIPProtocolRange(8,10).

dropIPSrcAddList(['1.2.3.11','1.2.3.12']).
dropIPSrcAddRange('1.2.3.13','1.2.3.15').

dropIPDstAddList(['1.2.3.11','1.2.3.12']).
dropIPDstAddRange('1.2.3.13','1.2.3.15').

dropIPProtocolList([11,12]).
dropIPProtocolRange('~','~').

/*tcp*/

acceptTcpSrcPortList([]).
acceptTcpSrcPortRange(0,3).

acceptTcpDstPortList([1,2,3]).
acceptTcpDstPortRange('~','~').


rejectTcpSrcPortList([4,5,6]).
rejectTcpSrcPortRange(7,8).

rejectTcpDstPortList([4,5,6]).
rejectTcpDstPortRange(7,8).


dropTcpSrcPortList([9,10]).
dropTcpSrcPortRange(11,12).
dropTcpDstPortList([9,10]).
dropTcpDstPortRange(11,12).


/*udp*/
acceptUdpSrcPortList([]).
acceptUdpSrcPortRange(0,3).

acceptUdpDstPortList([1,2,3]).
acceptUdpDstPortRange('~','~').


rejectUdpSrcPortList([4,5,6]).
rejectUdpSrcPortRange(7,8).

rejectUdpDstPortList([4,5,6]).
rejectUdpDstPortRange(5,8).


dropUdpSrcPortList([9,10]).
dropUdpSrcPortRange(11,12).
dropUdpDstPortList([9,10]).
dropUdpDstPortRange(11,12).


/*icmp*/
acceptICMPTypeList([]).
acceptICMPTypeRange(0,3).

acceptICMPCodeList([]).
acceptICMPCodeRange(0,3).

rejectICMPTypeList([]).
rejectICMPTypeRange(4,6).

rejectICMPCodeList([]).
rejectICMPCodeRange(4,6).

dropICMPTypeList([]).
dropICMPTypeRange(7,10).

dropICMPCodeList([]).
dropICMPCodeRange(7,10).