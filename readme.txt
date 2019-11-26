********************************FIREWALL ENGINE********************************

A firewall rule consists of several clauses chained together to match specific criteria for each packet. The clauses represent specific layers in the protocol stack. Each clause can be broken down into conditions and expressions. The expressions are the variable part of the rule in which you put the address, port, or numeric parameters.

The developed engine applies encoded rules on any incoming packet.


********************ASSUMPTIONS********************

If no range is to be given, then ('~','~') must be given in the corresponding range predicate of accept, reject and drop values in the database file.
Eg. acceptAdapterRange('~','~').

Single values must also be written in a list in database file.
Eg. (To allow) adapter A, in the database file, predicate should be like, acceptAdapterList(['A']). 

If only range is to be given and no list is to be given, then an empty list must be given in the predicate in the database file.
Eg. acceptAdapterList([]).

If 'any' is given in any of the lists ('accept', 'reject' or 'drop'), then corresponding action will be taken.
Eg. acceptAdapterList(['any']). - This means that no matter what is the adapter value of the incoming packet, it will be accepted.

ALL THE IDs ARE ASSUMED TO BE DECIMALS.


********************PREDICATES********************

isElementOf(X,[X|T]):- checks if X is an element of the list [X|T].

merge(X,Y,Z):- merges two lists X and Y.

succAlpha(X,Z):- gives the next alphabet after X from the list of valid alphabets that is from 'A' to 'P'.

notEquals(X,Y):- true when X is not equal to Y.

equals(X,Y):- true when X is equal to Y.

append(E,T,L):- Appends the element E in the list T.

succ(X,X1):- Gives the successor of X in X1.

split_string(X,".","",L1):- Splits X considering '.' as the delimiter.

compareIP(X,Y,Z):- Compares IP addresses X and Y by splitting it considering '.' as the delimiter ('/' is also considered as a delimiter in case of presence of a netmask).
Z=1 if X>=Y
Z=0 if X<Y


********************ADAPTER********************

acceptAdapterList(L):- For getting the adapter-to-be-accepted list present in the database file.

acceptAdapterRange(X,Y):- Gets the initial and final limits of the range of values of adapter-to-be-accepted.

adapterRangeRecurse(X,Y,Z,Q):- recursive function to get list of values from the start to the end of the range mentioned.

acceptAdapterRangeList(RL):- For getting the adapter-to-be-accepted range list obtained by recursion.

acceptFinalAdapterList(L):- Gives the combined list of values that includes the elements of adapter-to-be-accepted range list and adapter-to-be-accepted list, obtained by merging them. 

checkAdapter(X):- To check whether the adapter X will be accepted, rejected or dropped by the firewall.

The above mentioned predicates are for checking whether the adpater will be accepted or not. Similar predicates are made for the 'reject' and 'drop' checking.

********************ETHER********************

acceptEtherVIDList(L):- For getting the ether-to-be-accepted vid list present in the database file.

acceptEtherVIDRange(X,Y):- Gets the initial and final limits of the range of values of vid of ether-to-be-accepted.

rejectEtherVIDList(VL):- For getting the ether-to-be-rejected vid list present in the database file.

rejectEtherVIDRange(Re1,Re2):- Gets the initial and final limits of the range of values of vid of ether-to-be-rejected.

dropEtherVIDList(VL):- For getting the ether-to-be-dropped vid list present in the database file.

dropEtherVIDRange(Re1,Re2):- Gets the initial and final limits of the range of values of vid of ether-to-be-dropped.

If range is specified in the database, then it is checked whether the input lies in that range and the corresponding action is performed.

The above mentioned predicates are for checking whether ether will be accepted, rejected or dropped based on VID. Similar predicates are made for checking based on Protocol-id.

checkEther(X,Y):- To check whether an ether will be accepted, rejected or dropped based on the VID(=X) and Protocol-ID(=Y).


********************IPv4********************

acceptIPSrcAddList(SL):- For getting the ip-to-be-accepted src address list present in the database file.

rejectIPSrcAddList(SL):- For getting the ip-to-be-rejected src address list present in the database file.

dropIPSrcAddList(SL):- For getting the ip-to-be-dropped src address list present in the database file.

rejectIPSrcAddRange(Re1,Re2):- Gets the initial and final limits of the range of values of ip src address of ip-to-be-rejected.

dropIPSrcAddRange(Re1,Re2):- Gets the initial and final limits of the range of values of ip src address of ip-to-be-dropped.

acceptIPSrcAddRange(Re1,Re2):- Gets the initial and final limits of the range of values of ip src address of ip-to-be-accepted.

If range is specified in the database, then it is checked whether the input lies in that range, using the compare function and the corresponding action is performed.

The above mentioned predicates are for checking whether IP will be accepted, rejected or dropped based on source address. Similar predicates are made for checking based on destination address and protocol-id.

checkIP(S,Dt,P):- To check whether an ip will be accepted, rejected or dropped based on the source address(=S), destination address(=Dt) and Protocol-ID(=P).

********************TCP/UDP********************

rejectTcpSrcPortList(VL):- For getting the tcp-to-be-rejected source port list present in the database file.

dropTcpSrcPortList(VL):- For getting the tcp-to-be-dropped source port list present in the database file.

acceptTcpSrcPortList(VL):- For getting the tcp-to-be-accepted source port list present in the database file.

rejectTcpSrcPortRange(Re1,Re2):- Gets the initial and final limits of the range of values of tcp src port of tcp-to-be-rejected.

dropTcpSrcPortRange(Re1,Re2):- Gets the initial and final limits of the range of values of tcp src port of tcp-to-be-dropped.

acceptTcpSrcPortRange(Re1,Re2):- Gets the initial and final limits of the range of values of tcp src port of tcp-to-be-accepted.

If range is specified in the database, then it is checked whether the input lies in that range, and the corresponding action is performed.

The above mentioned predicates are for checking whether TCP will be accepted, rejected or dropped based on source port. Similar predicates are made for checking based on destination port.

checkTCP(X,Y):- To check whether a tcp will be accepted, rejected or dropped based on the source port(=X) and destination port(=Y).

In a similar manner, predicates for UDP are also made.


********************ICMP********************

rejectICMPTypeList(VL):- For getting the icmp-to-be-rejected type list present in the database file.

dropICMPTypeList(VL):- For getting the icmp-to-be-dropped type list present in the database file.

acceptICMPTypeList(VL):- For getting the icmp-to-be-accepted type list present in the database file.

rejectICMPTypeRange(Re1,Re2):- Gets the initial and final limits of the range of values of icmp type of icmp-to-be-rejected.

dropICMPTypeRange(Re1,Re2):- Gets the initial and final limits of the range of values of icmp type of icmp-to-be-dropped.

acceptICMPTypeRange(Re1,Re2):- Gets the initial and final limits of the range of values of icmp type of icmp-to-be-accepted.

If range is specified in the database, then it is checked whether the input lies in that range, and the corresponding action is performed.

The above mentioned predicates are for checking whether ICMP will be accepted, rejected or dropped based on icmp type. Similar predicates are made for checking based on icmp code.

checkICMP(X,Y):- To check whether an icmp will be accepted, rejected or dropped based on the icmp type(=X) and icmp code(=Y).


********************INPUT********************

check(A,EV,EP,IS,ID,IP,TS,TD,US,UD,ICP,ICM):-
checkAdapter(A),
checkEther(EV,EP),
checkIP(IS,ID,IP),
(TS\='~',TD\='~',checkTCP(TS,TD)),
(US\='~',UD\='~',checkUDP(US,UD)),
checkICMP(ICP,ICM),
write('Packet accepted by FIREWALL!!').

A - Adapter
EV - Ether VID
EP - Ether Protocol
IS - IP Source Address
ID - IP Destination Address
IP - IP Protocol-ID
TS - TCP Source Port
TD - TCP Destination Port
US - UDP Source Port
UD - UDP Destination Port
ICP - ICMP Type
ICM - ICMP Code

If only one of TCP and UDP is to be given as input, then ('~','~') must be passed as a parameter in the predicate of the other, while giving the input.


********************OUTPUT DISPLAY********************

If all the clauses are accepted, then the engine will display "FIREWALL ACCEPTED THE PACKET!", along with 'true' value as the output.

If any clause is rejected, the engine will display "FIREWALL REJECTED THE PACKET!" and will also display the reason for rejection of packet, along with 'false' value as the output.

If any clause is dropped, then the engine will still check if any further clause is rejected. If YES, then rejection message will be displayed, along with 'false' value as the output. If NO, then NO MESSAGE will be displayed ("Silently dropped!"), along with 'false' value as the output.


********************THE END********************


