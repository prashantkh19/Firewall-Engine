/* including rule file */

:- [database].

isElementOf(X,[X|T]).          
isElementOf(X,[H|T]) :-        
   isElementOf(X,T).           


validAlphabets(['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P']).

/*merging two lists*/
merge([],X,X).                            
merge([X|Y],Z,[X|W]) :- merge(Y,Z,W).   

/*alphabet successor function*/
assign(Z,[H|T]):-Z=H.
recurse(X,[X|T],Z):-assign(Z,T).
recurse(X,[H|T],Z):-recurse(X,T,Z).
succAlpha(X,Z):-validAlphabets(Y),recurse(X,Y,Z).

/*appending en ele in the list*/ 
append(E,T,L):-L=[E|T].

/* not equal*/
notEquals(X,Y):- X\=Y.

/* equal*/
equals(X,Y):- X==Y.

/* converting string to int*/

/*ip successor function */
traverse([],[],Z):-Z=1,!.
traverse([H1|T1],[H2|T2],Z):-atom_number(H1,NH1),atom_number(H2,NH2),((NH1>NH2,Z=1,!);(NH1<NH2,Z=0,!);traverse(T1,T2,Z)).
compareIP(X,Y,Z):-split_string(X,"./","",L1),split_string(Y,"./","",L2),traverse(L1,L2,Z).

/*IMPORTING ADAPTER RULES*/
adapterRangeRecurse(X,X,Z,Q):-append(X,Z,W),Q=W.
adapterRangeRecurse(X,Y,Z,Q):-append(X,Z,W),succAlpha(X,X1),adapterRangeRecurse(X1,Y,W,T),Q=T.

acceptAdapterRangeList(Z):-acceptAdapterRange(X,Y),adapterRangeRecurse(X,Y,[],T),Z=T.
rejectAdapterRangeList(Z):-rejectAdapterRange(X,Y),adapterRangeRecurse(X,Y,[],T),Z=T.
dropAdapterRangeList(Z):-dropAdapterRange(X,Y),adapterRangeRecurse(X,Y,[],T),Z=T.

acceptFinalAdapterList(Z):-acceptAdapterRangeList(RL),acceptAdapterList(L),merge(RL,L,Z).
rejectFinalAdapterList(Z):-rejectAdapterRangeList(RL),rejectAdapterList(L),merge(RL,L,Z).
dropFinalAdapterList(Z):-dropAdapterRangeList(RL),dropAdapterList(L),merge(RL,L,Z).

checkAdapter(X,Q):-acceptFinalAdapterList(L),isElementOf('any',L),write('ADAPTER PASS! '),Q=3.
checkAdapter(X,Q):-acceptFinalAdapterList(L),isElementOf(X,L),write('ADAPTER PASS! '),Q=3.
checkAdapter(X,Q):-rejectFinalAdapterList(L),isElementOf(X,L),write('ADAPTER REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1.
checkAdapter(X,Q):-dropFinalAdapterList(L),isElementOf(X,L),write('ADAPTER DROP! '),Q=2.

/*IMPORTING ETHER RULES*/

checkEther(X,Y,Q):-
	((rejectEtherVIDList(VL),isElementOf('any',VL),succ(0,R),D=0,A=0);
	(dropEtherVIDList(VL),isElementOf('any',VL),succ(0,D),A=0,R=0);
	(acceptEtherVIDList(VL),isElementOf('any',VL),succ(0,A),R=0,D=0);
	(rejectEtherVIDRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,R),D=0,A=0);
	(rejectEtherVIDList(VL),isElementOf(X,VL),succ(0,R),D=0,A=0);
	(dropEtherVIDRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,D),A=0,R=0);
	(dropEtherVIDList(VL),isElementOf(X,VL),succ(0,D),A=0,R=0);
	(acceptEtherVIDRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,A),R=0,D=0);
	(acceptEtherVIDList(VL),isElementOf(X,VL),succ(0,A),R=0,D=0)),

((rejectEtherProtocolList(PL),isElementOf('any',PL),succ(R,R1),D1=D,A1=A);
	(dropEtherProtocolList(PL),isElementOf('any',PL),succ(D,D1),R1=R,A1=A);
	(acceptEtherProtocolList(PL),isElementOf('any',PL),succ(A,A1),D1=D,R1=R);
	(rejectEtherProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(R,R1),D1=D,A1=A);
	(rejectEtherProtocolList(PL),isElementOf(Y,PL),succ(R,R1),D1=D,A1=A);
	(dropEtherProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(D,D1),R1=R,A1=A);
	(dropEtherProtocolList(PL),isElementOf(Y,PL),succ(D,D1),R1=R,A1=A);
	(acceptEtherProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(A,A1),D1=D,R1=R);
	(acceptEtherProtocolList(PL),isElementOf(Y,PL),succ(A,A1),D1=D,R1=R)),
	((R1>=1,write('ETHER REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1,!);(D1>=1,write('ETHER DROP! '),Q=2,!);(A1==2,write('ETHER ACCEPTED! '),Q=3,!)).


/*IMPORTING IP RULES*/

/*checking clause*/

checkIP(S,Dt,P,Q):-
	((rejectIPSrcAddList(SL),isElementOf('any',SL),succ(0,R),A=0,D=0);
	(dropIPSrcAddList(SL),isElementOf('any',SL),succ(0,D),A=0,R=0);
	(acceptIPSrcAddList(SL),isElementOf('any',SL),succ(0,A),R=0,D=0);
	(rejectIPSrcAddRange(Re1,Re2),Re1\='~',Re2\='~',compareIP(S,Re1,Z1),compareIP(Re2,S,Z2),Z1==1,Z2==1,succ(0,R),D=0,A=0);
	(rejectIPSrcAddList(SL),isElementOf(S,SL),succ(0,R),A=0,D=0);
	(dropIPSrcAddRange(Re1,Re2),Re1\='~',Re2\='~',compareIP(S,Re1,Z1),compareIP(Re2,S,Z2),Z1==1,Z2==1,succ(0,D),A=0,R=0);
	(dropIPSrcAddList(SL),isElementOf(S,SL),succ(0,D),A=0,R=0);
	(acceptIPSrcAddRange(Re1,Re2),Re1\='~',Re2\='~',compareIP(S,Re1,Z1),compareIP(Re2,S,Z2),Z1==1,Z2==1,succ(0,A),R=0,D=0);
	(acceptIPSrcAddList(SL),isElementOf(S,SL),succ(0,A),R=0,D=0)),

	((rejectIPDstAddList(DL),isElementOf('any',DL),succ(R,R1),A1=A,D1=D);
	(dropIPDstAddList(DL),isElementOf('any',DL),succ(D,D1),A1=A,R1=R);
	(acceptIPDstAddList(DL),isElementOf('any',DL),succ(A,A1),R1=R,D1=D);
	(rejectIPDstAddRange(DRe1,DRe2),DRe1\='~',DRe2\='~',compareIP(Dt,DRe1,Z1),compareIP(DRe2,Dt,Z2),Z1==1,Z2==1,succ(R,R1),A1=A,D1=D);
	(rejectIPDstAddList(DL),isElementOf(Dt,DL),succ(R,R1),A1=A,D1=D);
	(dropIPDstAddRange(DRe1,DRe2),DRe1\='~',DRe2\='~',compareIP(Dt,DRe1,Z1),compareIP(DRe2,Dt,Z2),Z1==1,Z2==1,succ(D,D1),A1=A,R1=R);
	(dropIPDstAddList(DL),isElementOf(Dt,DL),succ(D,D1),A1=A,R1=R);
	(acceptIPDstAddRange(DRe1,DRe2),DRe1\='~',DRe2\='~',compareIP(Dt,DRe1,Z1),compareIP(DRe2,Dt,Z2),Z1==1,Z2==1,succ(A,A1),R1=R,D1=D);
	(acceptIPDstAddList(DL),isElementOf(Dt,DL),succ(A,A1),R1=R,D1=D)),

	((rejectIPProtocolList(PL),isElementOf('any',PL),succ(R1,R2),D2=D1,A2=A1);
	(dropIPProtocolList(PL),isElementOf('any',PL),succ(D1,D2),R2=R1,A2=A1);
	(acceptIPProtocolList(PL),isElementOf('any',PL),succ(A1,A2),D2=D1,R2=R1);
	(rejectIPProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',P>=PRe1,P=<PRe2,succ(R1,R2),D2=D1,A2=A1);
	(rejectIPProtocolList(PL),isElementOf(P,PL),succ(R1,R2),D2=D1,A2=A1);
	(dropIPProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',P>=PRe1,P=<PRe2,succ(D1,D2),R2=R1,A2=A1);
	(dropIPProtocolList(PL),isElementOf(P,PL),succ(D1,D2),R2=R1,A2=A1);
	(acceptIPProtocolRange(PRe1,PRe2),PRe1\='~',PRe2\='~',P>=PRe1,P=<PRe2,succ(A1,A2),D2=D1,R2=R1);
	(acceptIPProtocolList(PL),isElementOf(P,PL),succ(A1,A2),D2=D1,R2=R1)),
	((R2>=1,write('IP REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1);(D2>=1,write('IP DROP! '),Q=2);(A2==3,write('IP ACCEPTED! ')),Q=3).


/*-------------------------------------------------------------------------------------------------------------------------------*/

/*IMPORTING TCP RULES*/

checkTCP(X /*TcpSrcPort*/,Y /*TcpDstPort*/,Q):-
	((rejectTcpSrcPortList(VL),isElementOf('any',VL),succ(0,R),D=0,A=0);
	(dropTcpSrcPortList(VL),isElementOf('any',VL),succ(0,D),A=0,R=0);
	(acceptTcpSrcPortList(VL),isElementOf('any',VL),succ(0,A),R=0,D=0);
	(rejectTcpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,R),D=0,A=0);
	(rejectTcpSrcPortList(VL),isElementOf(X,VL),succ(0,R),D=0,A=0);
	(dropTcpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,D),A=0,R=0);
	(dropTcpSrcPortList(VL),isElementOf(X,VL),succ(0,D),A=0,R=0);
	(acceptTcpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,A),R=0,D=0);
	(acceptTcpSrcPortList(VL),isElementOf(X,VL),succ(0,A),R=0,D=0)),

((rejectTcpDstPortList(PL),isElementOf('any',PL),succ(R,R1),D1=D,A1=A);
	(dropTcpDstPortList(PL),isElementOf('any',PL),succ(D,D1),R1=R,A1=A);
	(acceptTcpDstPortList(PL),isElementOf('any',PL),succ(A,A1),D1=D,R1=R);
	(rejectTcpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(R,R1),D1=D,A1=A);
	(rejectTcpDstPortList(PL),isElementOf(Y,PL),succ(R,R1),D1=D,A1=A);
	(dropTcpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(D,D1),R1=R,A1=A);
	(dropTcpDstPortList(PL),isElementOf(Y,PL),succ(D,D1),R1=R,A1=A);
	(acceptTcpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(A,A1),D1=D,R1=R);
	(acceptTcpDstPortList(PL),isElementOf(Y,PL),succ(A,A1),D1=D,R1=R)),

	((R1>=1,write('TCP REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1);(D1>=1,write('TCP DROP! '),Q=2);(A1==2,write('TCP ACCEPTED! ')),Q=3).

/*---------------------------------------------------------------------------------------------------------------------*/

/*IMPORTING UDP RULES*/

checkUDP(X /*UdpSrcPort*/,Y /*UdpDstPort*/,Q):-
	((rejectUdpSrcPortList(VL),isElementOf('any',VL),succ(0,R),D=0,A=0);
	(dropUdpSrcPortList(VL),isElementOf('any',VL),succ(0,D),A=0,R=0);
	(acceptUdpSrcPortList(VL),isElementOf('any',VL),succ(0,A),R=0,D=0);
	(rejectUdpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,R),D=0,A=0);
	(rejectUdpSrcPortList(VL),isElementOf(X,VL),succ(0,R),D=0,A=0);
	(dropUdpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,D),A=0,R=0);
	(dropUdpSrcPortList(VL),isElementOf(X,VL),succ(0,D),A=0,R=0);
	(acceptUdpSrcPortRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,A),R=0,D=0);
	(acceptUdpSrcPortList(VL),isElementOf(X,VL),succ(0,A),R=0,D=0)),

((rejectUdpDstPortList(PL),isElementOf('any',PL),succ(R,R1),D1=D,A1=A);
	(dropUdpDstPortList(PL),isElementOf('any',PL),succ(D,D1),R1=R,A1=A);
	(acceptUdpDstPortList(PL),isElementOf('any',PL),succ(A,A1),D1=D,R1=R);
	(rejectUdpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(R,R1),D1=D,A1=A);
	(rejectUdpDstPortList(PL),isElementOf(Y,PL),succ(R,R1),D1=D,A1=A);
	(dropUdpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(D,D1),R1=R,A1=A);
	(dropUdpDstPortList(PL),isElementOf(Y,PL),succ(D,D1),R1=R,A1=A);
	(acceptUdpDstPortRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(A,A1),D1=D,R1=R);
	(acceptUdpDstPortList(PL),isElementOf(Y,PL),succ(A,A1),D1=D,R1=R)),

	((R1>=1,write('UDP REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1);(D1>=1,write('UDP DROP! '),Q=2);(A1==2,write('UDP ACCEPTED! ')),Q=3).

/*----------------------------------------------------------*/
/*IMPORTING ICMP RULES*/

checkICMP(X /*ICMPType*/,Y /*ICMPCode*/,Q):-

	((rejectICMPTypeList(VL),isElementOf('any',VL),succ(0,R),D=0,A=0);
	(dropICMPTypeList(VL),isElementOf('any',VL),succ(0,D),A=0,R=0);
	(acceptICMPTypeList(VL),isElementOf('any',VL),succ(0,A),R=0,D=0);
	(rejectICMPTypeRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,R),D=0,A=0);
	(rejectICMPTypeList(VL),isElementOf(X,VL),succ(0,R),D=0,A=0);
	(dropICMPTypeRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,D),A=0,R=0);
	(dropICMPTypeList(VL),isElementOf(X,VL),succ(0,D),A=0,R=0);
	(acceptICMPTypeRange(Re1,Re2),Re1\='~',Re2\='~',X>=Re1,X=<Re2,succ(0,A),R=0,D=0);
	(acceptICMPTypeList(VL),isElementOf(X,VL),succ(0,A),R=0,D=0)),


	((rejectICMPTypeList(PL),isElementOf('any',PL),succ(R,R1),D1=D,A1=A);
	(dropICMPTypeList(PL),isElementOf('any',PL),succ(D,D1),R1=R,A1=A);
	(acceptICMPTypeList(PL),isElementOf('any',PL),succ(A,A1),D1=D,R1=R);
	(rejectICMPCodeRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(R,R1),D1=D,A1=A);
	(rejectICMPTypeList(PL),isElementOf(Y,PL),succ(R,R1),D1=D,A1=A);
	(dropICMPCodeRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(D,D1),R1=R,A1=A);
	(dropICMPTypeList(PL),isElementOf(Y,PL),succ(D,D1),R1=R,A1=A);
	(acceptICMPCodeRange(PRe1,PRe2),PRe1\='~',PRe2\='~',Y>=PRe1,Y=<PRe2,succ(A,A1),D1=D,R1=R);
	(acceptICMPTypeList(PL),isElementOf(Y,PL),succ(A,A1),D1=D,R1=R)),
	((R1>=1,write('ICMP REJECTED ... RESULT: FIREWALL REJECTED THE PACKET!'),Q=1);(D1>=1,write('ICMP DROP! '),Q=2);(A1==2,write('ICMP ACCEPTED! ')),Q=3).


/*----------------------------------------------------------------------------------------*/
/*INPUT*/

check(A,EV,EP,IS,ID,IP,TS,TD,US,UD,ICP,ICM):-
checkAdapter(A,W),
((W==1,false);(W==2,true);(W==3,true)),
checkEther(EV,EP,Q),
((Q==1,false);(Q==2,true);(Q==3,true)),
checkIP(IS,ID,IP,R),
((R==1,false);(R==2,true);(R==3,true)),
((TS\='~',TD\='~',checkTCP(TS,TD,S));(TS=='~',TD='~',S=3)),
((S==1,false);(S==2,true);(S==3,true)),
((US\='~',UD\='~',checkUDP(US,UD,T));(US=='~',UD='~',T=3)),
((T==1,false);(T==2,true);(T==3,true)),
checkICMP(ICP,ICM,U),
((U==1,false);(U==2,true);(U==3,true)),
W==3,Q==3,R==3,S==3,T==3,U==3,
write('RESULT: FIREWALL ACCEPTED THE PACKET!'),!.
