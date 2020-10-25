(C) 2016 University of Lisbon - IST.

=========== Quantum OT =============

List of files changed:

libscapi/lib/OTExtensionBristol/
	|
	|
	|---> quantum_random_oblivious_transfer :: insert this folder
	|---> Makefile :: change lines 12-13
	|
	|	12	#LIBSIMPLEOT = SimpleOT/libsimpleot.a
	|	13	LIBQOKDOT = quantum_random_oblivious_transfer/libqokdot.a
	|
	|	       :: change lines 19-22
	|
	|	19	#@echo "compling simple ot..........................."
	|	20	#cd SimpleOT && make
	|	21	cd quantum_random_oblivious_transfer && make	
	|	22	@echo "compling .a ...................."
	| 
	|	       :: change line 33
	|
	|	33 	install -m 0644 ${LIBQOKDOT} $(libdir)
	|		#install -m 0644 ${LIBSIMPLEOT} $(libdir)
	|
	|
	|---> OT/BaseOT.cpp :: adapt to qot_receiver.h and qot_sender.h
	|		    :: change lines 14 - 17
	|		    :: adapt function BaseOT::exec_base
	|			|
	|			|---> insert 'bool new_receiver_inputs' variable
	|			|---> SIMPLEOT_SENDER/RECEIVER -> QKDOT_SENDER/RECEIVER
	|			|---> Reformulate the rest of the function as shown in the doc
	|
	|---> OT/BaseOT.h :: change line 59 
	|
	|		from 'virtual void exec_base()' 
	|		to 'virtual void exec_base(bool new_receiver_inputs=true)'


MPC-Benchmark/SemiHonestYao/
	|
	|
	|---> CMakeList.txt :: change line 22-23
	|
	|	22	#OTExtensionBristol libsimpleot.a libOTe.a libcryptoTools.a libmiracl.a
        |	23	OTExtensionBristol libqokdot.a libOTe.a libcryptoTools.a libmiracl.a

