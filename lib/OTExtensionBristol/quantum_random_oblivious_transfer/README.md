(C) University of Lisbon - IST

Mariana Gama
Manuel B Santos
Armando N Pinto

=========== Quantum OT ==========

This program implements a Random Oblivious Transfer based on the OT protocol presented in 
"Generation and Distribution of Quantum Oblivious Keys for Secure Multiparty Computation".

The random version of this OT is described in the Random_OT.pdf file in this repository.




#### Implementation

This implementation is divided in two different programs, one for the sender and another for the receiver.
Each of the programs contains a structure for storing the relevant data for each party, as well as a set of functions.
These functions are called from a main program and perform the local operations to be done by each party. 

The universal hash function is done following the strategy presented in https://lemire.me/blog/2018/08/15/fast-strongly-universal-64-bit-hashing-everywhere/

In `main.c`, there is a test execution of the sender and receiver programs, with the outputs being printed at the end.




#### Compiling 

Execute the `make` command to generate the associated static library liboqokdot.a, as well as ot_test (test program generated from main.c).
 



#### Remarks

We are considering that the oblivious key length is 512, and the OT ouput length is 128.
These values were chosen because of the OT length used in the MASCOT, and also because of the relation between these lengths that is required for security (see the paper).
These lengths are defined in the sender and receiver header files, and might be changed if needed. Note, however, that the hash function is written such that it generates outputs with half the size of the input (the hash function input size is always half of the oblivious key length! In this case, the hash function input size is 256 and the hash function output size is 128). Hence, depending on the desired oblivious key length and OT output length, you might need to change the way that the hash function is written (you can find it in the last loop of the `receiver_output` and `sender_output` functions).

--- Outdated ---

In this version of the program, both the receiver and the sender are reading their keys from the `ObliviousKeys.sgn` file.
The receiver aux key is being read from the `key_aux.txt` file.
Before running the program, check that the location of these files is correctly linked in `qot_receiver.c` and `qot_sender.c`.
If you want to run the oblivious key simulator for each run of this OT, we suggest calling it at the beginning of the `receiver_okd` and `sender_okd` functions.

--- Outdated ---

Inside this folder (`quantum_random_oblivious_transfer` folder), there is another folder named `mascot_files`. In that folder, there are the adaptations of the MASCOT makefile (which links the `liboqokdot.a` library when compiling the MASCOT) and also of the `BaseOT.cpp` file. This last file contains the method for doing base OTs for the MASCOT. In the original MASCOT implementation, these OTs are done using the SimpleOT protocol. With this new version of the BaseOT file, the OTs will be done using the Quantum Random OT that we implemented. 


#### Using with libScapi and MPC-Benchmark/SemiHonestYao

To use this implementation together with the libscapi implementation, please follow these steps:

1. Insert the folder `quantum_random_oblivious_transfer` inside `libscapi/lib/OTExtensionBristol`

2. Update `Makefile` in `libscapi/lib/OTExtensionBristol`

	- Change lines 12-13 to create `LIBQOKDOT` path variable to `libqokdot.a` library.

	```
	12	#LIBSIMPLEOT = SimpleOT/libsimpleot.a
	13	LIBQOKDOT = quantum_random_oblivious_transfer/libqokdot.a
	```
	
	- Change lines 19-22 to `make` `quantum_random_oblivious_transfer` project

	
	```
	19	#@echo "compling simple ot..........................."
	20	#cd SimpleOT && make
	21	cd quantum_random_oblivious_transfer && make	
	22	@echo "compling .a ...................."
	```

	- Change line 33-34 to install `libqokdot.a` instead of `libsimpleot.a`

	```
	33 	install -m 0644 ${LIBQOKDOT} $(libdir)
	34	#install -m 0644 ${LIBSIMPLEOT} $(libdir)
	```


libscapi/lib/OTExtensionBristol/
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







#### Using with MASCOT

To use this implementation together with the MASCOT implementation provided in https://github.com/data61/MP-SPDZ/, please follow these steps:

1) Download the software provided in the link above, which contains the MASCOT implementation. After this step, you will have a folder `MP_SPDZ` which contains the original MASCOT implementation.

2) Before compiling the software, install the following requirements: `automake build-essential git libboost-dev libboost-thread-dev libsodium-dev libssl-dev libtool m4 python texinfo yasm`. Additionally, you might also need to download and install the MPIR library (see http://www.cs.sjsu.edu/~mak/tutorials/InstallMPIR.pdf and http://mpir.org/downloads.html. Use `--enable-cxx` flag when running configure).

3) Put the `quantum_random_oblivious_transfer` folder in the `MP-SPDZ` directory. Execute the `make` comand inside the folder `quantum_random_oblivious_transfer` to generate the `liboqokdot.a` library.

4) Substitute the `Makefile` in `MP_SPDZ` with the `Makefile` in `quantum_random_oblivious_transfer/mascot_files`, and the file `BaseOT.cpp` in `MP_SPDZ/OT` with the one with the same name in `quantum_random_oblivious_transfer/mascot_files`.

5) Check that the location of liboqokdot.a is correctly written in the Makefile in `MP_SPDZ`. Check that the location of `qot_receiver.h` and `qot_sender.h` is correctly written in `MP_SPDZ/OT/BaseOT.cpp`.

6) Compile the MASCOT by running the command `make -j8 mascot-party.x`. You can now use the MASCOT as described in https://github.com/data61/MP-SPDZ/. When the MASCOT is running, it will use this Quantum Random OT implementation whenever an OT is needed.


A guide for compiling and using this software is also provided in `main_tq.pdf`.


