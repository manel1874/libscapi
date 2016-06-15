# Libscapi
libscapi is the C++ high performance version of scapi (Secure Multiparty Computation API). We are in beta,  release of first version is expected by 1 August 2016. 
The goal of libscapi is to promote research by Academy and Industry practitioners in this field by providing:

- A consistent API over Primitives, Mid-Layer Protocols, Interactive Mid-Layer Protocols and Communictaion Channels, simplifying the development and evaluation fo new protocols. We focus on keeping libscapi easy to build and use.
- Integrating best performance open-source implementations by other Academy Research Institutets.  
- High Performance implementation on standard Linux & Intelx64 Architecture. We use modern techniques like Intel Intrinsics Instructions, Pipelining and TCP optimizations. However, we avoid using techinques that are too advanced or not available on common platforms (such as Intel AVX-512 and DPDK, GPGPU exc).   
- Provide a common platfrom for benchmarking different alogirthms and implementations

## License information
Libscapi is released under the MIT open source license. However, some of the libraries we use have different licenses. Fo further information pleare refer to [LICENSE.MD](LICENSE.MD)

##Installing libscapi

Libscapi has is tested on Ubuntu 14.04 and should run on all major versions of Linux. It also executes on Windows 8.1/10 but with performance limitations. Interally we use the Windows option for development only. All tests execute on Linux.
Mac OSX has not been tested so far. 
For detailed instructions, see [INSTALL.MD](INSTALL.MD)




