<h1 align="center">Trillian IMPP plugin for libpurple</h1>

# Status

Right now it's a proof-of-concept. It was meant to be a prototype for my Kickstarter project, but turned out Kickstarter's list of countries is very short, and as it happens, mine is not included. I was about to try Indiegogo, however along the way to my native currency it takes so many fees that unless I demand something big for this project, it defeats the purpose. Granted though, I don't know if it would be the same for Kickstarter. As I don't use Trillian personally, ATM I'm not actively working on the project, until I find sponsors *(I do accept contributions though)*.

It's able to use TLS, authenticate, send/receive plain-text messages, send/receive protocol-level pings, receive typing notification, receive offline messages *(being a separate feature in the protocol; however notification of the server about them received is not yet implemented, i.e. the server gonna spam them on every connection)*. There's also a partial support for compression, but at the moment it only wired up at [deflate-preload](https://github.com/Hi-Angel/purple-impp/tree/deflate_preload) branch, being a temporary branch until the support gets implemented everywhere.

Code-wise it's also able for α) human-readable representation of packets *(in terse haskell-like syntax)*, which proved to be an amazing debugging and reverse-engineering facility; and β) there's a build target `trillian_preload` meant as a library for injection into the original Trillian client to sniff on its data flow *(but because Trillian client always uses compression, the target is fully operational at `deflate_preload` branch, see a note on it above)*.

**In its current state it is not meant to be used in real world** as there's an ocean of things to be done. In particular, after a while server tends to forcefully disconnect the client for unknown reason — hopefully pings have solved that though.

# Building

Dependencies: libpurple, zlib, [cereal](https://github.com/USCiLab/cereal). Building only tested on GNU/Linux — I have not tested compilation on other operating systems, it's one of many *to-be-done* things.

	$ meson build
	$ ninja -C build
	$ mv libpurple-impp.so ~/.purple/plugins/

# FAQ:

Q: I'm getting a build error like this:


	FAILED: a@exe/serialize.cpp.o
	c++  -Ia@exe -I. -I.. -I/usr/include/libpurple -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -fdiagnostics-color=always -pipe -D_FILE_OFFSET_BITS=64 -Wall -Winvalid-pch -Wnon-virtual-dtor -O0 -g '-DPREFIX="/usr/local"' '-DLIBDIR="lib"' '-DPLUGIN_VERSION="0.1.0"' -O0 -g3 -fsanitize=address -std=c++17 -Wall -Wextra -Wno-unused-parameter -MMD -MQ 'a@exe/serialize.cpp.o' -MF 'a@exe/serialize.cpp.o.d' -o 'a@exe/serialize.cpp.o' -c ../serialize.cpp
	In file included from /usr/include/cereal/access.hpp:38:0,
					 from /usr/include/cereal/details/traits.hpp:43,
					 from /usr/include/cereal/cereal.hpp:43,
					 from /usr/include/cereal/archives/binary.hpp:32,
					 from ../serialize.cpp:2:
	/usr/include/cereal/details/helpers.hpp: In instantiation of ‘cereal::BinaryData<T>::BinaryData(T&&, uint64_t) [with T = const unsigned char*&; uint64_t = long unsigned int]’:
	/usr/include/cereal/cereal.hpp:82:40:   required from ‘cereal::BinaryData<T> cereal::binary_data(T&&, size_t) [with T = const unsigned char*&; size_t = long unsigned int]’
	../serialize.cpp:35:34:   required from ‘std::variant<T, std::monostate> deserialize(const uint8_t*, uint) [with T = tlv_packet_header; uint8_t = unsigned char; uint = unsigned int]’
	../serialize.cpp:46:62:   required from here
	/usr/include/cereal/details/helpers.hpp:219:72: error: invalid conversion from ‘const void*’ to ‘cereal::BinaryData<const unsigned char*&>::PT {aka void*}’ [-fpermissive]
		 BinaryData( T && d, uint64_t s ) : data(std::forward<T>(d)), size(s) {}

A: this is a bug in Cereal. [I fixed it](https://github.com/USCiLab/cereal/pull/455), but if you're still getting the error, it means you don't have the fix. You can get it by simply copying from the link — it's only 2 lines of code.
