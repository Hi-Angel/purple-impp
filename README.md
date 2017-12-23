This is an early prototype of trillian IMPP plugin for pidgin. Only athentification works ATM, and compilation tested only on GNU/Linux.

# Building'n'installing

Dependencies: libpurple, zlib, [cereal](https://github.com/USCiLab/cereal).

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
