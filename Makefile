all:
	mkdir -p build
	cd build && cmake .. && make
	cd rust && cp ../build/libmerkletree.a lib/ \
						&& cp ../c/merkletree.h include/ \
						&& cp ../c/verifier.h include/

test:
	mkdir -p build
	cd build && cmake .. && make
	cd rust && cp ../build/libmerkletree.a lib/ \
						&& cp ../c/merkletree.h include/ \
						&& cp ../c/verifier.h include/
	cd rust && cargo test