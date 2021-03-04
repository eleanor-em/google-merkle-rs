all:
	mkdir -p build
	cd build && cmake .. && make
	cd rust && cp ../build/libmerkletree.a lib/

test:
	mkdir -p build
	cd build && cmake .. && make
	cd rust && cp ../build/libmerkletree.a lib/
	cd rust && cargo test