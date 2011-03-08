default:
	$(MAKE) -C build/gcc4

clean:
	$(MAKE) -C build/gcc4 clean

all:
	$(MAKE) -C build/gcc4 all

install:
	$(MAKE) -C build/gcc4 install

