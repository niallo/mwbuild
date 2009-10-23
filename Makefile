default all:
	cd src && make
	cp src/mw .

clean:
	cd src && make clean
