unittests: aliases makros.sx sha512.sx sha512tests.sx sha512tests.c 
	gcc -g -o sha512.ut sha512.sx sha512tests.sx  sha512tests.c  
	./sha512.ut

build: libSha512.a


libSha512.a: sha512.o 
	ar rcs libSha256.a  sha512.o 


sha512.o: sha512.sx aliases makros.sx
	gcc -c -o sha512.o sha512.sx   
	
dump: sha512.o
	objdump -S -M no-aliases -s -d sha512.o > dump.txt
 

dump2: sha512.o
	objdump -s sha512.o > dump2.txt
 
	
	









	
