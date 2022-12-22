main: main.cpp 
	g++ -o main.exe progressbar.hpp main.cpp hash-uppers-downers/sha1.h hash-uppers-downers/sha1.c -g

clean :
	-rm main.exe