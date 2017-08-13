
/* ################################################################################# */
/* compilation:  g++ -o test_app test_app.cpp                                        */
/* running usage:  ./test_app                                                        */
/* ################################################################################# */
#include <cstdlib>
#include <iostream>
#include <string>

using std::cout;
using std::endl;
using std::string;

#define uint32_t unsigned

void myExit(const string& msg)
{
	cout << msg << endl;
	exit(1);
}

void foo()
{
	uint32_t* array = (uint32_t*) malloc(sizeof(uint32_t) * 1024); // allocate 4KB
	uint32_t* array2 = (uint32_t*) malloc(sizeof(uint32_t) * 1024); // allocate 4KB
	if (!array)
		myExit("Cannot allocate memory, malloc returned NULL");

	for (int i = 0; i < 100; ++i)
	{
		array[i+925] = 8; // Write Error
	}

	int a = array[1024]; // Read Error
	*(array2 + 1024) = 1; // Write Error
	free(array);
	free(array2);
	//cout << "Done" << endl;
}


int main(int argc, char* argv[])
{

	for (;;) {
		foo();
	}

	return 0;
}

