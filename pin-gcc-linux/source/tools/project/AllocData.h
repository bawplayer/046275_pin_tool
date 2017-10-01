#ifndef ALLOCDATA_H
#define ALLOCDATA_H
#include "pin.H"

class AllocData {
	
	public:
	AllocData();
	AllocData(const ADDRINT startAddr, const size_t allocSize);
	ADDRINT StartAddress();
	size_t Size();
	
	private:
	ADDRINT _startAddr;
	size_t _allocSize;
	
};

#endif /* ALLOCDATA_H */
