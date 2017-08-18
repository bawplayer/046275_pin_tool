#ifndef GRANDFATHER_H
#define GRANDFATHER_H
#include "pin.H"
#include <cstdlib>
#include <unordered_map>
#include "AllocData.h"

using std::unordered_map;

class Tracer {
	
	private:
	
	ADDRINT maxAddr;
	ADDRINT minAddr; 
	unordered_map<ADDRINT, AllocData> allocAddressMap;
	// C'tor
	Tracer();
	
	public:

	static Tracer& GetInstance();
	bool IsAllocatedAddress(ADDRINT addr);
	void AddNewAddress(const ADDRINT addr, const size_t size);
	void DeleteAddress(const ADDRINT addr);
	ADDRINT GetStartAddress(const ADDRINT addr);
	AllocData& operator[](ADDRINT addr);
	uint32_t Size();
	void Print();
};

#endif /* H_TRACER_ */
