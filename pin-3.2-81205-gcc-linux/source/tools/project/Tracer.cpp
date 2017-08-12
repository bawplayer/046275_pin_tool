#include "pin.H"
#include <algorithm>
#include <iostream>
#include "Tracer.h"
#include "AllocData.h"

#define MAX_64BITADDR 0xffffffffffffffff

Tracer::Tracer() : 
maxAddr(0), minAddr(MAX_64BITADDR), allocAddressMap()
{
}

Tracer& Tracer::GetInstance()
{
	static Tracer tracer = Tracer();
	return tracer;
}

bool Tracer::IsAllocatedAddress(ADDRINT addr)
{
	unordered_map<ADDRINT, AllocData>::iterator it = allocAddressMap.begin();
	
	while(allocAddressMap.end() != it)
	{
		
		ADDRINT allocStartAddr = it->second.StartAddress();
		ADDRINT allocSize = it->second.Size();
		
		if (addr >= allocStartAddr && addr < allocSize + allocStartAddr)
		{
			return true;
		}
		
		++it;
	}
	
	return false;
}

ADDRINT Tracer::GetStartAddress(ADDRINT addr)
{
	unordered_map<ADDRINT, AllocData>::iterator it = allocAddressMap.begin();
	
	while(allocAddressMap.end() != it)
	{
		
		ADDRINT allocStartAddr = it->second.StartAddress();
		ADDRINT allocSize = it->second.Size();
		
		if (addr >= allocStartAddr && addr < allocSize + allocStartAddr)
		{
			return allocStartAddr;
		}
		
		++it;
	}
	
	return 0;
}

void Tracer::AddNewAddress(const ADDRINT addr, const size_t size)
{
	AllocData allocData(addr, size);
	allocAddressMap[addr] = allocData;
}

void Tracer::DeleteAddress(const ADDRINT addr)
{
	allocAddressMap.erase(addr);
}

uint32_t Tracer::Size()
{
	return allocAddressMap.size();
}

AllocData& Tracer::operator[](ADDRINT addr)
{
	return allocAddressMap[addr];
}

void Tracer::Print()
{
	if (!Size())
		return;
	
	std::cout << "Tracer content: " << std::endl;
	for (auto& it : allocAddressMap)
	{
		std::cout << "Start address: " << it.second.StartAddress() << " Size: " << it.second.Size() << endl;
	}
}
