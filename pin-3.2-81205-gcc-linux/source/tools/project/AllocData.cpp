#include "pin.H"
#include <iostream>
#include "AllocData.h"

AllocData::AllocData(const ADDRINT startAddr, const size_t allocSize):
_startAddr(startAddr), _allocSize(allocSize)
{

}

AllocData::AllocData():
_startAddr(0x0), _allocSize(0)
{
}

ADDRINT AllocData::StartAddress()
{
	return _startAddr;
}

size_t AllocData::Size()
{
	return _allocSize;
}
