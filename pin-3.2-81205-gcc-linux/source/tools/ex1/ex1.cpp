/**
ex1.cpp
Written by: B

*/


#include <fstream>
//#include <iomanip>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include "pin.H"

class RoutineClass {
private:
	//RTN _rtn;
	unsigned _icount = 0;
	int _id;
	string _name;
public:
	RoutineClass(int id = 0, const string& name = ""): _id(id), _name(name) {}
	RoutineClass(const RTN& rtn): _id(RTN_Id(rtn)), _name(RTN_Name(rtn)) {}
	
	explicit operator int() const {
		return this->_id;
	}

	string getName() const {
		return this->_name;
	}

	unsigned getInstructionCount() const {
		return _icount;
	}
	unsigned incInstructionCount(int inc=1) {
		_icount += inc;
		return this->getInstructionCount();
	}

	friend std::ostream& operator<<(std::ostream&, const RoutineClass&);
	friend bool operator<(const RoutineClass&, const RoutineClass&);
	friend bool operator==(const RoutineClass&, const RoutineClass&);
};

std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
	return out << self.getName() << " icount: " << self.getInstructionCount();
}

bool operator<(const RoutineClass& a, const RoutineClass& b) {
	return (a.getInstructionCount() < b.getInstructionCount()) \
		|| ((a.getInstructionCount() == b.getInstructionCount()) \
		&& (a.getName() < b.getName()));
}

bool operator==(const RoutineClass& a, const RoutineClass& b) {
	return a.getInstructionCount() == b.getInstructionCount();
}

bool compareIsGreaterThan(const RoutineClass& a, const RoutineClass& b) {
	return !((a<b) || (a==b));
}


std::unordered_map<int, RoutineClass> routinesDict;

void incrementICounter(unsigned i) {
	routinesDict[i].incInstructionCount();
}


VOID Trace(TRACE trace, VOID *v);
VOID Fini(int, VOID * v);
std::ostream& printRoutineInstructionCount(std::ostream&);

/* ===================================================================== */
/* Implementations                                                       */
/* ===================================================================== */


VOID Fini(int, VOID * v) {
	std::ofstream out("rtn-output.txt");
	printRoutineInstructionCount(out);
}

std::ostream& printRoutineInstructionCount(std::ostream& os)  {
	// Insert routines into a vector, do clean-up, sort, and finally, print
	
	std::vector<RoutineClass> routinesVec;
	for (auto&& r : routinesDict) {
		auto& rot = r.second;
		// ignore zero-ed routines
		if (rot.getInstructionCount() == 0) {
			continue;
		}

		// merge name-duplicates
		bool dup_found = 0;
		for (auto&& vr : routinesVec) {
			if (rot.getName() == vr.getName()) {
				vr.incInstructionCount(rot.getInstructionCount());
				dup_found = 1;
			}
		}
		if (dup_found) {
			continue;
		}

		routinesVec.push_back(rot);
	}

	std::sort(routinesVec.begin(), routinesVec.end(), compareIsGreaterThan);
	//print routines
	for (auto&& r : routinesVec) {
		os << r << std::endl;
	}

	return os;
}

VOID Routine(RTN rtn, VOID *v) {
	RTN_Open(rtn);
	RoutineClass routine(rtn);
	routinesDict[int(routine)] = routine;

	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
	    // Increment routine's counter on every executed instruction
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)incrementICounter, IARG_UINT32, int(routine), IARG_END);
	}
	RTN_Close(rtn);
}




/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) {
    	return Usage();
    }

    //TRACE_AddInstrumentFunction(Trace, 0);
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}