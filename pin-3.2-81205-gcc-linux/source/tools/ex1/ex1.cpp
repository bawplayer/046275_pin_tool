/**
ex1.cpp
Written by: B

*/


#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include "pin.H"

class RoutineClass {
private:
	//RTN _rtn;
	int _id;
	string _name;
	unsigned _icount;
public:
	RoutineClass(int id = 0, const string& name = ""): _id(id), _name(name),
		_icount(0) {}
	RoutineClass(const RTN& rtn): _id(RTN_Id(rtn)), _name(RTN_Name(rtn)),
		_icount(0) {}

    int getId() const {
        return this->_id;
    }

/*  
	explicit operator int() const {
        this->getId();
    }
*/
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

	friend std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
		return out << self.getName() << " icount: " << self.getInstructionCount();
	}

	friend bool operator==(const RoutineClass& a, const RoutineClass& b) {
		return a._id == b._id;
	}
}; // END of ROUTINECLASS

bool operator<(const RoutineClass& a, const RoutineClass& b) {
	return (a.getInstructionCount() < b.getInstructionCount()) \
		|| ((a.getInstructionCount() == b.getInstructionCount()) \
		&& (a.getId() < b.getId()));
}

bool compareIsGreaterThan(const RoutineClass& a, const RoutineClass& b) {
	return !(a<b); // || (a.getInstructionCount() == b.getInstructionCount()));
}

std::map<int, RoutineClass> routinesDict;

void incrementICounter(unsigned i) {
	routinesDict[i].incInstructionCount();
}


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
	//for (auto&& r : routinesDict) {
	for (std::map<int, RoutineClass>::const_iterator it = routinesDict.begin();
		it != routinesDict.end(); ++it) {
		const RoutineClass& rot = it->second;
		// ignore zero-ed routines
		if (rot.getInstructionCount() == 0) {
			continue;
		}

		// merge name-duplicates
		bool dup_found = false;
		//for (auto&& vr : routinesVec) {
		for (std::vector<RoutineClass>::iterator it = routinesVec.begin();
			it != routinesVec.end(); ++it) {
			RoutineClass& vr = *it;
			if (rot.getName() == vr.getName()) {
				vr.incInstructionCount(rot.getInstructionCount());
				dup_found = true;
			}
		}

		if (!dup_found) {
			routinesVec.push_back(rot);
		}
	}

	std::sort(routinesVec.begin(), routinesVec.end(), compareIsGreaterThan);
	//print routines
	for (std::vector<RoutineClass>::iterator it = routinesVec.begin();
			it != routinesVec.end(); ++it) {
		os << *it << std::endl;
	}

	return os;
}

VOID Routine(RTN rtn, VOID *v) {
	RTN_Open(rtn);
	RoutineClass routine(rtn);
	int routine_id = routine.getId();
	routinesDict[routine_id] = routine;

	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
	    // Increment routine's counter on every executed instruction
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)incrementICounter, IARG_UINT32, routine_id, IARG_END);
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