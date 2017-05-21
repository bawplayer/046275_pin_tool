//Oren Kaikov, 037832292
/*This tool counts the number of times a routine is executed and the number of instructions executed in a routine.
this is based on the original proccount sample provided by pin tool.
I modified proccount by sorting the output and aggragating the instruction count of all the functions with the same name.
we still use proccount original linked list data structure to contain all the routins information, since the assumption that there are less then 1K rtns is valid for rtns that run more then 1 instructions.
since there are rtns with the same name but with diffrent image, they are counted seperatly.
the desired output doesn't distinguish between images, so I aggragated all the instruction count of all the rtns with the same name (even though they have a diffrent image.) 
also removed redundent code.
*/
#include <vector>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <string>
#include <set>
#include "pin.H"

using namespace std;
ofstream outFile;

/*
typedef enum {
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
}ETYPE;

string StringFromEtype( ETYPE etype)
{
    switch(etype)
    {
      case ETYPE_CALL:
        return "C";
      case ETYPE_ICALL:
        return "c";
      case ETYPE_BRANCH:
        return "B";
      case ETYPE_IBRANCH:
        return "b";
      case ETYPE_RETURN:
        return "r";
      case ETYPE_SYSCALL:
        return "s";
      default:
        ASSERTX(0);
        return "INVALID";
    }
}
*/

class EDGEClass {
private:
    int _rtn_id = 0;
    unsigned _icount = 0;
public:
    ADDRINT _src, _dst;
    ADDRINT _next_ins;
    //ETYPE   _type; // must be integer to make stl happy
        
    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, const RTN& rtn) :
        _src(s),_dst(d), _next_ins(n) {
            _rtn_id = RTN_Id(rtn);
        }

    unsigned getInstructionCount() const {
        return this->_icount;
    }

    unsigned incInstructionCount(int inc=1) {
        this->_icount += inc;
        return this->getInstructionCount();
    }

    int getRoutineId() const {
        return this->_rtn_id;
    }

    bool operator<(const EDGEClass& edge) const {
        return (this->_src < edge._src) || \
            ((this->_src == edge._src) && (this->_dst < edge._dst));
    }
}; // END of EDGEClass

class BBLClass {
private:
    int _rtn_id = 0;

    bool _validateSourceAndDestination() {
        if (_src > _dst) {
            std::swap(_src, _dst);
        }
        return true;
    }
public:
    ADDRINT _src = 0, _dst = 0;
    int _index = 0;
/*
    BBLClass(ADDRINT src, ADDRINT dst, const RoutineClass& rc): _src(src), _dst(dst) {
        _rtn_name = rc.getName();
        _rtn_id = rc.getId();
        _validateSourceAndDestination();
    }
*/
    BBLClass(ADDRINT src, ADDRINT dst, const RTN& rtn): _src(src), _dst(dst) {
        //_rtn_name = string(RTN_Name(rtn));
        _rtn_id = RTN_Id(rtn);
        _validateSourceAndDestination();
    }

    int getRoutineId() const {
        return this->_rtn_id;
    }

    bool isInstructionIn(ADDRINT addr) const {
        return (addr >= this->_src) && (addr <= this->_dst);
    }

    friend std::ostream& operator<<(std::ostream& out, const BBLClass& self) {
        out << "\tBB" << self._index << ": 0x" << hex << self._src << " - 0x" << self._dst;
        return out << dec << std::endl;
    }

    friend bool operator==(const BBLClass& a, const BBLClass& b) {
        return (a._src == b._src) && (a._dst == b._dst);
    }

    friend bool operator<(const BBLClass& a, const BBLClass& b) {
        return (a._src < b._src);
    }
}; // end of BBLClass

bool operator!=(const BBLClass& a, const BBLClass& b) {
    return !(a == b);
}

class RoutineClass {
private:
    unsigned _icount = 0, _rcount = 0;
    int _id;
    string _name;
    ADDRINT _address;

    int findBBLIndex(ADDRINT addr) const {
        int i = 0;
        for (auto&& bbl : this->bbls) {
            ++i;
            if (bbl.isInstructionIn(addr)) {
                return i;
            }
        }

        return -1;
    }

public:
    std::vector<EDGEClass> edges;
    std::vector<BBLClass> bbls;

    RoutineClass(int id = 0, const string& name = "", ADDRINT addr = 0): 
        _id(id), _name(name), _address(addr) {}
    RoutineClass(const RTN& rtn):
        _id(RTN_Id(rtn)), _name(RTN_Name(rtn)), _address(RTN_Address(rtn)) {}
    
    string getName() const {
        return this->_name;
    }

    ADDRINT getAddress() const {
        return this->_address;
    }

    int getId() const {
        return this->_id;
    }

/*    explicit operator int() const {
        this->getId();
    }*/

    unsigned getInstructionCount() const {
        return this->_icount;
    }
    unsigned incInstructionCount(int inc=1) {
        _icount += inc;
        return this->getInstructionCount();
    }

    unsigned getRoutineCount() const {
        return this->_rcount;
    }

    unsigned incRoutineCount(int inc=1) {
        _rcount += inc;
        return this->getRoutineCount();
    }
/*
    void printToProfileFile(const std::string& fname = "_profile.map") const {
        out << this->getName() << " at: 0x" << hex << this->_address;
        out << dec << " icount: " << this->getInstructionCount() << std::endl;

        int i = 1;
        const size_t array_len = 100;
        char char_array[array_len];
        for (auto&& bbl : this->bbls) {
            snprintf(char_array, array_len, "\tBB%d: 0x%llx - 0x%llx\n", i,
                static_cast<unsigned long long>(bbl._src), static_cast<unsigned long long>(bbl._dst));
            out << std::string(char_array);
            ++i;
        }

        i = 1;
        for (auto&& edge : this->edges) {
            int bbl1 = this->findBBLIndex(edge._src), bbl2 = this->findBBLIndex(edge._dst);
#ifdef NDEBUG
            if ((bbl1 == (-1)) || (bbl2 == (-1))) {
                // ignore edges that were not in the trace, or leaving the routine
                continue;
            }
#endif
            //std::cout << bbl1 << " " << bbl2 << endl;
            out << "\t\tEdge" << i << ": BB" << bbl1;
            out << " -> BB";
            out << bbl2 << " ";
            out << decstr(edge.getInstructionCount()) << std::endl;
            ++i;
        }
    }
*/
    friend std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
        out << self.getName() << " at: 0x" << hex << self._address;
        out << dec << " icount: " << self.getInstructionCount() << std::endl;

        int i = 1;
        const size_t array_len = 100;
        char char_array[array_len];
        for (auto&& bbl : self.bbls) {
            snprintf(char_array, array_len, "\tBB%d: 0x%llx - 0x%llx\n", i,
                static_cast<unsigned long long>(bbl._src), static_cast<unsigned long long>(bbl._dst));
            out << std::string(char_array);
            ++i;
        }

        i = 1;
        for (auto&& edge : self.edges) {
            int bbl1 = self.findBBLIndex(edge._src), bbl2 = self.findBBLIndex(edge._dst);
#ifdef NDEBUG
            if ((bbl1 == (-1)) || (bbl2 == (-1))) {
                // ignore edges that were not in the trace, or leaving the routine
                continue;
            }
#endif
            //std::cout << bbl1 << " " << bbl2 << endl;
            out << "\t\tEdge" << i << ": BB" << bbl1;
            out << " -> BB";
            out << bbl2 << " ";
            out << decstr(edge.getInstructionCount()) << std::endl;
            ++i;
        }

        return out;
    }

    friend bool operator==(const RoutineClass& a, const RoutineClass& b) {
        return a._id == b._id;
    }
}; // END of RoutineClass

bool operator<(const RoutineClass& a, const RoutineClass& b) {
    return (a.getInstructionCount() < b.getInstructionCount()) \
        || ((a.getInstructionCount() == b.getInstructionCount()) \
        && (0 < a.getName().compare(b.getName())));
}

bool compareIsGreaterThan(const RoutineClass& a, const RoutineClass& b) {
    return !((a<b) || (a.getInstructionCount() == b.getInstructionCount()));
}

std::map<int, RoutineClass> routinesDict;
std::set<BBLClass> bblsSet;

void incrementRoutineICounter(int i) {
    routinesDict[i].incInstructionCount();
}
void incrementRoutineRCounter(int i) {
    routinesDict[i].incRoutineCount();
}

void incrementRoutineEdgeCounter(int i, int j) {
    routinesDict[i].edges[j].incInstructionCount();
}


// This function is called before every instruction is executed
/*VOID docount(UINT64 * counter)
{
    (*counter)++;
}

const char * StripPath(const char * path)
{
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
}

*/
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);
        // Since bblsSet is a set, the item is inserted iff bbl start address differs
        bblsSet.insert(BBLClass(addr, addr + BBL_Size(bbl), RTN_FindByAddress(addr)));
     }
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v) {
    RoutineClass rc(rtn);
    int routine_id = rc.getId();
    // check if key (routine id) already exist in dictionary
    if (routinesDict.count(routine_id) < 1) {
        routinesDict[routine_id] = rc;
    } else {
        return;
    }

    RTN_Open(rtn);
            
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)incrementRoutineRCounter, IARG_UINT32, routine_id, IARG_END);
    
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)incrementRoutineICounter, IARG_UINT32, routine_id, IARG_END);

        // count the edges ((indirect)
        if (INS_IsDirectBranchOrCall(ins)) {
            //ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH;
    
            int edge_index = routinesDict[routine_id].edges.size();
            routinesDict[routine_id].edges.push_back(EDGEClass(INS_Address(ins), INS_DirectBranchOrCallTargetAddress(ins), INS_NextAddress(ins), rtn));

            // insert a call to increment edge's counter, called iff the branch was taken
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)incrementRoutineEdgeCounter, IARG_UINT32, routine_id, IARG_UINT32, edge_index, IARG_END);
        }
    }

    RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {
    // move BBL from global linked list to the vector in the relevant rtn
    for (auto&& bbl : bblsSet) {
        // TODO: merge inclusive bbls counters
        routinesDict[bbl.getRoutineId()].bbls.push_back(bbl);
    }

    
    //TODO: Initialize routines vector from profile.map
    //parseProfileMapIfFound();


/********************
*****print to file***
********************/
    std::vector<RoutineClass> routinesVector;

    // copy from dictionary to routines vector all routines that have been called
    for (auto&& di: routinesDict) {
        RoutineClass& rc = di.second;

        // ignore silent routines
        if (rc.getRoutineCount() == 0) {
            continue;
        }

        // clean silent edges
        rc.edges.erase(std::remove_if(rc.edges.begin(), rc.edges.end(), 
            [](const EDGEClass& edge){return edge.getInstructionCount() == 0;}),
            rc.edges.end());

        // append to vector
        routinesVector.push_back(rc);
    }

    // print the sorted output
    std::sort(routinesVector.begin(), routinesVector.end(), compareIsGreaterThan);
    for (auto&& rc : routinesVector) {
        outFile << rc;
    }
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

    outFile.open("rtn-output.txt");
    
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);
    
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
