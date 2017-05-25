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
const std::string profileFilename = "_profile.map";
const std::string edgeString = "\t\tEdge%d: BB%d -> BB%d %u\n";
const std::string edgeProfString = "e\t\tEdge%d: (%llu, %llu, %llu) %u\n";
const std::string bblString = "\tBB%d: 0x%llx - 0x%llx\n";
const std::string bblProfString = "b\tBB%d: 0x%llx - 0x%llx\n";
const std::string routineProfString = "r%d %s at: 0x%llx\ticount: %u\trcount: %u\n";
std::ofstream mylog;

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
    int _rtn_id ;
    unsigned _icount;
public:
    ADDRINT _src, _dst;
    ADDRINT _next_ins;
    //ETYPE   _type; // must be integer to make stl happy
        
    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, const RTN& rtn) :
        _rtn_id(0), _icount(0), _src(s),_dst(d), _next_ins(n) {
        _rtn_id = RTN_Id(rtn);
    }

    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, unsigned icount,
        int rtn_id):
        _rtn_id(rtn_id), _icount(icount), _src(s),_dst(d), _next_ins(n) {}

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

    EDGEClass& operator+=(const EDGEClass& left) {
        this->incInstructionCount(left.getInstructionCount());
        return *this;
    }

    EDGEClass operator++() {
        EDGEClass res(*this);
        this->incInstructionCount();
        return res;
    }

    EDGEClass& operator++(int) {
        this->incInstructionCount();
        return *this;
    }

    friend bool operator==(const EDGEClass& ea, const EDGEClass& eb) {
        return (ea.getRoutineId() == eb.getRoutineId()) && \
            (ea._src == eb._src) && (ea._dst == eb._dst) && \
            (ea._next_ins == eb._next_ins);
    }

    bool operator<(const EDGEClass& edge) const {
        return (this->_src < edge._src) || \
            ((this->_src == edge._src) && (this->_dst < edge._dst));
    }
}; // END of EDGEClass

bool compareEdgeCounterIsGreaterThan(const EDGEClass& a, const EDGEClass& b) {
    return (a.getInstructionCount() > b.getInstructionCount()) || \
        ((a.getInstructionCount() == b.getInstructionCount()) && (b<a));
}

class BBLClass {
private:
    int _rtn_id;

    bool _validateSourceAndDestination() {
        if (_src > _dst) {
            std::swap(_src, _dst);
        }
        return true;
    }
public:
    ADDRINT _src, _dst;
    //int _index = 0;

    BBLClass(ADDRINT src, ADDRINT dst, const RTN& rtn): 
        _rtn_id(0), _src(src), _dst(dst) {
        //_rtn_name = string(RTN_Name(rtn));
        this->_rtn_id = RTN_Id(rtn);
        _validateSourceAndDestination();
    }

    BBLClass(ADDRINT src, ADDRINT dst, int rtn_id): _rtn_id(rtn_id),
        _src(src), _dst(dst) {}

    int getRoutineId() const {
        return this->_rtn_id;
    }

    bool isInstructionIn(ADDRINT addr) const {
        return (addr >= this->_src) && (addr <= this->_dst);
    }

    ADDRINT extendStartAddress(ADDRINT addr) {
        if (addr < this->_src) {
            this->_src = addr;
        }
        return this->_src;
    }

    /**
        Essantially, BBLs are differentiated by their start address.
    */
    friend bool operator<(const BBLClass& a, const BBLClass& b) {
        return (a._dst < b._dst);
    }

    friend bool operator==(const BBLClass& ba, const BBLClass& bb) {
        return (ba._rtn_id == bb._rtn_id) && \
            !((ba < bb) || (bb < ba));
    }
}; // end of BBLClass

class RoutineClass {
private:
    int _id;
    string _name;
    ADDRINT _address;
    unsigned _icount;
    unsigned _rcount;

    int _findBBLIndex(ADDRINT addr) const {
        int i = 0;
        // for (auto&& bbl : this->bbls) {
        for (std::vector<BBLClass>::const_iterator it = this->bbls.begin();
            it != this->bbls.end(); ++it) {
            const BBLClass& bbl = *it;
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

    RoutineClass(int id = 0, const string& name = "", ADDRINT addr = 0, \
        unsigned icount = 0, unsigned rcount = 0): \
        _id(id), _name(name), _address(addr), _icount(icount), \
        _rcount(rcount) {}
    RoutineClass(const RTN& rtn):
        _id(RTN_Id(rtn)), _name(RTN_Name(rtn)), _address(RTN_Address(rtn)),
        _icount(0), _rcount(0) {}
    
    string getName() const {
        return this->_name;
    }

    ADDRINT getAddress() const {
        return this->_address;
    }

    int getId() const {
        return this->_id;
    }

/*  
    explicit operator int() const {
        this->getId();
    }
*/

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

    friend bool operator==(const RoutineClass& a, const RoutineClass& b) {
        return a.getId() == b.getId();
    }

    RoutineClass& operator+=(const RoutineClass& rc) {
        if (!(*this == rc)) {
            // not the same routine
            return *this;
        }

        RoutineClass tmp_rtn_obj(*this); // clone self

        // add counters
        tmp_rtn_obj.incInstructionCount(rc._icount);
        tmp_rtn_obj.incRoutineCount(rc._rcount);

        // append missing bbls
        //for (const BBLClass& bbl : rc.bbls) {
        for (std::vector<BBLClass>::const_iterator it = rc.bbls.begin();
            it != rc.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            if (std::find(tmp_rtn_obj.bbls.begin(), tmp_rtn_obj.bbls.end(),
                bbl) == tmp_rtn_obj.bbls.end()) {
                tmp_rtn_obj.bbls.push_back(bbl);
            }
        }

        // merge edges
        for (std::vector<EDGEClass>::const_iterator it = rc.edges.begin();
            it != rc.edges.end(); ++it) {
            const EDGEClass& edge_right = *it;
            std::vector<EDGEClass>::iterator fit = std::find(
                tmp_rtn_obj.edges.begin(), tmp_rtn_obj.edges.end(),
                edge_right);
            if (fit == tmp_rtn_obj.edges.end()) {
                tmp_rtn_obj.edges.push_back(edge_right);
            } else {
                *fit += edge_right;
            }
        }

        *this = tmp_rtn_obj;
        return *this;
    }

    friend std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
        const size_t array_len = 100;
        char char_array[array_len+1];
        char_array[array_len] = '\0';

        // Set buffer with routine data
        snprintf(char_array, array_len, "%s at: 0x%llx icount: %u\n",
            self.getName().c_str(), static_cast<unsigned long long>(self._address),
            self.getInstructionCount());
        out << std::string(char_array);


        int i = 1;
        for (std::vector<BBLClass>::const_iterator it = self.bbls.begin();
            it != self.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            snprintf(char_array, array_len, bblString.c_str(), i,
                static_cast<unsigned long long>(bbl._src),
                static_cast<unsigned long long>(bbl._dst));
            out << std::string(char_array);
            ++i;
        }

        i = 1;
        for (std::vector<EDGEClass>::const_iterator it = self.edges.begin();
            it != self.edges.end(); ++it) {
            const EDGEClass& edge = *it;
            // Set buffer with edge data
            int bbl1 = self._findBBLIndex(edge._src), bbl2 = self._findBBLIndex(edge._dst);
            if ((bbl1 == (-1)) || (bbl2 == (-1))) {
                // ignore edges that were not in the trace, or exiting the routine
                continue;
            }

            snprintf(char_array, array_len, edgeString.c_str(),
                i++, bbl1, bbl2, edge.getInstructionCount());
            out << std::string(char_array);
        }

        return out;
    }

    std::ofstream& printProfile(std::ofstream& profileFile) const {
        RoutineClass const& self = *this;
        const size_t array_len = 100;
        char char_array[array_len+1];
        char_array[array_len] = '\0';

        // Set buffer with routine data
        snprintf(char_array, array_len, routineProfString.c_str(),
            self.getId(), self.getName().c_str(),
            static_cast<unsigned long long>(self._address),
            self.getInstructionCount(), self.getRoutineCount());
        profileFile << std::string(char_array);

        int i = 1;
        for (std::vector<BBLClass>::const_iterator it = self.bbls.begin();
            it != self.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            snprintf(char_array, array_len, bblProfString.c_str(), i++,
                static_cast<unsigned long long>(bbl._src),
                static_cast<unsigned long long>(bbl._dst));
            profileFile << std::string(char_array);
        }

        i = 1;
        for (std::vector<EDGEClass>::const_iterator it = self.edges.begin();
            it != self.edges.end(); ++it) {
            const EDGEClass& edge = *it;
            // Set buffer with edge data
            snprintf(char_array, array_len, edgeProfString.c_str(),
                i++, edge._src, edge._dst, edge._next_ins,
                edge.getInstructionCount());
            profileFile << std::string(char_array);
        }

        return profileFile;
    }
}; // END of RoutineClass

bool compareRoutineIsGreaterThan(const RoutineClass& a, const RoutineClass& b) {
    return !(((a.getInstructionCount() < b.getInstructionCount()) \
        || ((a.getInstructionCount() == b.getInstructionCount()) \
            && (a.getId() < b.getId()))) \
        || (a.getInstructionCount() == b.getInstructionCount()));
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

bool edgeWithZeroCalls(const EDGEClass& edge) {
    return edge.getInstructionCount() == 0;
}

void parseProfileMapIfFound() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return;
    }

    std::string strBuffer;

    const std::string bblPrefix = "\tBB";
    const std::string edgePrefix = "\t\tEdge";

    RoutineClass currentRoutine(0);
    while (std::getline(inFile, strBuffer)) {
        const char firstChar = strBuffer[0];

        if (firstChar == '#') {
            // ignore comments
            continue;
        } else if (firstChar == 'e') {
            // parse edge refernced the most recent routine
            unsigned long long src_ins, dst_ins, next_ins;
            int num;
            unsigned icount;
            sscanf(strBuffer.c_str(), edgeProfString.c_str(), &num,
                &src_ins, &dst_ins, &next_ins, &icount);
            currentRoutine.edges.push_back(EDGEClass(src_ins, dst_ins,
                next_ins, icount, currentRoutine.getId()));
        } else if (firstChar == 'b') {
            // parse bbl referenced the most recent routine
            unsigned long long start, end;
            int num;
            sscanf(strBuffer.c_str(), bblProfString.c_str(), &num, &start, &end);
            currentRoutine.bbls.push_back(BBLClass(start, end, currentRoutine.getId()));
        } else if (firstChar == 'r') {
            // parse routine
            // merge previous routine to routinesDict
            if (currentRoutine.getId() != 0) {
                if (routinesDict.find(currentRoutine.getId()) == routinesDict.end()) {
                    routinesDict[currentRoutine.getId()] = currentRoutine;
                } else {
/*#ifndef NDEBUG
                    if (true) {
                        mylog << currentRoutine.getId() << " ";
                        mylog << currentRoutine.getName() << endl;
                        mylog << "Routine's current run instruction count:\t" <<
                            routinesDict[currentRoutine.getId()].getInstructionCount()
                            << endl;
                        mylog << "Routine's previous runs instruction count:\t" <<
                            currentRoutine.getInstructionCount() << endl;
                        routinesDict[currentRoutine.getId()] += currentRoutine;
                        mylog << "Instruction count merged: " <<
                            routinesDict[currentRoutine.getId()].getInstructionCount()
                            << endl;
                    } else {
#endif*/
                  routinesDict[currentRoutine.getId()] += currentRoutine;
/*#ifndef NDEBUG
                    }
#endif*/
                }
            }

            char rtn_name[101];
            unsigned long long rtn_addr = 0;
            unsigned rtn_icnt = 0, rtn_rcnt = 0;
            int rtn_id;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt);
            currentRoutine = RoutineClass(rtn_id, std::string(rtn_name), rtn_addr,
                rtn_icnt, rtn_rcnt);
        } else {
            std::cerr << "Could not compile line: " << strBuffer << endl;
        }
    } // end of while loop

    // merge last routine to routinesDict
    if (currentRoutine.getId() != 0) {
        if (routinesDict.find(currentRoutine.getId()) == routinesDict.end()) {
            routinesDict[currentRoutine.getId()] = currentRoutine;
        } else {
            routinesDict[currentRoutine.getId()] += currentRoutine;
        }
    }

    inFile.close();
}


/**
    Note: PIN_DEPRECATED_API BBL LEVEL_PINCLIENT::RTN_BblHead (   RTN     x    )
    Here we will register each BBL sequence only once.
*/
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);
        ADDRINT end_addr = addr + BBL_Size(bbl);

        std::pair<std::set<BBLClass>::iterator, bool> pairset = bblsSet.insert(BBLClass(addr, end_addr, RTN_FindByAddress(addr)));
        if (pairset.second == false) {
            continue;
        } 
/*
        TODO
        // otherwise, there's a duplicate.
        // Assuming a BBL may have multiple entries, we will merge them now.
        if (addr < pairset.first->_src) {
            // set the 1st BBL's start address to the minimal address of the two
            pairset.first->extendStartAddress(addr);
        }*/
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
    RTN_InsertCall(rtn, IPOINT_BEFORE, \
        (AFUNPTR)incrementRoutineRCounter, IARG_UINT32, routine_id, IARG_END);
    
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)incrementRoutineICounter,\
            IARG_UINT32, routine_id, IARG_END);

        // count the edges ((indirect)
        if (INS_IsDirectBranchOrCall(ins)) {
            //ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH;
    
            int edge_index = routinesDict[routine_id].edges.size();
            routinesDict[routine_id].edges.push_back(\
                EDGEClass(
                    INS_Address(ins),
                    INS_DirectBranchOrCallTargetAddress(ins),
                    INS_NextAddress(ins), rtn));

            // insert a call to increment edge's counter, called iff the branch was taken
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                (AFUNPTR)incrementRoutineEdgeCounter, IARG_UINT32,
                routine_id, IARG_UINT32, edge_index, IARG_END);
        }
    }

    RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {
    // move BBL from global linked list to the vector in the relevant rtn
    //for (auto&& bbl : bblsSet) {
    for (std::set<BBLClass>::const_iterator it = bblsSet.begin();
        it != bblsSet.end(); ++it) {
        const BBLClass& bbl = *it;
        // TODO: merge inclusive bbls counters
        routinesDict[bbl.getRoutineId()].bbls.push_back(bbl);
    }

    parseProfileMapIfFound();


/********************
*****print to file***
********************/
    std::vector<RoutineClass> routinesVector;

    // copy from dictionary to routines vector all routines that have been called
    //for (auto&& di: routinesDict) {
    for (std::map<int, RoutineClass>::iterator it = routinesDict.begin();
        it != routinesDict.end(); ++it) {
        RoutineClass& rc = it->second;

        // ignore silent routines
        if (rc.getInstructionCount() == 0) {
            continue;
        }

        // clean silent edges
        rc.edges.erase(std::remove_if(rc.edges.begin(), rc.edges.end(), 
            edgeWithZeroCalls), rc.edges.end());
        // sort edges
        std::sort(rc.edges.begin(), rc.edges.end(), compareEdgeCounterIsGreaterThan);

        // append to vector
        routinesVector.push_back(rc);
    }

    // print the sorted output
    std::sort(routinesVector.begin(), routinesVector.end(), compareRoutineIsGreaterThan);

    std::ofstream outFile("rtn-output.txt"), profileFile(profileFilename.c_str());
    //for (auto&& rc : routinesVector) {
    for (std::vector<RoutineClass>::const_iterator it = routinesVector.begin();
        it != routinesVector.end(); ++it) {
        const RoutineClass& rc = *it;
        outFile << rc;
        rc.printProfile(profileFile);
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

int main(int argc, char * argv[]) {
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

/*#ifndef NDEBUG
    mylog.open("deb.log");
#endif
*/
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
