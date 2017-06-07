//O
//B

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
const std::string routineProfString = "r%d %s at: 0x%llx\ticount: %u\trcount: %u\tImage address: %llx\n";
std::ofstream mylog;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<BOOL>   KnobRunEx2(KNOB_MODE_WRITEONCE,   "pintool",
    "prof", "0", "print out edge profiling into the file output");
KNOB<BOOL>   KnobOptimizeHottestTen(KNOB_MODE_WRITEONCE,   "pintool",
    "inst", "0", "should run in probe mode and generate the binary code of the top 10 routines according to the gathered profiling data");
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");
KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");
KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");


class EDGEClass {
private:
    int _rtn_id ;
    unsigned _icount;
public:
    bool _exitRoutine;
    ADDRINT _src_offset, _dst_offset;
    ADDRINT _next_ins_offset;
        
    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, const RTN& rtn) :
        _rtn_id(0), _icount(0), _exitRoutine(false), _src_offset(s),
        _dst_offset(d), _next_ins_offset(n) {
        _rtn_id = RTN_Id(rtn);
    }

    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, unsigned icount,
        int rtn_id):
        _rtn_id(rtn_id), _icount(icount), _exitRoutine(false),
        _src_offset(s),_dst_offset(d), _next_ins_offset(n) {}

    unsigned getInstructionCount() const {
        return this->_icount;
    }

    unsigned incInstructionCount(int inc) {
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
        this->incInstructionCount(1);
        return res;
    }

    EDGEClass& operator++(int) {
        this->incInstructionCount(1);
        return *this;
    }

    friend bool operator==(const EDGEClass& ea, const EDGEClass& eb) {
        return (ea.getRoutineId() == eb.getRoutineId()) && \
            (ea._src_offset == eb._src_offset) && (ea._dst_offset == eb._dst_offset) && \
            (ea._next_ins_offset == eb._next_ins_offset);
    }

    bool operator<(const EDGEClass& edge) const {
        return (this->_src_offset < edge._src_offset) || \
            ((this->_src_offset == edge._src_offset) && (this->_dst_offset < edge._dst_offset));
    }
}; // END of EDGEClass

bool compareEdgeCounterIsGreaterThan(const EDGEClass& a, const EDGEClass& b) {
    return (a.getInstructionCount() > b.getInstructionCount()) || \
        ((a.getInstructionCount() == b.getInstructionCount()) && (b<a));
}

bool isEdgeExitsThisRoutine(const EDGEClass& edge) {
    return edge._exitRoutine;
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
    ADDRINT _src_offset, _dst_offset;

    BBLClass(ADDRINT src, ADDRINT dst, const RTN& rtn): 
        _rtn_id(0), _src(src), _dst(dst),
        _src_offset(0), _dst_offset(0) {
        this->_rtn_id = RTN_Id(rtn);
        _validateSourceAndDestination();
    }

    BBLClass(ADDRINT src, ADDRINT dst, int rtn_id): _rtn_id(rtn_id),
        _src(src), _dst(dst),
        _src_offset(0), _dst_offset(0) {}

    int getRoutineId() const {
        return this->_rtn_id;
    }

    std::pair<ADDRINT, ADDRINT> setOffset(ADDRINT image_addr) {
        this->_src_offset = this->_src - image_addr;
        this->_dst_offset = this->_dst - image_addr;
        return std::pair<ADDRINT, ADDRINT>(
            this->_src_offset, this->_dst_offset);
    }
/*
    bool isInstructionIn(ADDRINT addr) const {
        return (addr >= this->_src) && (addr <= this->_dst);
    }
*/
    bool isInstructionOffsetIn(ADDRINT off) const {
        return (off >= this->_src_offset) && (off <= this->_dst_offset);
    }

    ADDRINT extendStartAddress(ADDRINT addr) {
        if (addr < this->_src) {
            this->_src = addr;
        }
        return this->_src;
    }

    /*
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
    ADDRINT _imageAddress;

    int _findBBLIndex(ADDRINT off) const {
        int i = 0;
        for (std::vector<BBLClass>::const_iterator it = this->bbls.begin();
            it != this->bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            ++i;
            if (bbl.isInstructionOffsetIn(off)) {
                return i;
            }
        }

        return -1;
    }

public:
    std::vector<EDGEClass> edges;
    std::vector<BBLClass> bbls;

    RoutineClass(int id = 0, const string& name = "", ADDRINT addr = 0, \
        unsigned icount = 0, unsigned rcount = 0, ADDRINT imageAddress = 0): \
        _id(id), _name(name), _address(addr), _icount(icount), \
        _rcount(rcount), _imageAddress(imageAddress) {}
    RoutineClass(const RTN& rtn):
        _id(RTN_Id(rtn)), _name(RTN_Name(rtn)), _address(RTN_Address(rtn)),
        _icount(0), _rcount(0),
        _imageAddress(IMG_LowAddress(IMG_FindByAddress(_address))) {}
    
    string getName() const {
        return this->_name;
    }

    ADDRINT getAddress() const {
        return this->_address;
    }

    int getId() const {
        return this->_id;
    }

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

    ADDRINT getRoutineOffsetFromImage() const {
        return this->_address - this->_imageAddress;
    }

    ADDRINT getImageAddress() const {
        return this->_imageAddress;
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
        for (std::vector<BBLClass>::const_iterator bbl_i_iter = rc.bbls.begin();
            bbl_i_iter != rc.bbls.end(); ++bbl_i_iter) {
            bool is_found = false;
            for (std::vector<BBLClass>::const_iterator bbl_j_iter = tmp_rtn_obj.bbls.begin();
                bbl_j_iter != tmp_rtn_obj.bbls.end(); ++bbl_j_iter) {
                if (bbl_i_iter->_src == bbl_j_iter->_src_offset) {
                    is_found = true;
                    break;
                }
            }

            if (!is_found) {
                BBLClass tmp_bbl(*bbl_i_iter);
                tmp_bbl._src += this->getImageAddress();
                tmp_bbl._dst += this->getImageAddress();
                tmp_bbl.setOffset(this->getImageAddress());
                tmp_rtn_obj.bbls.push_back(tmp_bbl);
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

    void cleanEdgesThatExitRoutine() {
        for (std::vector<EDGEClass>::iterator it = this->edges.begin();
            it != this->edges.end(); ++it) {
            int bbl1 = this->_findBBLIndex(it->_src_offset);
            int bbl2 = this->_findBBLIndex(it->_dst_offset);
            it->_exitRoutine = ((bbl1 == (-1)) || (bbl2 == (-1)));
        }

        this->edges.erase(std::remove_if(this->edges.begin(), this->edges.end(), 
            isEdgeExitsThisRoutine), this->edges.end());
    }

    friend std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
        const size_t array_len = 100;
        char char_array[array_len+1];
        char_array[array_len] = '\0';

        // Set buffer with routine data
        snprintf(char_array, array_len, "%s at: 0x%llx icount: %u\n",
            self.getName().c_str(),
            static_cast<unsigned long long>(self.getAddress()),
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
            int bbl1 = self._findBBLIndex(edge._src_offset), bbl2 = self._findBBLIndex(edge._dst_offset);
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
            static_cast<unsigned long long>(self.getRoutineOffsetFromImage()),
            self.getInstructionCount(), self.getRoutineCount());
        profileFile << std::string(char_array);

        int i = 1;
        for (std::vector<BBLClass>::const_iterator it = self.bbls.begin();
            it != self.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            snprintf(char_array, array_len, bblProfString.c_str(), i++,
                static_cast<unsigned long long>(bbl._src_offset),
                static_cast<unsigned long long>(bbl._dst_offset));
            profileFile << std::string(char_array);
        }

        i = 1;
        for (std::vector<EDGEClass>::const_iterator it = self.edges.begin();
            it != self.edges.end(); ++it) {
            const EDGEClass& edge = *it;
            // Set buffer with edge data
            snprintf(char_array, array_len, edgeProfString.c_str(),
                i++, edge._src_offset, edge._dst_offset,
                edge._next_ins_offset,
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
std::vector<std::pair<int, bool> > routineCandidateIdsVector;

void incrementRoutineICounter(int i) {
    routinesDict[i].incInstructionCount();
}
void incrementRoutineRCounter(int i) {
    routinesDict[i].incRoutineCount();
}

void incrementRoutineEdgeCounter(int i, int j) {
    ++(routinesDict[i].edges[j]);
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
                  routinesDict[currentRoutine.getId()] += currentRoutine;
                }
            }

            char rtn_name[101];
            unsigned long long rtn_addr = 0, img_addr = 0;
            unsigned rtn_icnt = 0, rtn_rcnt = 0;
            int rtn_id;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt, &img_addr);
            currentRoutine = RoutineClass(rtn_id, std::string(rtn_name), rtn_addr,
                rtn_icnt, rtn_rcnt, img_addr);
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


VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);
        ADDRINT end_addr = addr + BBL_Size(bbl);

        std::pair<std::set<BBLClass>::iterator, bool> pairset = bblsSet.insert(BBLClass(addr, end_addr, RTN_FindByAddress(addr)));
        if (pairset.second == false) {
            continue;
        } 
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
            int edge_index = routinesDict[routine_id].edges.size();
            routinesDict[routine_id].edges.push_back(\
                EDGEClass(
                    INS_Address(ins) - rc.getImageAddress(),
                    INS_DirectBranchOrCallTargetAddress(ins) - rc.getImageAddress(),
                    INS_NextAddress(ins) - rc.getImageAddress(),
                    rtn)
                );

            // insert a call to increment edge's counter, called iff the branch was taken
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                (AFUNPTR)incrementRoutineEdgeCounter, IARG_UINT32,
                routine_id, IARG_UINT32, edge_index, IARG_END);
        }
    }

    RTN_Close(rtn);
}

/**
    The routine traverses through routineCandidateIdsVector's pairs.
    Each pair stands for <routine_id:int, is_in_main_image:bool>.
    To find routine_id within the top 10, specify n = 10.
    To exclude routines that aren't found in the main image, call
    with mainImgOnly = true.
*/
bool routineIsTopCandidate(int rtn_id, bool mainImgOnly=false, unsigned n = 0) {
    if (n < 1) {
        n = routineCandidateIdsVector.size();
    }
    unsigned i = 0;
    for (std::vector<std::pair<int, bool> >::const_iterator it = routineCandidateIdsVector.begin();
        (it != routineCandidateIdsVector.end()) && (i<n); ++it) {
        if (!mainImgOnly || it->second) {
            if (it->first == rtn_id) {
                return true;
            }
            ++i;
        }
    }

    return false;
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {
    // move BBL from global linked list to the vector in the relevant rtn
    for (std::set<BBLClass>::const_iterator it = bblsSet.begin();
        it != bblsSet.end(); ++it) {
        const BBLClass& bbl = *it;
        routinesDict[bbl.getRoutineId()].bbls.push_back(bbl);
    }

    // fix all absolute addresses to relative offset
    for (std::map<int, RoutineClass>::iterator routine_map_iter = routinesDict.begin();
        routine_map_iter != routinesDict.end(); ++routine_map_iter) {
        RoutineClass& rc = routine_map_iter->second;
        for (std::vector<BBLClass>::iterator bbl_iter = rc.bbls.begin();
            bbl_iter != rc.bbls.end(); ++bbl_iter) {
            // fix address to offset from lowest image address
            bbl_iter->setOffset(rc.getImageAddress());
        }
    }

    // clean all the edges that jump outside the routine
    for (std::map<int, RoutineClass>::iterator it = routinesDict.begin();
        it != routinesDict.end(); ++it) {
        it->second.cleanEdgesThatExitRoutine();
    }

    parseProfileMapIfFound();


/********************            it != rc.bbls.end(); ++it)
*****print to file***
********************/
    std::vector<RoutineClass> routinesVector;

    // copy from dictionary to routines vector all routines that have been called
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
    for (std::vector<RoutineClass>::const_iterator it = routinesVector.begin();
        it != routinesVector.end(); ++it) {
        const RoutineClass& rc = *it;
        outFile << rc;
        rc.printProfile(profileFile);
    }
}

void parsePorfileForCandidates() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return;
    }

    std::string strBuffer;
    while (std::getline(inFile, strBuffer)) {
        const char firstChar = strBuffer[0];

        if (firstChar == '#') {
            // ignore comments
            continue;
        } else if (firstChar == 'e') {
            // parse edge refernced the most recent routine
            continue;
        } else if (firstChar == 'b') {
            // parse bbl referenced the most recent routine
            continue;
        } else if (firstChar == 'r') {
            // append routine to result vector
            char rtn_name[101];
            unsigned long long rtn_addr = 0, img_addr =0;
            unsigned rtn_icnt = 0, rtn_rcnt = 0;
            int rtn_id;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt, &img_addr);
            routineCandidateIdsVector.push_back(std::pair<int,bool>(rtn_id, false));
        } else {
            std::cerr << "Could not compile line: " << strBuffer << endl;
        }
    } // end of while loop

    inFile.close();
}

/*********************************************************************************/
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;   
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct { 
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    bool hasNewTargAddr;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    xed_category_enum_t category_enum;
    unsigned int size;
    int new_targ_entry;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;


// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct { 
    ADDRINT rtn_addr; 
    USIZE rtn_size;
    int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
    bool isSafeForReplacedProbe;    
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;



/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {       

            // Open the RTN.
            RTN_Open( rtn );

            cerr << RTN_Name(rtn) << ":" << endl;

            for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {               
                  cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            }

            // Close the RTN.
            RTN_Close( rtn );
        }
    }
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
    // debug print decoded instr:
    char disasm_buf[2048];

    xed_uint64_t runtime_address = (xed_uint64_t)(address);  // set the runtime adddress for disassembly    

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0); 

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);                  

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
      cerr << "invalid opcode" << endl;
      return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{   
    for (int i=0; i < num_of_instr_map_entries; i++) {
        for (int j=0; j < translated_rtn_num; j++) {
            if (translated_rtn[j].instr_map_entry == i) {

                RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

                if (rtn == RTN_Invalid()) {
                    cerr << "Unknwon"  << ":" << endl;
                } else {
                  cerr << RTN_Name(rtn) << ":" << endl;
                }
            }
        }
        dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);      
    }
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
    cerr << dec << instr_map_entry << ": ";
    cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
    cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
    cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

    ADDRINT new_targ_addr;
    if (instr_map[instr_map_entry].new_targ_entry >= 0)
        new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
    else
        new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

    cerr << " new_targ_addr: " << hex << new_targ_addr;
    cerr << "    new instr:";
    dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

      xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
      xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);                  

      BOOL xed_ok = (xed_code == XED_ERROR_NONE);
      if (!xed_ok){
          cerr << "invalid opcode" << endl;
          return;
      }
 
      xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

      cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

      size = xed_decoded_inst_get_length (&new_xedd);   
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
{

    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

    if (xed_decoded_inst_get_length (xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
    
    xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
      orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;  
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
    
    xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;        
        return -1;
    }   
    
    // add a new entry in the instr_map:
    
    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
    instr_map[num_of_instr_map_entries].new_targ_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;    
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

    num_of_instr_map_entries++;

    // update expected size of tc:
    tc_cursor += new_size;           

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }
    

    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "    new instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
    }

    return new_size;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
    for (int i=0; i < num_of_instr_map_entries; i++) {              

        if (instr_map[i].orig_targ_addr == 0)
            continue;

        if (instr_map[i].hasNewTargAddr)
            continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
               continue;
    
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
                instr_map[i].new_targ_entry = j;
                break;
            }
        }
    }
   
    return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for(unsigned int i=0; i < memops ; i++)   {

        base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }
        
    }

    if (!isRipBase)
        return 0;

            
    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

    // modify rip displacement. use direct addressing mode: 
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length 
    xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;
            
    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);
    
    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry); 
        return -1;
    }               

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }
    
    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
    
    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

        cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
              << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].new_targ_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;
                

    xed_encoder_instruction_t  enc_instr;

    ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
                       instr_map[instr_map_entry].new_ins_addr - 
                       xed_decoded_inst_get_length (&xedd);

    if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
   

    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

    // handle the case where the original instr size is different from new encoded instr:
    if (olen != xed_decoded_inst_get_length (&xedd)) {
        
        new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
                   instr_map[instr_map_entry].new_ins_addr - olen;

        if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

        if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
        if (!convert_ok) {
            cerr << "conversion to encode request failed" << endl;
            return -1;
        }

        xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
        if (xed_error != XED_ERROR_NONE) {
            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
            dump_instr_map_entry(instr_map_entry);
            return -1;
        }       
    }

    
    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry); 
    }
        
    instr_map[instr_map_entry].hasNewTargAddr = true;
    return olen;    
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{                   

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int32_t  new_disp = 0;  
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;


    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
    
    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].new_targ_entry < 0) {
       int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
       return rc;
    }

    ADDRINT new_targ_addr;      
    new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
        
    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

    xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
      new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
      new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
    xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        char buf[2048];     
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
        return -1;
    }       

    new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
    
    xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }               

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}               


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;  

    do {
        
        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (int i=0; i < num_of_instr_map_entries; i++) {

            instr_map[i].new_ins_addr += size_diff;
                   
            int rc = 0;

            // fix rip displacement:            
            rc = fix_rip_displacement(i);
            if (rc < 0)
                return -1;

            if (rc > 0) { // this was a rip-based instruction which was fixed.

                if (instr_map[i].size != (unsigned int)rc) {
                   size_diff += (rc - instr_map[i].size);                   
                   instr_map[i].size = (unsigned int)rc;                                
                }

                continue;   
            }

            // check if it is a direct branch or a direct call instr:
            if (instr_map[i].orig_targ_addr == 0) {
                continue;  // not a direct branch or a direct call instr.
            }


            // fix instr displacement:          
            rc = fix_direct_br_call_displacement(i);
            if (rc < 0)
                return -1;

            if (instr_map[i].size != (unsigned int)rc) {
               size_diff += (rc - instr_map[i].size);
               instr_map[i].size = (unsigned int)rc;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

   return 0;
 }


/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
    int rc;

    // go over routines and check if they are candidates for translation and mark them for translation:

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec)) {
            continue;
        }

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (rtn == RTN_Invalid()) {
                cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
                continue;
            }
            if (!routineIsTopCandidate(RTN_Id(rtn), true, 10)) {
                continue;
            }

            translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);         
            translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
            translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
            translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;   

            // Open the RTN.
            RTN_Open( rtn );              

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

                //debug print of orig instruction:
                if (KnobVerbose) {
                    cerr << "old instr: ";
                    cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
                    //xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));                           
                }               

                ADDRINT addr = INS_Address(ins);
                            
                xed_decoded_inst_t xedd;
                xed_error_enum_t xed_code;                          
                
                xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

                xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
                if (xed_code != XED_ERROR_NONE) {
                    cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    break;
                }

                // Add instr into instr map:
                rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
                if (rc < 0) {
                    cerr << "ERROR: failed during instructon translation." << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    break;
                }
            } // end for INS...


            // debug print of routine name:
            if (KnobVerbose) {
                cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
            }           

            // Close the RTN.
            RTN_Close( rtn );

            if (++translated_rtn_num >= 10) {
                return 0;
            }
         } // end for RTN..
    } // end for SEC...

    std::cerr << "WOOPS: translated_rtn_num = " << translated_rtn_num << endl;
    return 0;
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
    int cursor = 0;

    for (int i=0; i < num_of_instr_map_entries; i++) {

      if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
          cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
          return -1;
      }   

      memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

      cursor += instr_map[i].size;
    }

    return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
    // Commit the translated functions: 
    // Go over the candidate functions and replace the original ones by their new successfully translated ones:

    for (int i=0; i < translated_rtn_num; i++) {

        //replace function by new function in tc
    
        if (translated_rtn[i].instr_map_entry >= 0) {
                    
            if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {                      

                RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

                //debug print:              
                if (rtn == RTN_Invalid()) {
                    cerr << "committing rtN: Unknown";
                } else {
                    cerr << "committing rtN: " << RTN_Name(rtn);
                }
                cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

                        
                if (RTN_IsSafeForProbedReplacement(rtn)) {

                    AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);                         

                    if (origFptr == NULL) {
                        cerr << "RTN_ReplaceProbed failed.";
                    } else {
                        cerr << "RTN_ReplaceProbed succeeded. ";
                    }
                    cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
                            << " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl; 

                    dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);                                                
                }                                               
            }
        }
    }
}


/****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
    // Calculate size of executable sections and allocate required memory:
    //TODO: need to find a more efficient way to calculate the size 
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;


        if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
            lowest_sec_addr = SEC_Address(sec);

        if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
            highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

        // need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {       

            if (rtn == RTN_Invalid())
                    continue;

                  max_ins_count += RTN_NumIns(rtn);
                  max_rtn_count++;

                  std::pair<int, bool> rtn_pair(RTN_Id(rtn), false);
                  std::vector<pair<int, bool> >::iterator it = std::find(
                    routineCandidateIdsVector.begin(),
                    routineCandidateIdsVector.end(), rtn_pair);
                  it->second = true;
            }
    }

    max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
    
    // Allocate memory for the instr map needed to fix all branch targets in translated routines:
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) {
        perror("calloc");
        return -1;
    }

    // Allocate memory for the array of candidate routines containing inlineable function calls:
    // Need to estimate size of inlined routines.. ???
    translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
    if (translated_rtn == NULL) {
        perror("calloc");
        return -1;
    }

    // get a page size in the system:
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
      return -1;
    }

    ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

    // Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:      
    char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if ((ADDRINT) addr == 0xffffffffffffffff) {
        cerr << "failed to allocate tc" << endl;
        return -1;
    }
    
    tc = (char *)addr;
    return 0;
}



/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
    // debug print of all images' instructions
    //dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;

    int rc = 0;

    // step 1: Check size of executable sections and allocate required memory:  
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;

    
    // Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;  
    
    // Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0 )
        return;
    
    cout << "after calculate direct br targets" << endl;

    // Step 4: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0 )
        return;
    
    cout << "after fix instructions displacements" << endl;


    // Step 5: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0 )
        return;

    cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
       cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

       cerr << endl << "instructions map dump:" << endl;
       dump_entire_instr_map();     // dump all translated instructions in map_instr
   }


    // Step 6: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    commit_translated_routines();   

    cout << "after commit translated routines" << endl;
   
}

/*********************************************************************************/



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

int printIllegalFlags() {
    std::cerr << "Illegal flages entered. Please enter either -prof or -inst.\n";
    return -1;    
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[]) {
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv)) {
        return Usage();
    } else if (!(KnobRunEx2 ^ KnobOptimizeHottestTen)) {
        printIllegalFlags(); // return from here would thwart compilation
    }

    if (KnobRunEx2) {
        // Register Routine to be called to instrument rtn
        RTN_AddInstrumentFunction(Routine, 0);
        
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register Fini to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);

        // Start the program, never returns
        PIN_StartProgram(); 
    } else if (KnobOptimizeHottestTen) {
        parsePorfileForCandidates();
        // Register ImageLoad
        IMG_AddInstrumentFunction(ImageLoad, 0);

        // Start the program, never returns
        PIN_StartProgramProbed();
    } else {
        /* This scenario is required for the program to complete
        compilation properly. */
        PIN_StartProgram();
    }

    return 0;
}