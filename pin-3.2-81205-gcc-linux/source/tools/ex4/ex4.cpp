//O
//B

#include <vector>
#include <memory>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <string>
#include <set>
#include "pin.H"

/*********************************************************************************/
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
KNOB<BOOL>   KnobReorderBBLsInHottestRoutine(KNOB_MODE_WRITEONCE,    "pintool",
    "opt", "0", "optimize bbl order");


/*********************************************************************************/
/* ===================================================================== */
/* Some Declarations */
/* ===================================================================== */

const int NUMBER_OF_CANDIDATES = 10;
const std::string profileFilename = "_profile.map";
const std::string edgeString = "\t\tEdge%d: BB%d -> BB%d %u\n";
const std::string edgeProfString = "e\t\tEdge%d: (%llu, %llu, %llu) (taken: %u out of %u calls) (conditional=%d) (call=%d)\n";
const std::string bblString = "\tBB%d: 0x%llx - 0x%llx\n";
const std::string bblProfString = "b\tBB%d: 0x%llx - 0x%llx\n";
const std::string routineProfString = "r%d %s at: 0x%llx\ticount: %u\trcount: %u\tImage address: %llx\n";
std::ofstream mylog;

/**
    routine ids of routines that are found in the main image are
    marked with true.
*/
std::vector<std::pair<int, bool> > routineCandidateIdsVector;

bool routineIsTopCandidate(int, bool, unsigned);
int hottestRoutineId = 0;


/** More includes **/
#include "xed_helper_code.h"
#include "InstructionClass.h"
#include "Routine.h"
#include "RankedBBL.h"

std::map<int, RoutineClass> routinesDict;
std::set<BBLClass> bblsSet;
std::vector<RankedBBL> rankedBBLsVector;



void incrementRoutineICounter(int i) {
    routinesDict[i].incInstructionCount();
}
void incrementRoutineRCounter(int i) {
    routinesDict[i].incRoutineCount();
}

void incrementRoutineEdgeTakenCounter(int i, int j) {
    (routinesDict[i].edges[j]).incTakenCount();
}

void incrementRoutineEdgeInstCounter(int i, int j) {
    (routinesDict[i].edges[j]).incInstructionCount();
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
            unsigned icount, tcount;
            int cond_branch, is_call;
            sscanf(strBuffer.c_str(), edgeProfString.c_str(), &num,
                &src_ins, &dst_ins, &next_ins, &tcount, &icount,
                &cond_branch, &is_call);
            currentRoutine.edges.push_back(
                EDGEClass(src_ins, dst_ins,
                next_ins, cond_branch, is_call,
                icount, tcount, currentRoutine.getId()));
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

            const unsigned rtn_name_array_size = 200;
            char rtn_name[rtn_name_array_size + 1];
            unsigned long long rtn_addr = 0, img_addr = 0;
            unsigned rtn_icnt = 0, rtn_rcnt = 0;
            int rtn_id;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt, &img_addr);
            currentRoutine = RoutineClass(rtn_id, std::string(rtn_name), rtn_addr,
                rtn_icnt, rtn_rcnt, img_addr);
            currentRoutine.obsoleteImageAddress = true;
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

std::set<ADDRINT> BBL_Opening_Addresses_set;
std::vector<EDGEClass> edges_from_profile_vector;

void addBBLOpeningAddressesToSetOfAddresses(std::set<ADDRINT>& addressesSet,
    const EDGEClass& edge) {
    if (edge.isCall()) {
        // Calls should not appear in the file
        return;
    }

    bool dest_found = false, next_inst_found = false;
    for (auto& addr : addressesSet) {
        if (addr == edge._dst_offset) {
            dest_found = true;
            if (!edge.isConditionalBranch() || next_inst_found) {
                break;
            }
        }
        if (edge.isConditionalBranch()) {
            if (addr == edge._next_ins_offset) {
                next_inst_found = true;
                if (dest_found) {
                    break;
                }
            }
        }
    }

    if (!dest_found) {
        addressesSet.insert(edge._dst_offset);
    }
    if (!next_inst_found) {
        addressesSet.insert(edge._next_ins_offset);
    }
}

void addRankedBBLToVector(std::vector<RankedBBL>& rbVector, const EDGEClass& edge) {
    if (edge.isCall()) {
        // Calls should not appear in the file
        return;
    }

    HasSameSourceAddress predDest(edge._dst_offset);
    std::vector<RankedBBL>::iterator find_iter = std::find_if(
        rbVector.begin(), rbVector.end(), predDest);
    int rank = edge.getTakenCount();
    if (find_iter != rbVector.end()) {
        RankedBBL rbbl(edge._dst_offset, (ADDRINT)(0), edge.getRoutineId(), rank);
        rankedBBLsVector.push_back(rbbl);
    } else {
        find_iter->increaseRank(rank);
    }

    if (edge.isConditionalBranch()) {
        HasSameSourceAddress predNext(edge._next_ins_offset);
        find_iter = std::find_if(rbVector.begin(), rbVector.end(), predNext);
        rank = edge.getFallThroughCount();
        if (find_iter != rbVector.end()) {
            RankedBBL rbbl(edge._next_ins_offset, (ADDRINT)(0),
                edge.getRoutineId(), rank);;
            rankedBBLsVector.push_back(rbbl);
        } else {
            find_iter->increaseRank(rank);
        }
    }
}

void parseForBBLReordering() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return;
    }

    std::string strBuffer;
    int first_routine_entered = false; // TODO: Receive the top routine ID as an argument
    int second_routine_entered = false;
    int first_rtn_id = (-1);
    while (std::getline(inFile, strBuffer)) {
        const char firstChar = strBuffer[0];

        if (firstChar == '#') {
            // ignore comments
            continue;
        } else if (firstChar == 'e') {
            // parse edge refernced the most recent routine
            if (second_routine_entered) {
                continue;
            }
            unsigned long long src_ins, dst_ins, next_ins;
            int num;
            unsigned icount, tcount;
            int cond_branch, is_call;
            sscanf(strBuffer.c_str(), edgeProfString.c_str(), &num,
                &src_ins, &dst_ins, &next_ins, &tcount, &icount,
                &cond_branch, &is_call);

            edges_from_profile_vector.push_back(EDGEClass(
                src_ins, dst_ins, next_ins,
                icount, cond_branch, is_call, tcount, first_rtn_id)); //,
        } else if (firstChar == 'b') {
            // parse bbl referenced the most recent routine
            continue;
        } else if (firstChar == 'r') {
            // append routine to result vector
            if (first_routine_entered) {
                second_routine_entered = true;
            }
            first_routine_entered = true;
            char rtn_name[101];
            unsigned long long rtn_addr = 0, img_addr = 0;
            unsigned rtn_icnt = 0, rtn_rcnt = 0;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &first_rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt, &img_addr);
            routineCandidateIdsVector.push_back(std::pair<int,bool>(first_rtn_id, false));
        } else {
            std::cerr << "Could not compile line: " << strBuffer << endl;
        }
    } // end of while loop

    inFile.close();
}

void set_up_data_structures_for_hottest_routine_optimization() {
    parseForBBLReordering();

    for (const auto& edge : edges_from_profile_vector) {
        addBBLOpeningAddressesToSetOfAddresses(BBL_Opening_Addresses_set, edge);
        addRankedBBLToVector(rankedBBLsVector, edge);
    }
}

/**
    The routine traverses through routineCandidateIdsVector's pairs.
    Each pair stands for <routine_id:int, is_in_main_image:bool>.
    To find routine_id within the top 10, specify n = 10.
    To exclude routines that aren't found in the main image, call
    with mainImgOnly = true.
*/
bool routineIsTopCandidate(int rtn_id, bool mainImgOnly=true, unsigned n = 0) {
    if (n < 1) {
        n = routineCandidateIdsVector.size();
    }
    unsigned i = 0;

    for (std::vector<std::pair<int, bool> >::const_iterator it = routineCandidateIdsVector.begin();
        (it != routineCandidateIdsVector.end()) && (i<n); ++it) {
        if (!mainImgOnly || it->second) { // it->second equal to routine_is_in_main_image
            if (it->first == rtn_id) {
                return true;
            }
            ++i;
        }
    }

    return false;
}

std::vector<InstructionClass> instructionsVector;
void parseRoutineManually(RTN rtn) {
    RTN_Open(rtn);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        ADDRINT instruction_address = INS_Address(ins);
        xed_decoded_inst_t *xedd = INS_XedDec(ins);
        //xed_category_enum_t category_enum = xed_decoded_inst_get_category(xedd);
        InstructionClass curr(instruction_address, xedd);
        instructionsVector.push_back(curr);
    }

    ADDRINT image_offset = IMG_LowAddress(IMG_FindByAddress(RTN_Address(rtn)));
    std::cout << "BBL opening offsets: (Image offset is: " << image_offset << ")" << std::endl;
    for (const auto& i : BBL_Opening_Addresses_set) {
        std::vector<InstructionClass>::iterator it = std::find(
            instructionsVector.begin(), instructionsVector.end(), i+image_offset);
        if (it != instructionsVector.end()) {
            std::cout << "BBL opens: ";
        } else {
            std::cout << "Address not found: ";
        }
        std::cout << i << std::endl;
    }

    RTN_Close(rtn);

    for (auto rbbl : rankedBBLsVector) {
        std::cout << rbbl;
    }
}

VOID xedRoutine(RTN rtn, VOID *v) {
    RoutineClass rc(rtn);
    int routine_id = rc.getId();
    if (!routineIsTopCandidate(routine_id, false, 1)) {
        /* TODO: Note that we invoke the call with mainImageOnly=false.
        This is false, but it works, because the hottest routine is also
        found in the main image.
        Should the hottest routine will not found in the main image,
        it will result with a failure down the line.
        */
        return;
    }

    std::cout << "Entered routine No. " << routine_id << std::endl;

    parseRoutineManually(rtn);
}

// Pin calls this function every time a new rtn is executed
VOID RoutineInstrument(RTN rtn, VOID *v) {
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
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)incrementRoutineICounter,\
            IARG_UINT32, routine_id, IARG_END);

        if (INS_IsDirectBranchOrCall(ins)) {
            int edge_index = routinesDict[routine_id].edges.size();
            routinesDict[routine_id].edges.push_back(\
                EDGEClass(
                    INS_Address(ins) - rc.getImageAddress(),
                    INS_DirectBranchOrCallTargetAddress(ins) - rc.getImageAddress(),
                    INS_NextAddress(ins) - rc.getImageAddress(),
                    INS_HasFallThrough(ins),
                    INS_IsCall(ins),
                    rtn)
                );

            INS_InsertCall(ins, IPOINT_BEFORE, 
                (AFUNPTR)incrementRoutineEdgeInstCounter, IARG_UINT32,
                routine_id, IARG_UINT32, edge_index, IARG_END);
            
            // insert a call to increment edge's counter, called iff the branch was taken
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                (AFUNPTR)incrementRoutineEdgeTakenCounter, IARG_UINT32,
                routine_id, IARG_UINT32, edge_index, IARG_END);
        }
    }

    RTN_Close(rtn);
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


/********************
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

        // clean silent edges (The instruction was not executed)
        rc.edges.erase(std::remove_if(rc.edges.begin(), rc.edges.end(), 
            edgeWithZeroCalls), rc.edges.end());

        // sort edges
        std::sort(rc.edges.begin(), rc.edges.end(), compareEdgeTakenCounterIsGreaterThan);

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
    } /*else if (!(KnobRunEx2 ^ KnobOptimizeHottestTen)) {
        printIllegalFlags(); // return from here would thwart compilation
    }*/

    if (KnobRunEx2) {
        // Register Routine to be called to instrument rtn
        RTN_AddInstrumentFunction(RoutineInstrument, 0);
        
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
    } else if (KnobReorderBBLsInHottestRoutine) {
        set_up_data_structures_for_hottest_routine_optimization();

        RTN_AddInstrumentFunction(xedRoutine, 0);

        PIN_StartProgramProbed();
    } else {
        /* This scenario is required for the program to complete
        compilation properly. */
        PIN_StartProgram();
    }

    return 0;
}
