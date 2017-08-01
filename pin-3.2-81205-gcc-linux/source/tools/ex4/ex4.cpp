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
int printProfileFileNotFound();
int HottestRoutineId = (-1);
unsigned HottestRoutine_rcnt;

/** More includes **/
#include "xed_helper_code.h"
#include "InstructionClass.h"
std::vector<InstructionClass> instructionsVector;
#include "Routine.h"

std::map<int, RoutineClass> routinesDict;
std::set<BBLClass> bblsSet;
std::vector<BBLClass> rankedBBLsVector;
std::set<ADDRINT> BBL_Opening_Addresses_set;
std::vector<EDGEClass> edges_from_profile_vector;

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

int parseProfileMap_ex2() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return (-1);
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
    return 0;
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

int parseProfileMap_ex3() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return (-1);
    }

    std::string strBuffer;
    while (std::getline(inFile, strBuffer)) {
        const char firstChar = strBuffer[0];

        if (firstChar == '#') {
            // ignore comments
            continue;
        } else if (firstChar == 'e') {
            // ignore edges
            continue;
        } else if (firstChar == 'b') {
            // ignore bbls
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

    return 0;
}

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

void rankBBLs_aux(
    std::vector<BBLClass>& bbls,
    ADDRINT edgeTargetAddress,
    int rank) {
    for (std::vector<BBLClass>::iterator bbl_it = bbls.begin();
        bbl_it != bbls.end(); ++bbl_it) {
        if (!bbl_it->isInstructionOffsetIn(edgeTargetAddress)) {
            continue;
        }

        bbl_it->increaseRank(rank);
        while (!bbl_it->hasBranchInIt()) {
            if (++bbl_it == bbls.end()) {
                break;
            }
            bbl_it->increaseRank(rank);
        }
        
        break;
    }
}

void rankBBLs(std::vector<BBLClass>& bbls,
    const std::vector<EDGEClass>& edges) {
    for (auto& edge : edges) {
        rankBBLs_aux(bbls, edge._dst_offset, edge.getTakenCount());

        if (!edge.isConditionalBranch()) {
            continue;
        }

        rankBBLs_aux(bbls, edge._next_ins_offset, edge.getFallThroughCount());
    }

    rankBBLs_aux(bbls, bbls[0]._src_offset, HottestRoutine_rcnt);
}

int buildBBLsFromInstructions(
    const std::vector<InstructionClass>& instructionVec,
    std::vector<BBLClass>& bblVec,
    long image_offset) {
    int opening_index = (-1);
    int closing_index = (-1);

    for (const auto& inst : instructionVec) {
        if (inst.open_bbl) {
            if (opening_index != (-1)) {
                std::cerr << "Woops: Open after Open" << std::endl;
                return (-1);
            }
            opening_index = inst.index_in_routine;
        }

        if (inst.close_bbl) {
            closing_index = inst.index_in_routine;
            if (opening_index == (-1)) {
                std::cerr << "Woops: Close before Open" << std::endl;
                return (-2);
            }

            BBLClass bbl(
                instructionVec.at(opening_index).address,
                instructionVec.at(closing_index).address,
                HottestRoutineId,
                opening_index,
                closing_index
            );
            bbl.setOffset(image_offset);

            bblVec.push_back(bbl);

            opening_index = (-1);
            closing_index = (-1);
        }
    }

    return 0;
}

int parseProfileMap_ex4() {
    std::ifstream inFile(profileFilename.c_str());
    if (!inFile.is_open()) {
        return (-1);
    }

    std::string strBuffer;
    int first_routine_entered = false;
    int second_routine_entered = false;
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
                icount, cond_branch, is_call, tcount, HottestRoutineId));
        } else if (firstChar == 'b') {
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
            int rtn_id;
            sscanf(strBuffer.c_str(), routineProfString.c_str(),
                &rtn_id, rtn_name, &rtn_addr, &rtn_icnt, &rtn_rcnt, &img_addr);
            routineCandidateIdsVector.push_back(std::pair<int,bool>(rtn_id, false));
            if (!second_routine_entered) {
                HottestRoutineId = rtn_id;
                HottestRoutine_rcnt = rtn_rcnt;
            }
        } else {
            std::cerr << "Could not compile line: " << strBuffer << endl;
        }
    } // end of while loop

    inFile.close();
    return 0;
}

int set_up_data_structures_for_hottest_routine_optimization() {
    if (parseProfileMap_ex4()) {
        return (-1);
    }
/*
    for (const auto& edge : edges_from_profile_vector) {
        addBBLOpeningAddressesToSetOfAddresses(BBL_Opening_Addresses_set, edge);
        addRankedBBLToVector(rankedBBLsVector, edge);
    }
*/
    return 0;
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


void printBBLOpeningOffset(long image_offset) {
    // verify here that there's instruction where we expect it to be
    std::cout << "BBL opening offsets: (Image offset is: " << image_offset << ")" << std::endl;
    for (const auto& bbl_offset : BBL_Opening_Addresses_set) {
        std::vector<InstructionClass>::iterator it = std::find(
            instructionsVector.begin(), instructionsVector.end(), bbl_offset+image_offset);
        if (it != instructionsVector.end()) {
            std::cout << "BBL opens: ";
        } else {
            std::cout << "Address not found: ";
        }
        std::cout << bbl_offset << std::endl;
    }
}

/**
    The function traverses over edges vector that lists all the direct
    branches (unconditional jumps included) and marks instructions
    in @instructionVec as either BBL_opening or BBL_closing, or both.
*/
void markInstructionsAsBBLStartOrEnd(std::vector<InstructionClass>& instructionVec,
    const std::vector<EDGEClass>& directBranchesVector,
    long image_offset) {
    for (const auto& edge : directBranchesVector) {
        std::vector<InstructionClass>::iterator it_src = std::find(
            instructionVec.begin(), instructionVec.end(),
            edge._src_offset+image_offset);
        if (it_src != instructionVec.end()) {
            it_src->close_bbl = true;
        } else {
            std::cerr << "Woops: Couldn't find instruction where expected" <<\
                edge._src_offset+image_offset << std::endl;
        }

        std::vector<InstructionClass>::iterator it_dest = std::find(
            instructionVec.begin(), instructionVec.end(),
            edge._dst_offset+image_offset);
        if (it_dest != instructionVec.end()) {
            it_dest->open_bbl = true;
            if (it_dest->index_in_routine > 0) {
                std::vector<InstructionClass>::iterator it_prev = std::find(
                instructionVec.begin(), instructionVec.end(),
                it_dest->previous_address);
                if (it_prev != instructionVec.end()) {
                    if (it_dest->address - it_prev->address != it_prev->size_in_bytes) {
                        std::cerr << "Inferring bbl_close_instruction failed in addresses: " <<
                        it_dest->address << " " << it_prev->address << std::endl;
                    } else {
                        it_prev->close_bbl = true;
                    }
                } else {
                    std::cerr << "Woops: Couldn't find instruction where expected" <<\
                        it_dest->previous_address << std::endl;
                }
            }
        } else {
            std::cerr << "Woops: Couldn't find instruction where expected" <<\
                edge._dst_offset+image_offset << std::endl;
        }

        if (edge.isConditionalBranch()) {
            std::vector<InstructionClass>::iterator it_next = std::find(
                instructionVec.begin(), instructionVec.end(),
                edge._next_ins_offset+image_offset);
            if (it_next != instructionVec.end()) {
                it_next->open_bbl = true;
            } else {
                std::cerr << "Woops: Couldn't find instruction where expected" <<\
                    edge._next_ins_offset+image_offset << std::endl;
            }
        }
    }

    for (auto & inst : instructionVec) {
        if (inst.is_branch && !inst.close_bbl) {
            std::cerr << "Unchecked indirect branch found in address: ";
            std::cerr << inst.address << std::endl;
        }
    }
}

void buildInstructionObjectUsingPinTool(RTN rtn,
    std::vector<InstructionClass>& instVec) {
    int i = 0;
    ADDRINT prev_addr = 0;
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        ADDRINT instruction_address = INS_Address(ins);
        xed_decoded_inst_t *xedd = INS_XedDec(ins);
        InstructionClass curr(instruction_address, xedd, i,
            INS_Size(ins), prev_addr, INS_IsBranch(ins));
        if (i == 0) {
            curr.open_bbl = true;
        }

        instVec.push_back(curr);

        prev_addr = instruction_address;
        ++i;
    }

    // Last instruction closes a BBL implicitly
    instVec.at(instVec.size()-1).close_bbl = true;
}

int parseRoutineManually(RTN rtn) {
    RTN_Open(rtn);

    buildInstructionObjectUsingPinTool(rtn, instructionsVector);
    ADDRINT image_offset = IMG_LowAddress(IMG_FindByAddress(RTN_Address(rtn)));
    
    RTN_Close(rtn);
    
    printBBLOpeningOffset(image_offset);
    markInstructionsAsBBLStartOrEnd(instructionsVector,
        edges_from_profile_vector,
        image_offset);
    int res = buildBBLsFromInstructions(instructionsVector, rankedBBLsVector,
        image_offset);
    if (res) {
        for (auto instruction : instructionsVector) {
            std::cout << instruction;
        }
        return res;
    }

    rankBBLs(rankedBBLsVector, edges_from_profile_vector);

    int i = 0;
    for (auto bbl : rankedBBLsVector) {
        std::cout << "BBL NO.: " << i++ << "\t";
        std::cout << bbl.first_instr_index << " ";
        std::cout << bbl.last_instr_index << "\t"; 
        std::cout << "rank is: " << bbl.rank << std::endl;
    }

    return 0;
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

    if (parseProfileMap_ex2()) {
        // error
        printProfileFileNotFound();
        return;
    }


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
    std::cerr << "This Pintool counts the number of times a routine is executed" << endl;
    std::cerr << "and the number of instructions executed in a routine" << endl;
    std::cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int printIllegalFlags() {
    std::cerr << "Illegal flages entered. Please enter either -prof or -inst.\n";
    return 0;    
}

int printProfileFileNotFound() {
    std::cerr << "Profile was not found" << std::endl;
    return 0;
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
        if (parseProfileMap_ex3()) {
            printProfileFileNotFound();
            return 0;
        }
        // Register ImageLoad
        IMG_AddInstrumentFunction(ImageLoad, 0);

        // Start the program, never returns
        PIN_StartProgramProbed();
    } else if (KnobReorderBBLsInHottestRoutine) {
        if (set_up_data_structures_for_hottest_routine_optimization()) {
            printProfileFileNotFound();
            return 0;
        }

        RTN_AddInstrumentFunction(xedRoutine, 0);

        PIN_StartProgramProbed();
    } else {
        /* This scenario is required for the program to complete
        compilation properly. */
        PIN_StartProgram();
    }

    return 0;
}
