/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/rtn-translation.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool generates translated code of routines, places them in an allocated TC 
 * and patches the orginal code to jump to the translated routines.
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
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


std::vector<ADDRINT> ofir_instrumentations_addresses;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

/* ===================================================================== */

#include <set>
#include "Tracer.h"

using std::set;

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#define MALLOC "malloc"
#define FREE "free"
#define MAIN "main"

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ostream& TraceFile = std::cout;
bool mainInit = false;
bool mainFinished = false;
ADDRINT lastMallocSize;
Tracer mallocTracer = Tracer::GetInstance();
set<ADDRINT> suspiciousAddresses;
int asmFileSize;
std::string binaryFilename = "env_r_s.bin";


/* ===================================================================== */

bool IsCalledAfterMain()
{
	// Don't run instumentation code unless main has started
	if (!mainInit || mainFinished)
		return false;
	
	return true;
}

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */
 
VOID Arg1Before(CHAR * name, ADDRINT size) {
	if (!IsCalledAfterMain())
		return;

	lastMallocSize = size;
}

VOID AfterFree(CHAR * name, ADDRINT addr)
{
	if (!IsCalledAfterMain())
		return;

	mallocTracer.DeleteAddress(addr);
}

VOID MallocAfter(ADDRINT ret)
{
	if (!IsCalledAfterMain())
		return;
	
	mallocTracer.AddNewAddress(ret, lastMallocSize);
}

VOID mainBefore()
{
	mainInit = true;
}

VOID mainAfter()
{
	mainFinished =  true;
}

unsigned int dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr);

// Print a memory read record
VOID RecordMemRead(VOID * ip, ADDRINT addr) {
	// dump_instr_from_mem((ADDRINT*)ip, (ADDRINT)ip);
	// std::cerr << "RecordMemRead(" << hex << ip << ", 0x" << addr << ")" << std::endl;
	if (!IsCalledAfterMain()) {
		return;
	}
	
	if (suspiciousAddresses.count((ADDRINT)ip) !=0) {
		cout << "Memory read overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
	}
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, ADDRINT addr) {
	// dump_instr_from_mem((ADDRINT*)ip, (ADDRINT)ip);
	// std::cerr << "RecordMemWrite(" << hex << ip << ", 0x" << addr << ")" << std::endl;
	if (!IsCalledAfterMain()) {
		return;
	}
	
	if (suspiciousAddresses.count((ADDRINT)ip) !=0) {
		cout << "Memory write overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
	}
}

VOID CheckAddIns(ADDRINT regVal, UINT64 immediate, VOID* ip, UINT64 insSize)
{
	// std::cerr << "CheckAddIns(" << regVal << ", "<< immediate << ", "<< ip << ", "<< insSize <<") is called" << std::endl;
	if (!mallocTracer.IsAllocatedAddress(regVal))
		return;

	if (mallocTracer.GetStartAddress(regVal + immediate) != mallocTracer.GetStartAddress(regVal))
		suspiciousAddresses.insert(ADDRINT(ip) + insSize);
}

bool INS_IsAdd(INS ins)
{
	string insDisassembly = INS_Disassemble(ins);
	if (insDisassembly.substr(0, 3) == "add")	
		return true;
	
	return false;
}

VOID CheckAddInsIndexReg(ADDRINT regVal, ADDRINT indexRegVal, VOID* ip, UINT64 insSize)
{
	// std::cerr << "CheckAddInsIndexReg(" << regVal << ", " << indexRegVal << ", " << ip << ", "<< insSize << ") is called" << std::endl;
	if (!mallocTracer.IsAllocatedAddress(regVal))
		return;
		
	if (mallocTracer.GetStartAddress(regVal + indexRegVal) != mallocTracer.GetStartAddress(regVal))
		suspiciousAddresses.insert(ADDRINT(ip) + insSize);
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
   
VOID mallocImage(IMG img) {
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    
    //  Find the malloc() function.
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn)) {
        RTN_InsertCallProbed(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);

        PROTO proto_malloc = PROTO_Allocate( PIN_PARG(void *), CALLINGSTD_DEFAULT,
            MALLOC, PIN_PARG(int), PIN_PARG_END() );
                       
        RTN_InsertCallProbed(mallocRtn, IPOINT_AFTER,
        	(AFUNPTR)MallocAfter,
        	IARG_PROTOTYPE, proto_malloc, 
        	IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn)) {
    	PROTO proto_free = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
            FREE, PIN_PARG(void*), PIN_PARG_END() );
        // Instrument free()
        RTN_InsertCallProbed(freeRtn, IPOINT_AFTER, (AFUNPTR)AfterFree,
        	IARG_PROTOTYPE, proto_free,
            IARG_ADDRINT, FREE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
    }
    
    RTN mainRtn = RTN_FindByName(img, MAIN);
	if (RTN_Valid(mainRtn)) {
		RTN_InsertCallProbed(mainRtn, IPOINT_BEFORE, (AFUNPTR)mainBefore, IARG_END);
		
		PROTO proto_main = PROTO_Allocate( PIN_PARG(int), CALLINGSTD_DEFAULT,
            FREE, PIN_PARG(int), PIN_PARG(char*), PIN_PARG_END() );
		
		RTN_InsertCallProbed(mainRtn, IPOINT_AFTER, (AFUNPTR)mainAfter,
			IARG_PROTOTYPE, proto_main,
			IARG_END);
	}
}


/* ======================================================================= */

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream* out = 0;

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

#define MAX_PROBE_JUMP_INSTR_BYTES  14  // 6 bytes of "jmp [rip]" instr + size of 64bit address which is 8 bytes long
#define JMP_TO_ITSELF_OFFFSET_OPCODE 0xfffffffbe9  // jmp -5 = jmp to itself
#define SIZE_OF_JMP_TO_ITSELF_OPCODE 5  // 5 bytes is the size of jmp -5 to itself
#define SIZE_OF_JMP_RIP_INSTR 6    // 6 bytes is the size of "jmp [rip]" instruction.

// global variables related to the tc (translation cache) containing the new code:
char *tc;	
int tc_cursor = 0;
int tclen = 0;
IMG img_tc;
int pagesize;

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
	bool call_imm;
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
	bool isProbed;
	char orig_probed_mem[MAX_PROBE_JUMP_INSTR_BYTES];
	char translated_probed_mem[MAX_PROBE_JUMP_INSTR_BYTES];
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

// commit/uncommit thread-related variables:
volatile bool enable_commit_uncommit_flag = false;


/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

int addBinaryCodeToTC(ADDRINT mmap_addr, int codeSize, int funcIndex, UINT64 val1, UINT64 val2, UINT64 val3, UINT64 val4);

// Pin calls this function every time a new rtn is executed
int addAssemblyCode(INS ins) {
	int instrumentationAdded = 0;
	ADDRINT instructionAddr = INS_Address(ins);
	int instructionSize = INS_Size(ins);

	if (INS_IsAdd(ins)) {
		UINT32 opNum = INS_OperandCount(ins);
		UINT64 immediate = 0;
		REG operandReg = REG_INVALID();
		REG indexReg = REG_INVALID();
		bool foundReg = false;
		bool foundIndexReg = false;
		bool foundImm = false;

		for (UINT32 i = 0; i < opNum; ++i) {
			if (!foundImm && INS_OperandIsImmediate(ins, i)) {
				immediate = INS_OperandImmediate(ins, i);
				foundImm = true;
			} else if (!foundReg && INS_OperandIsReg(ins, i) && INS_OperandWritten(ins, i)) {
				operandReg = INS_OperandReg(ins, i);
				if (REG_INVALID() != operandReg )
					foundReg = true;
			} else if (!foundIndexReg && INS_OperandIsReg(ins, i) && INS_OperandReadOnly(ins, i)) {
				indexReg = INS_OperandReg(ins, i);
				if (REG_INVALID() != indexReg)
					foundIndexReg = true;
			}

			if (foundReg && foundImm && REG_valid_for_iarg_reg_value(operandReg)) {
					if (addBinaryCodeToTC(ofir_instrumentations_addresses[0], asmFileSize,
						1, operandReg, immediate, instructionAddr, INS_Size(ins))) {
						return (-1);
					}
					++instrumentationAdded;

/*					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddIns, 
					IARG_REG_VALUE, operandReg, IARG_UINT64, immediate,
					IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
*/
				break;
			} else if (foundIndexReg && foundReg && REG_valid_for_iarg_reg_value(operandReg) && REG_valid_for_iarg_reg_value(indexReg)) {
					if(addBinaryCodeToTC(ofir_instrumentations_addresses[0], asmFileSize,
						2, operandReg, indexReg, instructionAddr, INS_Size(ins))) {
						return (-1);
					}

					++instrumentationAdded;
/*					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddInsIndexReg, 
					IARG_REG_VALUE, operandReg, IARG_REG_VALUE, indexReg,
					IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
*/				break;
			}
		}
	} else { // not ADD instruction
		UINT32 memOperands = INS_MemoryOperandCount(ins);
		// bool ins_mem_op_flag = false;
		// Iterate over each memory operand of the instruction.
		for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
			bool readFlag = false, writeFlag = false;

			if (INS_MemoryOperandIsRead(ins, memOp)) {
				readFlag = true;
/*					 INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_END);
*/			}
			// Note that in some architectures a single memory operand can be 
			// both read and written (for instance incl (%eax) on IA-32)
			// In that case we instrument it once for read and once for write.
			if (INS_MemoryOperandIsWritten(ins, memOp))	{
				writeFlag = true;
/*					 INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_UINT64, INS_Size(ins),
					IARG_END);
*/			}

			if (!readFlag && !writeFlag) {
				continue;
			}
/*			
			ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, memOp);
			REG baseReg = INS_OperandMemoryBaseReg(ins, memOp);
			REG indexReg = INS_OperandMemoryIndexReg(ins, memOp);
			UINT32 scale = INS_OperandMemoryScale(ins, memOp);
			if (!ins_mem_op_flag) {
				std::cout << std::endl;
				ins_mem_op_flag = true;
			}
			if (readFlag) {
				std::cout << "READ";
			}
			if (writeFlag) {
				std::cout << "WRITE";
			}
			std::cout << " " << memOp << std::endl;

			// std::cout << "EA calc: " << displacement << ", " << str2xed_reg_enum_t((REG_StringShort(indexReg)).c_str());
			std::cout << "EA calc: " << displacement << ", " << REG_StringShort(indexReg);
			std::cout << ", " << REG_StringShort(baseReg) << ", " << scale << std::endl;
*/
/*			if (readFlag && writeFlag) { // optimization
				// call binary code here
				// continue;
			}*/

			if (readFlag) {
				if (addBinaryCodeToTC(ofir_instrumentations_addresses[0], asmFileSize,
					3, instructionAddr, memOp, 0, 0)) {
					return (-1);
				}
				++instrumentationAdded;
			}
			if (writeFlag) {
				if (addBinaryCodeToTC(ofir_instrumentations_addresses[0], asmFileSize,
					4, instructionAddr, memOp, instructionSize, 0)) {
					return (-1);
				}
				++instrumentationAdded;
			}
		}
	}
	
	return instrumentationAdded;
}

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

    xed_uint64_t runtime_address = reinterpret_cast<xed_uint64_t>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
unsigned int dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);    
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);
  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return 0;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);
  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;   

  return xed_decoded_inst_get_length (&new_xedd);
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

int add_new_call_entry(xed_decoded_inst_t *xedd, unsigned int size, ADDRINT funcAddress) {
	ADDRINT orig_targ_addr = funcAddress;

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = (-1);
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].new_targ_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);
    instr_map[num_of_instr_map_entries].call_imm = true;

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

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, int corr_required = false) {
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
    instr_map[num_of_instr_map_entries].call_imm = false;

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

int encodeBinaryMovInstructionAux(UINT8* encoded_bytes, int arg_index, UINT64 imm, bool use_rax = false) {
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	xed_encoder_instruction_t  enc_instr;
	unsigned olen = 0;
	const unsigned ilen = XED_MAX_INSTRUCTION_BYTES;

	xed_encoder_operand_t xed_e_oper;
	switch(arg_index) {
		case 1: xed_e_oper = xed_reg(XED_REG_RDI); break;
		case 2: xed_e_oper = xed_reg(XED_REG_RSI); break;
		case 3: xed_e_oper = xed_reg(XED_REG_RDX); break;
		case 4: xed_e_oper = xed_reg(XED_REG_RCX); break;
		default: xed_e_oper = xed_reg(XED_REG_RAX);
	}

	if (!use_rax) {
		xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_e_oper, xed_imm0(imm, 64));
	} else {
		xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_e_oper, xed_reg(XED_REG_RAX));
	}	

	xed_encoder_request_t enc_req;
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_bytes), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;;
	}
/*
	std::cout << "**Encoded MOV: " << std::endl;
	dump_instr_from_mem((ADDRINT*)encoded_bytes, 0);
*/
	return 0;
}

int encodeBinaryMovInstruction(int arg_index, UINT64 imm, int correctionFlag = 0) {
	char encoded[XED_MAX_INSTRUCTION_BYTES];
	encodeBinaryMovInstructionAux((UINT8*)encoded, arg_index, imm, (correctionFlag == 2));

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

	if (xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded), max_inst_len) != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << encoded << endl;
		return 1;
	}

	int size = xed_decoded_inst_get_length (&xedd);
	return (add_new_instr_entry(&xedd, -1, size, correctionFlag) < 0) ? 1:0;
}

int addBinaryCodeToTC(ADDRINT mmap_addr, int codeSize, int funcIndex, UINT64 val1, UINT64 val2, UINT64 val3, UINT64 val4) {
	int size = 0;
	ADDRINT funcAddress = (ADDRINT)(ofir_instrumentations_addresses[funcIndex]);

	for(ADDRINT currentAddress=mmap_addr; (signed)(currentAddress-mmap_addr)<codeSize; currentAddress+=size) {
		int rc = 0;
		xed_decoded_inst_t xedd;

		xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

		xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(currentAddress), max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << currentAddress << endl;
			return 1;
		}

		if ((xed_decoded_inst_get_iclass(&xedd) == XED_ICLASS_CALL_NEAR) && (xed_decoded_inst_get_branch_displacement(&xedd) == (-5))) {
			switch(funcIndex) {
				case 1:
				case 2:
					rc = encodeBinaryMovInstruction(1, val1);
					if (rc != 0) {return rc;}
					rc = encodeBinaryMovInstruction(2, val2);
					if (rc != 0) {return rc;}
					rc = encodeBinaryMovInstruction(3, val3); // instruction ptr
					if (rc != 0) {return rc;}
					rc = encodeBinaryMovInstruction(4, val4);
					if (rc != 0) {return rc;}
					break;
				case 3:
				case 4:
					rc = encodeBinaryMovInstruction(1, val1); // instruction ptr
					if (rc != 0) {return rc;}
					rc = encodeBinaryMovInstruction(2, val2, 2); // instruction memop ea
					if (rc != 0) {return rc;}
					rc = encodeBinaryMovInstruction(3, val3);
					if (rc != 0) {return rc;}
					break;
			}
		}

		xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(currentAddress), max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << currentAddress << endl;
			return 1;
		}

		xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(currentAddress), max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << currentAddress << endl;
			return 1;
		}

		size = xed_decoded_inst_get_length (&xedd);

		if ((xed_decoded_inst_get_iclass(&xedd) == XED_ICLASS_CALL_NEAR) && (xed_decoded_inst_get_branch_displacement(&xedd) == (-5))) {
			rc = add_new_call_entry(&xedd, size, funcAddress);
		} else if ((xed_decoded_inst_get_iclass(&xedd) == XED_ICLASS_CALL_NEAR) && (xed_decoded_inst_get_branch_displacement(&xedd) == 0)) {
			rc = add_new_call_entry(&xedd, size, 0);
		} else {
			rc = add_new_instr_entry(&xedd, -1, size);
		}
		if (rc < 0) {
			std::cerr << "ERROR: failed during instructon translation in addBinaryCodeToTC()." << endl;
			std::cerr << "Instruction index during error: 0x" << hex << num_of_instr_map_entries << std::endl;
			return 1;
		}
	}

	return 0;
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

	xed_int64_t new_disp = (xed_int64_t)instr_map[instr_map_entry].orig_targ_addr - 
		                   (xed_int64_t)instr_map[instr_map_entry].new_ins_addr - 
					       xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL) {
		if (instr_map[instr_map_entry].call_imm) {
			if (instr_map[instr_map_entry].orig_targ_addr == 0) {
				xed_inst1(&enc_instr, dstate, 
				XED_ICLASS_CALL_NEAR, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(0, 32), 64));
			} else {
				xed_inst1(&enc_instr, dstate, XED_ICLASS_CALL_NEAR, 64, xed_relbr(new_disp, 32));
			}
			// std::cerr << "Call IMM's displacement: " << new_disp << std::endl;
			// dump_instr_map_entry(instr_map_entry);
		} else {
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));
		}
	}

	if (category_enum == XED_CATEGORY_UNCOND_BR) {
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));
	}


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
		new_disp = (xed_int64_t)instr_map[instr_map_entry].orig_targ_addr - 
	               (xed_int64_t)instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL) {
			if (instr_map[instr_map_entry].call_imm) {
				if (instr_map[instr_map_entry].orig_targ_addr == 0) {
					xed_inst1(&enc_instr, dstate, 
					XED_ICLASS_CALL_NEAR, 64,
					xed_mem_bd (XED_REG_RIP, xed_disp(0, 32), 64));
				} else {
					xed_inst1(&enc_instr, dstate, XED_ICLASS_CALL_NEAR, 64, xed_relbr(new_disp, 32));
				}
			} else {
				xed_inst1(&enc_instr, dstate, 
				XED_ICLASS_CALL_NEAR, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));
			}
		}

		if (category_enum == XED_CATEGORY_UNCOND_BR) {
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));
		}

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
int fix_direct_br_call_displacement(int instr_map_entry) {
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
	xed_encoder_request_set_branch_displacement(&xedd, new_disp, new_disp_byts);
	
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
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {	

			if (rtn == RTN_Invalid() /*|| RTN_Size(rtn) < MAX_PROBE_JUMP_INSTR_BYTES */) {
			  cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
  			  continue;
			}

			translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);			
			translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;
			translated_rtn[translated_rtn_num].isProbed = false;

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
			
				if (RTN_Size(rtn) < MAX_PROBE_JUMP_INSTR_BYTES) {
					//cerr << "Warning: Routine " << RTN_Name(rtn) << " too short for instrumentation" << endl;
					translated_rtn[translated_rtn_num].isSafeForReplacedProbe = false;
				}

				// Check for direct jumps/calls to the header of the routine:		
				if (INS_IsDirectBranchOrCall(ins)) {
					ADDRINT tgt = INS_DirectBranchOrCallTargetAddress(ins);
					if (tgt > RTN_Address(rtn) && tgt < RTN_Address(rtn) + MAX_PROBE_JUMP_INSTR_BYTES) {
						//cerr << "Warning: Routine " << RTN_Name(rtn) << " contains non-instrumentable jump at 0x" << hex << INS_Address(ins) << endl;
						translated_rtn[translated_rtn_num].isSafeForReplacedProbe = false;
					}
				}			

				if (addAssemblyCode(ins) < 0) {
					return 1;
				}

			    xed_decoded_inst_t xedd;
			    xed_error_enum_t xed_code;							
	            
				xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

				xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
				if (xed_code != XED_ERROR_NONE) {
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
					RTN_Close( rtn );
					return 1;
				}


				// Add instr into instr map:
				rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					std::cerr << "Instruction index during error: 0x" << hex << num_of_instr_map_entries << std::endl;
					RTN_Close( rtn );
					return 1;
				}
			} // end for INS...


			// debug print of routine name:
			if (KnobVerbose) {
				cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
			}			

			// Close the RTN.
			RTN_Close( rtn );

			translated_rtn_num++;

		 } // end for RTN..
	} // end for SEC...


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


/***************************/
/* void safe_code_update() */
/***************************/
int safe_code_update(ADDRINT addr, char *bytes, unsigned int size, int is_code_write_protected)
{

	if (is_code_write_protected) {
		char *buffer = (char *)(addr & (0xFFFFFFFFFFFFF000));                    
		int rc = mprotect ((void *)buffer, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
		if (rc < 0) {
			perror ("mprotect");
			return -1;
		}
		
		// check if the instr crosses a page:
		if (((addr + size) & 0x00000000000F000) != (addr & 0x00000000000F000)) {
			//cerr << "found page crossing at 0x:" << hex << addr << endl;
			char *buffer = (char *)((addr + size)& (0xFFFFFFFFFFFFF000));
			int rc = mprotect ((void *)buffer, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
			if (rc < 0) {
				perror ("mprotect");
				return -1;
			}
		}
	}

	if (size <= 8)  { // update can be done with a single atomic store instr:
		memcpy((char *)addr, (char *)bytes, size);
		asm volatile("mfence");	
		return 0;
	}

	//1st stage: insert jmp to itself.
	*(ADDRINT *)addr = JMP_TO_ITSELF_OFFFSET_OPCODE;
	asm volatile("mfence");	

	//2nd stage: restore the rest of the bytes after the 1st 8 bytes:
    memcpy((char *)(addr + SIZE_OF_JMP_TO_ITSELF_OPCODE),   
		   (char *)(bytes + SIZE_OF_JMP_TO_ITSELF_OPCODE), 
		   size - SIZE_OF_JMP_TO_ITSELF_OPCODE);
	asm volatile("mfence");	

	//3rd stage: restore the 1st 8 bytes from original code from the probing code:
    memcpy((char *)addr, (char *)bytes, SIZE_OF_JMP_TO_ITSELF_OPCODE);
	asm volatile("mfence");	

	return 0;
}		


/***************************/
/* int insert_probe_jump() */
/***************************/
int insert_probe_jump(ADDRINT from_addr, ADDRINT to_addr, int is_code_write_protected)
{
	// insert a probe of indirect jump from from_addr to to_addr.
	// The probe jump includes 2 parts:
	// 1. the instruction: jmp [rip]
	// 2. the target address placed immediately adfter the above jmp [rip] instr.	

	unsigned int olen = 0;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;

	xed_encoder_instruction_t  enc_instr;

	// jmp [rip] (the target address is placed immediately after the instr).
	xed_inst1(&enc_instr, dstate, 
				XED_ICLASS_JMP, 64,
				xed_mem_bd (XED_REG_RIP, xed_disp(0, 32), 64));

	xed_encoder_request_t enc_req;
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}

	char encoded_jump_bytes[MAX_PROBE_JUMP_INSTR_BYTES];
	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_jump_bytes), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;;
	}

	if (olen != SIZE_OF_JMP_RIP_INSTR) { 
		cerr << "invalid indirect probe jump" << endl;
		return -1;
	}

	if (KnobVerbose) {
		cerr << "Jump to translated routine: ";
		dump_instr_from_mem ((ADDRINT *)encoded_jump_bytes, from_addr);			
	}

	// Modify the code with the indirect jump probe followed by target addr:
	*(ADDRINT *)(encoded_jump_bytes + olen) = to_addr;

	int rc = safe_code_update(from_addr, (char *)encoded_jump_bytes, 
							  MAX_PROBE_JUMP_INSTR_BYTES, is_code_write_protected);
	if (rc < 0)
		return -1;

	if (KnobVerbose) {
		cerr << "Code After probe: ";
		dump_instr_from_mem ((ADDRINT *)from_addr, from_addr);			
	}		

	return 0;
}


/***************************************/
/* void uncommit_translated_routines() */
/***************************************/
void uncommit_translated_routines() {
   // Uncommit all committed translated functions: 

	for (int i=0; i < translated_rtn_num; i++) {
	
		if (!translated_rtn[i].isProbed)
			continue;
		
		if (KnobVerbose) {
			cerr << "uncommit rtn: " << RTN_Name(RTN_FindByAddress(translated_rtn[i].rtn_addr)) << endl;
			cerr << "Target Code Before Uncommit: ";
			dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
		}

		// Restore the original non-probed code:
		int rc = safe_code_update(translated_rtn[i].rtn_addr, translated_rtn[i].orig_probed_mem, MAX_PROBE_JUMP_INSTR_BYTES, 1);		
		if (rc < 0)
			continue;

		//save the translated non-probed code before applying the probing jump backwards to orig code:
		ADDRINT translated_rtn_addr = instr_map[translated_rtn[i].instr_map_entry].new_ins_addr;
		memcpy((char *)translated_rtn[i].translated_probed_mem, 
			   (char *)translated_rtn_addr, 
			   MAX_PROBE_JUMP_INSTR_BYTES);
		
		if (KnobVerbose) {
			cerr << "Target Code After Uncommit: ";
			dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
		}

		if (KnobVerbose) {
			cerr << " from: 0x" << hex << translated_rtn_addr << " to: 0x" 
				 << hex << translated_rtn[i].rtn_addr << endl;
			cerr << "Code Before Probe: ";
			dump_instr_from_mem ((ADDRINT *)translated_rtn_addr, translated_rtn_addr);		
		}

		// insert a probe jump from translated rtn to original rtn:
		rc = insert_probe_jump(translated_rtn_addr, translated_rtn[i].rtn_addr, 0);
		if (rc < 0)
			continue; 			
	}

	asm volatile("mfence");	
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
void commit_translated_routines() {
   // Commit the translated functions: 
   // Go over the candidate functions and replace the original 
   // ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc

		if (translated_rtn[i].instr_map_entry < 0)
			continue;
				    
		if (translated_rtn[i].rtn_size <= MAX_PROBE_JUMP_INSTR_BYTES ||
			!translated_rtn[i].isSafeForReplacedProbe) 
			continue;

		RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);
		if (rtn == RTN_Invalid()) {
			cerr << "probing rtN: Unknown" << endl;
			continue;
		}

		if (RTN_Size(rtn) < MAX_PROBE_JUMP_INSTR_BYTES) // routine is too small for probing
			continue;
						
		if (!RTN_IsSafeForProbedReplacement(rtn))
			continue;

		if (strstr(RTN_Name(rtn).c_str(), "@plt"))
			continue;

		// do not probe the special _fini routine:
         if (RTN_Name(rtn) == string("_fini"))
			 continue;
		 		 
		 //make sure the 1st 5bytes of the rotuine do not cross a 32byte cache line boundary:
		 // (this is due to cache coherency issues when patching accross 32bytes aligned addresses)
		 if ((RTN_Address(rtn) & 0xff) >= 0xfc && (RTN_Address(rtn) & 0xff) <= 0xff) {
			continue;
		 }

		if (KnobVerbose) {
			cerr << "probing rtN: " << RTN_Name(rtn);
		    cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex 
				 << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;
		}

		if (KnobVerbose) {
			cerr << "Code Before probe: ";
			dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
		}
		

		ADDRINT translated_rtn_addr = instr_map[translated_rtn[i].instr_map_entry].new_ins_addr;

		if (translated_rtn[i].isProbed == true) {
			// Restore target code:
			int rc = safe_code_update(translated_rtn_addr, translated_rtn[i].translated_probed_mem, MAX_PROBE_JUMP_INSTR_BYTES, 0);
			if (rc < 0)
				continue;
		}

		//save the original non-probed code before applying the probing jump:
		memcpy((char *)translated_rtn[i].orig_probed_mem, (char *)translated_rtn[i].rtn_addr, MAX_PROBE_JUMP_INSTR_BYTES);

		// insert a probe jump from original rtn addr to translated rtn:
		int rc = insert_probe_jump(translated_rtn[i].rtn_addr, translated_rtn_addr, 1);
		if (rc < 0)
			continue; 			

		translated_rtn[i].isProbed = true;	   

	}
	asm volatile("mfence");	
}


/**********************************************/
/* void commit_uncommit_translated_routines() */
/**********************************************/
void commit_uncommit_translated_routines(void *v) 
{
    while (!enable_commit_uncommit_flag);
	asm volatile("mfence");	
	sleep(1);

	while (true) {
		cerr << "before commit translated routines" << endl;

		PIN_LockClient();
		commit_translated_routines();
		PIN_UnlockClient();

		cerr << "after commit translated routines" << endl;

		sleep(1);

		cerr << "before uncommit translated routines" << endl;

		PIN_LockClient();
		uncommit_translated_routines();
		PIN_UnlockClient();

		cerr << "after uncommit translated routines" << endl;

		sleep(1);
	}  
}


/****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
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
		}
	}

	max_ins_count *= 60;

	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}

	// Allocate memory for the array of candidate routines containing inlineable function calls:
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    tclen = 2 * text_size + pagesize * 4;   // TODO: need a better size estimate

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	//
	char * tc_addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) tc_addr == 0xffffffffffffffff) {
	   cerr << "failed to allocate a translation cache" << endl;
       return -1;
	}
	
    //ADDRINT highest_limit = (ADDRINT) (lowest_sec_addr + MAXINT);
    //ADDRINT init_hi_addr = (ADDRINT) (highest_sec_addr + 0x100000) & 0xfffffffffff00000;
    //char * tc_addr = NULL;
    //for (ADDRINT addr = init_hi_addr; addr < highest_limit; addr += 0x100000) {
    //    tc_addr = (char *) mmap((void *)addr, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    //    if ((ADDRINT) tc_addr != 0xffffffffffffffff)
    //            break;
    //}
	//if ((ADDRINT) tc_addr == 0xffffffffffffffff) {
	//   cerr << "failed to allocate a translation cache" << endl;
    //   return -1;
	//}


	// cerr << "tc addr: " << hex << (ADDRINT)tc_addr << endl; 

	tc = (char *)tc_addr;

	return 0;
}

/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v) {
	// debug print of all images' instructions
	//dump_all_image_instrs(img);

	mallocImage(img);

    // Step 0: Check that the image is of the main executable file:
	if (!IMG_IsMainExecutable(img)) {
		return;
	}

	int rc = 0;

	// step 1: Check size of executable sections and allocate required memory:	
	rc = allocate_and_init_memory(img);
	if (rc < 0) {
		return;
	}

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

	// Step 6: Enable the Commit-Uncommit thread to start 
    //         applyng the commit-uncommit routines alternatingly:
    asm volatile("mfence");	
    // enable_commit_uncommit_flag = true;
    commit_translated_routines();
	asm volatile("mfence");
}

void stub(UINT64 x, UINT64 y) {
	std::cout << "*****stub(" << x << ", " << y << ") is called********" << std::endl;
}

void setOfirRoutineAddresses(std::vector<ADDRINT>& addresses) {
	addresses.push_back((ADDRINT)(&CheckAddIns)); // 2nd element
	addresses.push_back((ADDRINT)(&CheckAddInsIndexReg));
	
	addresses.push_back((ADDRINT)(&RecordMemRead));
	addresses.push_back((ADDRINT)(&RecordMemWrite));

	addresses.push_back((ADDRINT)(&stub)); // 6th element
	// std::cout << "Stub() address is: 0x" << hex << (ADDRINT)(stub) << std::endl;
}

int get_file_size(std::string filename) // path to file
{
    FILE *p_file = NULL;
    p_file = fopen(filename.c_str(),"rb");
    fseek(p_file,0,SEEK_END);
    int size = ftell(p_file);
    fclose(p_file);
    return size;
}


int allocate_asm_to_mem(const std::string& filename) {
	asmFileSize = get_file_size(filename.c_str());

	int fd = open(filename.c_str(), O_RDONLY);
	if (fd < 0) {
		std::cerr << "Failed to open file" << std::endl;
		return 1;
	}

	char * addr = (char*) mmap(NULL, asmFileSize,
		PROT_READ, MAP_PRIVATE,
		fd, 0);
	
	if (((long long)addr == (-1))) {
		std::cerr << "Failed to allocate asm code" << std::endl;
	}/* else {
		std::cerr << "mmap allocated at : 0x" << hex <<(long long)addr << " size " << asmFileSize << std::endl;
	}*/

	close(fd);

	ofir_instrumentations_addresses.push_back((ADDRINT)addr);

	return 0;
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	allocate_asm_to_mem(binaryFilename);
	setOfirRoutineAddresses(ofir_instrumentations_addresses);

    // Initialize pin & symbol manager
    //out = new std::ofstream("xed-print.out");

    if( PIN_Init(argc,argv) )
        return Usage();

    PIN_InitSymbols();	
	// Register ImageLoad
	IMG_AddInstrumentFunction(ImageLoad, 0);

    /* It is safe to create internal threads in the tool's main procedure and spawn new
     * internal threads from existing ones. All other places, like Pin callbacks and 
     * analysis routines in application threads, are not safe for creating internal threads.
    */
    THREADID tid = PIN_SpawnInternalThread(commit_uncommit_translated_routines, NULL, 0, NULL);
    if (tid == INVALID_THREADID) {
		cerr << "failed to spawn a thread for commit" << endl;
    }

    // Start the program, never returns
    PIN_StartProgramProbed();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

