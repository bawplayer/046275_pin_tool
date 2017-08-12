#include "pin.H"
#include <iostream>
#include <fstream>
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

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "malloctrace.out", "specify trace file name");

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
 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
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

// Print a memory read record
VOID RecordMemRead(VOID * ip, ADDRINT addr)
{
	if (!IsCalledAfterMain())
		return;
	
	if (suspiciousAddresses.count((ADDRINT)ip) !=0)
		cout << "Memory read overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, ADDRINT addr)
{
	if (!IsCalledAfterMain())
		return;
	
	if (suspiciousAddresses.count((ADDRINT)ip) !=0)
		cout << "Memory write overflow at address: 0x" << hex << (ADDRINT)ip << dec << endl;
}

VOID CheckAddIns(ADDRINT regVal, UINT64 immediate, VOID* ip, UINT64 insSize)
{
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
	if (!mallocTracer.IsAllocatedAddress(regVal))
		return;
		
	if (mallocTracer.GetStartAddress(regVal + indexRegVal) != mallocTracer.GetStartAddress(regVal))
		suspiciousAddresses.insert(ADDRINT(ip) + insSize);
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
   
VOID Image(IMG img, VOID *v)
{
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    //
    //  Find the malloc() function.
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
                       
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free()
        RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)AfterFree,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
    
    RTN mainRtn = RTN_FindByName(img, MAIN);
	if (RTN_Valid(mainRtn))
	{
		RTN_Open(mainRtn);
		
		RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)mainBefore, IARG_END);
		
		RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)mainAfter, IARG_END);
		
		RTN_Close(mainRtn);
	}
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v)
{
    RTN_Open(rtn);
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
		if (INS_IsAdd(ins))
		{
			UINT32 opNum = INS_OperandCount(ins);
			UINT64 immediate = 0;
			REG operandReg = REG_INVALID();
			REG indexReg = REG_INVALID();
			bool foundReg = false;
			bool foundIndexReg = false;
			bool foundImm = false;

			for (UINT32 i = 0; i < opNum; ++i)
			{
				if (!foundImm && INS_OperandIsImmediate(ins, i))
				{
					immediate = INS_OperandImmediate(ins, i);
					foundImm = true;
				}
				
				else if (!foundReg && INS_OperandIsReg(ins, i) && INS_OperandWritten(ins, i))
				{
					operandReg = INS_OperandReg(ins, i);
					if (REG_INVALID() != operandReg )
						foundReg = true;
				}
				
				else if (!foundIndexReg && INS_OperandIsReg(ins, i) && INS_OperandReadOnly(ins, i))
				{
					indexReg = INS_OperandReg(ins, i);
					if (REG_INVALID() != indexReg)
						foundIndexReg = true;
				}

				if (foundReg && foundImm && REG_valid_for_iarg_reg_value(operandReg))
				{
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddIns, 
						IARG_REG_VALUE, operandReg, IARG_UINT64, immediate,
						IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
					break;
				}
				
				else if (foundIndexReg && foundReg && REG_valid_for_iarg_reg_value(operandReg)
					&& REG_valid_for_iarg_reg_value(indexReg))
				{
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAddInsIndexReg, 
						IARG_REG_VALUE, operandReg, IARG_REG_VALUE, indexReg,
						IARG_INST_PTR, IARG_UINT64, INS_Size(ins), IARG_END);
					break;
				}
			}
		} 
		else 
		{
			UINT32 memOperands = INS_MemoryOperandCount(ins);

			// Iterate over each memory operand of the instruction.
			for (UINT32 memOp = 0; memOp < memOperands; memOp++)
			{
				if (INS_MemoryOperandIsRead(ins, memOp))
				{
					 INS_InsertCall(
						ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
						IARG_INST_PTR,
						IARG_MEMORYOP_EA, memOp,
						IARG_END);
				}
				// Note that in some architectures a single memory operand can be 
				// both read and written (for instance incl (%eax) on IA-32)
				// In that case we instrument it once for read and once for write.
				if (INS_MemoryOperandIsWritten(ins, memOp))
				{

					 INS_InsertCall(
						ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
						IARG_INST_PTR,
						IARG_MEMORYOP_EA, memOp,
						IARG_UINT64, INS_Size(ins),
						IARG_END);
				}
			}
		}
    }
    RTN_Close(rtn);
}

/* ===================================================================== */


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);
    RTN_AddInstrumentFunction(Routine, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
