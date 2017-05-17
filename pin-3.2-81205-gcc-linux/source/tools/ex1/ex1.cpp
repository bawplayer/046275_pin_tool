//Oren Kaikov, 037832292
/*This tool counts the number of times a routine is executed and the number of instructions executed in a routine.
this is based on the original proccount sample provided by pin tool.
I modified proccount by sorting the output and aggragating the instruction count of all the functions with the same name.
we still use proccount original linked list data structure to contain all the routins information, since the assumption that there are less then 1K rtns is valid for rtns that run more then 1 instructions.
since there are rtns with the same name but with diffrent image, they are counted seperatly.
the desired output doesn't distinguish between images, so I aggragated all the instruction count of all the rtns with the same name (even though they have a diffrent image.) 
also removed redundent code.
*/

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"

ofstream outFile;

// Holds instruction count for a single procedure
typedef struct RtnCount
{
    string _name;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount * _next;
} RTN_COUNT;

// Linked list of instruction counts for each routine
RTN_COUNT * RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64 * counter)
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

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v)
{
    
    // Allocate a counter for this routine
    RTN_COUNT * rc = new RTN_COUNT;

    // The RTN goes away when the image is unloaded, so save it now
    // because we need it in the fini
    rc->_name = RTN_Name(rtn);
    rc->_icount = 0;
    rc->_rtnCount = 0;

    // Add to list of routines
    rc->_next = RtnList;
    RtnList = rc;
            
    RTN_Open(rtn);
            
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
    
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    }

    RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v)
{
    RTN_COUNT rtn_array[1000];
    int index_top = 0;
    bool break_flag;  
    
    // we convert the linked list to an array
    for (RTN_COUNT * rc = RtnList; rc; rc = rc->_next)
    {
        break_flag = false;
        if (rc->_icount > 0)
        {

            // if we have the more then one rtn with the same name we do not create a new item, but add the icount to the original.
            for(int i=0; i<index_top; i++)
            {
                if (rc->_name == rtn_array[i]._name)
                {
                    rtn_array[i]._icount += rc->_icount;
                    break_flag = true;
                    break;
                }
            }

            if(break_flag == true) continue;
            rtn_array[index_top++] = *rc;
            if (index_top==1000) break; //never happens, just a fail-safe mechanisem.
        }
    }

    // sort the array (bubble sort)
    RTN_COUNT tmp;
    for(int i=0;i<index_top;i++)
     {
           for(int j=0;j<index_top-i;j++)
           {
                 if(rtn_array[j]._icount<rtn_array[j+1]._icount)
                 {
                       tmp=rtn_array[j+1];
                       rtn_array[j+1]=rtn_array[j];
                       rtn_array[j]=tmp;
                 }
           }
     }

    // print the sorted output
    for (int i=0; i<index_top; i++)
    {
            outFile << rtn_array[i]._name << " icount: "
                  <<rtn_array[i]._icount << endl;
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

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
