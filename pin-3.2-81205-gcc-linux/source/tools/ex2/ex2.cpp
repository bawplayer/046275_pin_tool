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

/*
typedef struct EdgeStruct
{
    ADDRINT _source_address;
    ADDRINT _dest_address;
    BBL_OBJECT _source_bbl;
    BBL_OBJECT _dest_bbl;
    UINT64 _count;
    struct EdgeStruct* _next;
} EDGE_OBJECT;
EDGE_OBJECT* EdgeList = 0; // Linked list of edge objects
*/



class COUNTER
{
  public:
    UINT64 _count;       // number of times the edge was traversed

    COUNTER() : _count(0)   {}
};

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
}ETYPE;

class EDGE
{
  public:
    ADDRINT _src;
    ADDRINT _dst;
    ADDRINT _next_ins;
    ETYPE   _type; // must be integer to make stl happy

    EDGE(ADDRINT s, ADDRINT d, ADDRINT n, ETYPE t) :
        _src(s),_dst(d), _next_ins(n),_type(t)  {}

    bool operator <(const EDGE& edge) const
    {
        return _src < edge._src || (_src == edge._src && _dst < edge._dst);
    }
};
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
typedef map< EDGE, COUNTER*> EDG_HASH_SET;
static EDG_HASH_SET EdgeSet;
static COUNTER * Lookup( EDGE edge)
{
    COUNTER *& ref =   EdgeSet[ edge ];

    if( ref == 0 )
    {
        ref = new COUNTER();
    }

    return ref;
}





typedef struct BblStruct
{
    ADDRINT _start_address;
    ADDRINT _end_address;
    struct BblStruct* _next;
} BBL_OBJECT;
BBL_OBJECT* BblList = 0; // Linked list of bbl objects

typedef struct RtnStruct
{
    string _name;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
//    EDGE_OBJECT* _edge_list_ptr;
//    EDG_HASH_SET EdgeSet;
    BBL_OBJECT* _bbl_list_ptr;
    struct RtnStruct* _next;
} RTN_OBJECT;
// Linked list of rtn objects
RTN_OBJECT* RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64 * counter)
{
    (*counter)++;
}

VOID edgecount( COUNTER *pedg )
{
    pedg->_count++;
}
    
const char * StripPath(const char * path)
{
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
}


VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_OBJECT* bbl_obj = new BBL_OBJECT;
        bbl_obj->_start_address = BBL_Address(bbl);
        bbl_obj->_end_address = bbl_obj->_start_address + BBL_Size(bbl);
        
        // Add bbl_obj to list of bbl's
        bbl_obj->_next = BblList;
        BblList = bbl_obj;
     }
}



// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v)
{
    
    // Allocate a routine object
    RTN_OBJECT* rtn_obj = new RTN_OBJECT;

    // The RTN goes away when the image is unloaded, so save it now because we need it in the fini
    rtn_obj->_name = RTN_Name(rtn);
    rtn_obj->_address = RTN_Address(rtn);
    rtn_obj->_rtn = rtn;
    rtn_obj->_rtnCount = 0;
    rtn_obj->_icount = 0;
//    rtn_obj->_edge_list_ptr = NULL;
    rtn_obj->_bbl_list_ptr = NULL;

    // Add rtn_obj to list of routines
    rtn_obj->_next = RtnList;
    RtnList = rtn_obj;
            
    RTN_Open(rtn);
            
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rtn_obj->_rtnCount), IARG_END);
    
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rtn_obj->_icount), IARG_END);

        // count the edges ((indirect)
        if (INS_IsDirectBranchOrCall(ins))
        {
            ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH;
    
            // static targets can map here once
            COUNTER *pedg = Lookup( EDGE(INS_Address(ins),  INS_DirectBranchOrCallTargetAddress(ins), INS_NextAddress(ins), type) );
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR) edgecount, IARG_ADDRINT, pedg, IARG_END);
        }
    }

    RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v)
{
    // ***rtn code***
    RTN_OBJECT rtn_array[1000];
    int index_top = 0;
    bool break_flag;  
    
    // we convert the linked list to an array
    for (RTN_OBJECT* rtn_obj = RtnList; rtn_obj; rtn_obj = rtn_obj->_next)
    {
        break_flag = false;
        if (rtn_obj->_icount > 0)
        {

            // if we have the more then one rtn with the same name we do not create a new item, but add the icount to the original.
            for(int i=0; i<index_top; i++)
            {
                if (rtn_obj->_name == rtn_array[i]._name)
                {
                    rtn_array[i]._icount += rtn_obj->_icount;
                    break_flag = true;
                    break;
                }
            }

            if(break_flag == true) continue;
            rtn_array[index_top++] = *rtn_obj;
            if (index_top==1000) break; //never happens, just a fail-safe mechanisem.
        }
    }

    // sort the array (bubble sort)
    RTN_OBJECT tmp;
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

    // ***bbl code***
    BBL_OBJECT bbl_array[10000];
    int bbl_index_top = 0;
    for (BBL_OBJECT* bbl_obj = BblList; bbl_obj; bbl_obj = bbl_obj->_next)
    {
        bbl_array[bbl_index_top++] = *bbl_obj;
        if (bbl_index_top==10000) break; //never happens, just a fail-safe mechanisem.
    }    



    // print the sorted output
    for (int i=0; i<index_top; i++)
    {
        outFile << rtn_array[i]._name << " at: 0x" << hex << rtn_array[i]._address << dec << " icount: " <<rtn_array[i]._icount << endl;
    }
    for (int j=0; j<bbl_index_top; j++)
    {
        outFile << "BB" << j <<": 0x" << hex << bbl_array[j]._start_address << " - 0x" << bbl_array[j]._end_address << dec << endl;
    }

    int i=0;
    for( EDG_HASH_SET::const_iterator it = EdgeSet.begin(); it !=  EdgeSet.end(); it++, i++ )
    {
        const pair<EDGE, COUNTER*> tuple = *it;


        if( tuple.second->_count == 0 ) continue;

        string rtn_name = RTN_FindNameByAddress(tuple.first._src+10); 	

        outFile << "source rtn name is " << rtn_name <<  endl;
        outFile << "Edge" << i << ": " << StringFromAddrint( tuple.first._src)  << " -> " << StringFromAddrint(tuple.first._dst) << " " << decstr(tuple.second->_count,12) << " " << endl;

    }

    ADDRINT x = 0x409c33;
    string rtn_name = RTN_Name(RTN_FindByAddress(x));
    outFile << "x=  " << x << "rtn name = " << rtn_name <<  endl;

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