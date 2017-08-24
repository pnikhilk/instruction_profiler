#include <iostream>
#include <fstream>
#include "pin.H"

#define MAX_INS 1000

struct InsProfile
{
    UINT32 op;
    string ins;
    UINT64 count;
};

struct THREAD_DATA
{
    UINT64 depth;
};

ofstream OutFile;
static UINT64 insCount = 0;
static UINT64 bbCount = 0;
static UINT64 funCount = 0;
static UINT64 total = 0;
static THREADID maxDepth_tid;
static UINT64 maxDepth = 0;
static TLS_KEY tls_key;
struct InsProfile insProfile[MAX_INS];

//Get Thread Local Storage
THREAD_DATA *get_tls(THREADID threadid)
{
    THREAD_DATA* tdata = static_cast<THREAD_DATA*>(PIN_GetThreadData(tls_key,       threadid));
    return tdata;
}

//Start function of thread
VOID ThreadStart(THREADID tid, CONTEXT *context, INT32 flags, VOID *v)
{
    THREAD_DATA *tdata = new THREAD_DATA();
    PIN_SetThreadData(tls_key, tdata, tid);
    cerr << "Thread " << decstr(tid) << " start" << endl;
}

//Call function
VOID dopush(ADDRINT ret_addr, THREADID tid)
{
    funCount++;
    THREAD_DATA *tdata = get_tls(tid);
    tdata->depth++;    
}

//Return function
VOID dopop(ADDRINT target_addr, THREADID tid)
{ 
    THREAD_DATA *tdata = get_tls(tid);
    if(maxDepth < tdata->depth)
    {
	maxDepth = tdata->depth;
	maxDepth_tid = tid;
    }
    tdata->depth--;
}
    
//Increment number of instructions and basic blocks
VOID PIN_FAST_ANALYSIS_CALL DoCount(UINT32 icount) {
	insCount += icount;
	bbCount++;
}

//Get instruction profile
VOID PIN_FAST_ANALYSIS_CALL getInsProfile(UINT32 index){
    for(UINT32 i = 0; i < total; i++){
	if(insProfile[i].op == index){
	    insProfile[i].count++;
	    return;
	}
    }
    insProfile[total].op = index;
    insProfile[total].ins = OPCODE_StringShort(index);
    insProfile[total].count = 1;
    total++;
}

VOID CustomInstrument(TRACE trace, VOID *v){
	//Iterate over each Basic block
    for(BBL bb = TRACE_BblHead(trace); BBL_Valid(bb); bb = BBL_Next(bb)){
	//Insert call to count no. of instructions and basic block
	BBL_InsertCall(bb, IPOINT_BEFORE, (AFUNPTR)DoCount, IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns(bb), IARG_END);
	
	for(INS ins = BBL_InsHead(bb); INS_Valid(ins); ins = INS_Next(ins)){
	    //Insert call to get instruction profile
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getInsProfile, IARG_FAST_ANALYSIS_CALL, IARG_UINT32, INS_Opcode(ins), IARG_END);
    	    if (INS_IsCall(ins))
    	    {
		//If instruction is call instruction, increment depth
    		INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)dopush, IARG_RETURN_IP, IARG_THREAD_ID, IARG_END);
    	    }
    	    else if (INS_IsRet(ins))
    	    {
		//If instruction is return instruction, decrement depth
    		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dopop, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);
      	    }
	}
    }
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    cerr << "Thread " << decstr(threadIndex) << " exit" << endl;
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "assgn3.out", "specify output file name");

VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Total number of instructions executed: " << insCount << endl;
    OutFile << "Total number of basic blocks executed: " << bbCount << endl;
    OutFile << "Total number of functions executed: " << funCount << endl;
    OutFile << "Max depth: " << maxDepth << endl;
    OutFile << "Max_depth Thread id: " << maxDepth_tid << endl;
    OutFile << "Instruction Profile: " << endl;
    for(UINT32 i = 0; i < total; i++){
	OutFile << insProfile[i].ins << " : " << insProfile[i].count << endl;
    }
    OutFile.close();
}

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char *argv[])
{   
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    //Get key for TLS storage
    tls_key = PIN_CreateThreadDataKey(NULL);
    if(tls_key == -1)
    {
	PIN_ExitProcess(1);
    }

    //Register function for thread start
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    //Register function for thread finish
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    //Add instrumentation
    TRACE_AddInstrumentFunction(CustomInstrument, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
