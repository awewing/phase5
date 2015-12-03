/*
 * vm.h
 */


/*
 * All processes use the same tag.
 */
#define TAG 0

/*
 * Different states for a page.
 */
#define UNUSED 500
#define INCORE 501

/* You'll probably want more states */
#define OPEN -1
#define CLOSED 1

/*
 * Page table entry.
 */
typedef struct PTE {
    int  memState;   // See above.
    int  diskState;  
    int  frame;      // Frame that stores the page (if any). -1 if none.
    int  diskBlock;  // Disk block that stores the page (if any). -1 if none.
    int  semaphore;
    // Add more stuff here
} PTE;

/*
 * Per-process information.
 */
typedef struct Process {
    int  numPages;   // Size of the page table.
    PTE  *pageTable; // The page table for the process.
    // Add more stuff here */
} Process;

/*
 * Information about page faults. This message is sent by the faulting
 * process to the pager to request that the fault be handled.
 */
typedef struct FaultMsg {
    int  pid;        // Process with the problem.
    void *addr;      // Address that caused the fault.
    int  replyMbox;  // Mailbox to send reply.
    // Add more stuff here.
} FaultMsg;

/* 
 * Frame table entry 
 */
typedef struct FTE {
    int state;
    int pid;
    int page;
} FTE;

/* 
 * Block table
 */
typedef struct Block Block;
struct Block {
	int blockNum;
	int track;
	int sector;
	Block *nextBlock;
};

#define CheckMode() assert(USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE)
