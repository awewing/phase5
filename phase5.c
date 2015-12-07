#include <assert.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <phase4.h>
#include <phase5.h>
#include <usyscall.h>
#include <libuser.h>
#include <vm.h>
#include <provided_prototypes.h>
#include <string.h>

/*
 * phase5.c
 *
 * Date: 11/23/15
 * Authors: Alex Ewing, Andre Takagi
 */

/******************** Globals ********************/
int debugflag5 = 1;

int vmOn = 0; // if the vm has already been started

// counters
int numPages = 0;
int numFrames = 0;
int numPagers = 0;
int diskBlocks;
int nextBlock = 0;

int faultBox; // fault Mailbox for pagers

int pagerPids[MAXPAGERS];
Process procTable[MAXPROC];
FTE *frameTable;
int *blockTable;
int lastFrameIndex = 0;

int frameSem;
int statSem;

void *vmRegion;

// swap disk info
int diskUnit;
int diskUnitSectorSize;
int diskUnitTrackSize;
int diskUnitSize;

VmStats  vmStats;
FaultMsg faults[MAXPROC]; /* Note that a process can have only
                           * one fault at a time, so we can
                           * allocate the messages statically
                           * and index them by pid. */

/******************** Function Prototypes ********************/
static int Pager(char *buf);
static void FaultHandler(int dev, void *arg); // different in skeleton, not sure which is correct
void *vmInitReal(int mappings, int pages, int frames, int pagers);
void vmDestroyReal(void);
void PrintStats(void);

static void mboxCreate(systemArgs *args);
static void mboxRelease(systemArgs *args);
static void mboxSend(systemArgs *args);
static void mboxReceive(systemArgs *args);
static void mboxCondSend(systemArgs *args);
static void mboxCondReceive(systemArgs *args);
static void vmInit(systemArgs *args);
static void vmDestroy(systemArgs *args);
void setUserMode();
/*
 *----------------------------------------------------------------------
 *
 * start4 --
 *
 * Initializes the VM system call handlers. 
 *
 * Results:
 *      MMU return status
 *
 * Side effects:
 *      The MMU is initialized.
 *
 *----------------------------------------------------------------------
 */
int start4(char *arg) {
    int pid;
    int result;
    int status;

    /* to get user-process access to mailbox functions */
    systemCallVec[SYS_MBOXCREATE]      = mboxCreate;
    systemCallVec[SYS_MBOXRELEASE]     = mboxRelease;
    systemCallVec[SYS_MBOXSEND]        = mboxSend;
    systemCallVec[SYS_MBOXRECEIVE]     = mboxReceive;
    systemCallVec[SYS_MBOXCONDSEND]    = mboxCondSend;
    systemCallVec[SYS_MBOXCONDRECEIVE] = mboxCondReceive;

    // calculate diskblock stuff
    int sector;
    int track;
    int disk;
    DiskSize(1, &sector, &track, &disk);

    diskUnit = 1;
    diskUnitSectorSize = sector;
    diskUnitTrackSize = track;
    diskUnitSize = disk;

    if (debugflag5) {
        USLOSS_Console("start4(): disksize:\n\tSector size is %d bytes\n\tTrack size is %d sectors\n\tdisk size is %d tracks\n", sector, track, disk);
    }

    diskBlocks = disk;
    blockTable = malloc(sizeof(int) * diskBlocks);
    for (int i = 0; i < diskBlocks; i++) {
        blockTable[i] = i * (sector * (track / 2));
    }

    /* user-process access to VM functions */
    systemCallVec[SYS_VMINIT]    = vmInit;
    systemCallVec[SYS_VMDESTROY] = vmDestroy;

    result = Spawn("Start5", start5, NULL, 8*USLOSS_MIN_STACK, 2, &pid);
    if (result != 0) {
        USLOSS_Console("start4(): Error spawning start5\n");
        Terminate(1);
    }
    result = Wait(&pid, &status);
    if (result != 0) {
        USLOSS_Console("start4(): Error waiting for start5\n");
        Terminate(1);
    }
    Terminate(0);
    return 0; // not reached

} /* start4 */

/*
 *----------------------------------------------------------------------
 *
 * vmInitReal --
 *
 * Called by vmInit.
 * Initializes the VM system by configuring the MMU and setting
 * up the page tables.
 *
 * Results:
 *      Address of the VM region.
 *
 * Side effects:
 *      The MMU is initialized.
 *
 *----------------------------------------------------------------------
 */
void *vmInitReal(int mappings, int pages, int frames, int pagers) {
    if (debugflag5) {
        USLOSS_Console("process %d: vmInit real\n", getpid());
    }

    CheckMode();

    // check bad input
    if (mappings < 0 || pages < 0 || frames < 0 || pagers < 0 || pagers > MAXPAGERS) {
        return (void *) -1L;
    }

    // check for duplicate intialization
    if (vmOn == 1) {
        return (void *) -1L;
    }
    else {
        // set vmOn to true
        vmOn = 1;
    }

    // set global variables
    numPages = pages;
    numFrames = frames;
    numPagers = pagers;

    // create global sems
    frameSem = semcreateReal(1);
    statSem = semcreateReal(1);

    int status;
    int dummy;

    // start the vm
    status = USLOSS_MmuInit(mappings, pages, frames);
    if (status != USLOSS_MMU_OK) {
        USLOSS_Console("vmInitReal: couldn't init MMU, status %d\n", status);
        return (void *) -1L;
    }

    // set the inturrupt handler
    USLOSS_IntVec[USLOSS_MMU_INT] = FaultHandler;

    // set the region
    vmRegion = USLOSS_MmuRegion(&dummy);

    // initialize frame table
    frameTable = malloc(sizeof(FTE) * frames);
    for (int i = 0; i < frames; i++) {
        frameTable[i].state = OPEN;
        frameTable[i].pid = -1;
        frameTable[i].page = -1;
    }

    // Initialize page tables.
    for (int i = 0; i < MAXPROC; i++) {
    	procTable[i].numPages = 0; // pages
    	procTable[i].pageTable = NULL;
    }

    // Create the fault mailbox.
    faultBox = MboxCreate(MAXPROC, sizeof(FaultMsg));

    // Fork the pagers.
    for (int i = 0; i < pagers; i++) {
        char name[10];
        sprintf(name, "Pager %d", i);
        pagerPids[i] = fork1(name, Pager, NULL, 4 * USLOSS_MIN_STACK, PAGER_PRIORITY);
    }

    // Zero out, then initialize, the vmStats structure
    memset((char *) &vmStats, 0, sizeof(VmStats));
    vmStats.pages = pages;
    vmStats.frames = frames;

    // Initialize other vmStats fields.
    vmStats.diskBlocks = diskBlocks;
    vmStats.freeFrames = frames;
    vmStats.freeDiskBlocks = diskBlocks;
    vmStats.switches = 0;
    vmStats.faults = 0;
    vmStats.new = 0;
    vmStats.pageIns = 0;
    vmStats.pageOuts = 0;
    vmStats.replaced = 0;

    if (debugflag5) {
        USLOSS_Console("VmInit(): size of a page is %d bytes\n", USLOSS_MmuPageSize());
    }

    return USLOSS_MmuRegion(&dummy);
} /* vmInitReal */

/*
 *----------------------------------------------------------------------
 *
 * vmDestroyReal --
 *
 * Called by vmDestroy.
 * Frees all of the global data structures
 *
 * Results:
 *      None
 *
 * Side effects:
 *      The MMU is turned off.
 *
 *----------------------------------------------------------------------
 */
void vmDestroyReal(void) {
    if (debugflag5) {
        USLOSS_Console("process %d: vmDestroy started\n", getpid());
    }

    CheckMode();

    // free the mutex
    semfreeReal(frameSem);
    semfreeReal(frameSem);

    // end mmu
    USLOSS_MmuDone();

    // Kill the pagers
    for (int i = 0; i < numPagers; i++) {
        MboxSend(faultBox, "quit", sizeof(char) * 4); // wake up the pager
        zap(pagerPids[i]);
    }

    // Print vm statistics
    PrintStats();

    // free stuff that we malloc'd
    free(frameTable);

} /* vmDestroyReal */

/*
 *----------------------------------------------------------------------
 *
 * PrintStats --
 *
 *      Print out VM statistics.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      Stuff is printed to the USLOSS_Console.
 *
 *----------------------------------------------------------------------
 */
void PrintStats(void) {
     USLOSS_Console("VmStats\n");
     USLOSS_Console("pages:          %d\n", vmStats.pages);
     USLOSS_Console("frames:         %d\n", vmStats.frames);
     USLOSS_Console("diskBlocks:     %d\n", vmStats.diskBlocks);
     USLOSS_Console("freeFrames:     %d\n", vmStats.freeFrames);
     USLOSS_Console("freeDiskBlocks: %d\n", vmStats.freeDiskBlocks);
     USLOSS_Console("switches:       %d\n", vmStats.switches);
     USLOSS_Console("faults:         %d\n", vmStats.faults);
     USLOSS_Console("new:            %d\n", vmStats.new);
     USLOSS_Console("pageIns:        %d\n", vmStats.pageIns);
     USLOSS_Console("pageOuts:       %d\n", vmStats.pageOuts);
     USLOSS_Console("replaced:       %d\n", vmStats.replaced);
} /* PrintStats */

/*
 *----------------------------------------------------------------------
 *
 * FaultHandler
 *
 * Handles an MMU interrupt. Simply stores information about the
 * fault in a queue, wakes a waiting pager, and blocks until
 * the fault has been handled.
 *
 * Results:
 * None.
 *
 * Side effects:
 * The current process is blocked until the fault is handled.
 *
 *----------------------------------------------------------------------
 */
static void FaultHandler(int dev/* MMU_INT */, void *arg  /* Offset within VM region */) {
    if (debugflag5) {
        USLOSS_Console("process %d: FaultHandler started\n", getpid());
    }

    int cause;
    int result;
    int type = dev;
    void *addr = arg;

    assert(type == USLOSS_MMU_INT);
    cause = USLOSS_MmuGetCause();
    assert(cause == USLOSS_MMU_FAULT);
    vmStats.faults++;

    // create a fault message
    FaultMsg fault = faults[getpid() % MAXPROC];
    fault.pid = getpid();
    fault.addr = addr;
    fault.replyMbox = MboxCreate(1, sizeof(int));
    
    // send the fault
    result = MboxSend(faultBox, &fault, sizeof(FaultMsg));
    if (result < 0) {
        USLOSS_Console("process %d: FaultHandler can't send: %d\n", getpid(), result);
        USLOSS_Halt(1);
    }

    // receive the reply
    int status;
    result = MboxReceive(fault.replyMbox, &status, sizeof(FaultMsg));
    if (result < 0) {
        USLOSS_Console("process %d: FaultHandler can't receive: %d\n", getpid(), result);
        USLOSS_Halt(1);
    }
    else if (debugflag5) {
        USLOSS_Console("process %d: FaultHandler received reply\n", getpid());
    }

    // clean out the fault message
    fault.pid = -1;
    fault.addr = NULL;
    MboxRelease(fault.replyMbox);

} /* FaultHandler */

/*
 *----------------------------------------------------------------------
 *
 * Pager 
 *
 * Kernel process that handles page faults and does page replacement.
 *
 * Results:
 * None.
 *
 * Side effects:
 * None.
 *
 *----------------------------------------------------------------------
 */
static int Pager(char *buf) {
    if (debugflag5) {
        USLOSS_Console("process %d: Pager started\n", getpid());
    }

    int result;

    while (!isZapped()) {
        /* Wait for fault to occur (receive from mailbox) */
        FaultMsg fault;

        result = MboxReceive(faultBox, &fault, sizeof(FaultMsg));
        if (result == -1) {
            USLOSS_Console("process %d: Pager can't receive: %d\n", getpid(), result);
            USLOSS_Halt(1);
        }
        else if (debugflag5) {
            USLOSS_Console("process %d: Pager received fault from: %d\n", getpid(), fault.pid);
        }

        int pid = fault.pid;
        int page = (int) ((long) fault.addr / USLOSS_MmuPageSize()); // convert to a page

        int frame;

        // check if zapped while waiting
        if (isZapped()) {
            break;
        }

        /* Look for free frame */
        /* If there isn't one then use clock algorithm to
         * replace a page (perhaps write to disk) */
        // start mutual exclussion
        sempReal(frameSem);
        while (1) {
            // check if we are pointing beyond the edge of the array
            if (lastFrameIndex == numFrames) {
                lastFrameIndex = 0;
            }

            // check if this node is open
            if (frameTable[lastFrameIndex].state == OPEN) {
                // check if this frame was previously in use
                if (frameTable[lastFrameIndex].pid != -1) {
                    // it was previously in use and needs to be written to the disk

                    // gain access to the frame
                    int oldPage = frameTable[frame].page;
                    int mapResult = USLOSS_MmuMap(0, oldPage, frame, USLOSS_MMU_PROT_RW);

                    if (mapResult != USLOSS_MMU_OK) {
                        USLOSS_Console("Pager(): MmuMap() returned an error%d, halting\n", mapResult);
                        USLOSS_Halt(1);
                    }

                    if (debugflag5) {
                        USLOSS_Console("Pager(): replaced oldPage %d, frame %d\n", oldPage, frame);
                    }
                    // inc page outs
                    sempReal(statSem);
                    vmStats.pageOuts++;
                    semvReal(statSem);

                    int accessPtr;
                    USLOSS_MmuGetAccess(lastFrameIndex, &accessPtr);
                    if (debugflag5) {
                        USLOSS_Console("Pager(): returned from getAccess, testing dirty bit\n");
                    }
                    int dirtyBit = (accessPtr >> USLOSS_MMU_DIRTY) & 1;
                    
                    // case for dirty bits
                    if ( dirtyBit == 1) {
                        // write to disk
                        if (debugflag5) {
                            USLOSS_Console("Pager(): bit is dirty\n");
                        }
                        // find out where to write
                        int pageIndex = frameTable[lastFrameIndex].page;

                        Process tempProc = procTable[pid];
                        int pageDiskBlock = tempProc.pageTable[pageIndex].diskBlock;

                        if (pageDiskBlock == -1) {
                            //get a new block(sector) to store the page into
                            pageDiskBlock = nextBlock;
                            tempProc.pageTable[pageIndex].diskBlock = nextBlock;
                            nextBlock++;
                        }

                        // Create buffer to store page
                        char *buffer = NULL;
                        // memcpy / strcpy to buffer
                        memcpy(buffer, frame, USLOSS_MmuPageSize());

                        // diskWrite(buffer, place)
                        diskWriteReal(diskUnit, pageDiskBlock, 0, diskUnitTrackSize, buffer);
                    }

                    if (debugflag5) {
                        USLOSS_Console("Pager(): zeroing out frame now\n");
                    }

                    // zero out the frame
                    memset(frame, 0, USLOSS_MmuPageSize());

                    if (debugflag5) {
                        USLOSS_Console("Pager(): frame zeroed, unmapping old page\n");
                    }

                    // Unmap the old page
                    int unmapResult = USLOSS_MmuUnmap(0, oldPage);
                    if (unmapResult != USLOSS_MMU_OK) {
                        USLOSS_Console("Pager(): unmapResult gave error %d, halting\n", unmapResult);
                        USLOSS_Halt(1);
                    }
                }

                frameTable[lastFrameIndex].state = CLOSED;
                frameTable[lastFrameIndex].pid = pid;
                frameTable[lastFrameIndex].page = page;

                frame = lastFrameIndex;

                lastFrameIndex++;
                break;
            }
            // otherwise set it to be open next time
            else {
                frameTable[lastFrameIndex].state = OPEN;

                lastFrameIndex++;
            }
        }

        // end mutual exclussion
        semvReal(frameSem);

        /* Load page into frame from disk, if necessary */
        // check if necessary
        if (procTable[pid % MAXPROC].pageTable[page].diskState == 1) {
            // inc page ins
            sempReal(statSem);
            vmStats.pageIns++;
            semvReal(statSem);

            // disk size variables
            int sector;
            int track;
            int disk;

            // TODO this whole part, wtf, which disk unit/track/sector
            // find out where on the disk it is stored
            DiskSize(1, &sector, &track, &disk);
            int numSectors = USLOSS_MmuPageSize() / sector;
            int start = procTable[pid % MAXPROC].pageTable[page].diskBlock / sector;

            // read from that location in memory
            char *buf = malloc(USLOSS_MmuPageSize());
            diskReadReal(1, start, start, numSectors, buf);

            // map the memory
            result = USLOSS_MmuMap(0, page, frame, 3);
            if (result != USLOSS_MMU_OK) {
                USLOSS_Console("process %d: Pager failed mapping: %d\n", getpid(), result);
                USLOSS_Halt(1);
            }

            // calculate where in the vmregion to write
            void *destination = vmRegion + (USLOSS_MmuPageSize() * page);

            // copy what was on disk to the frame
            memcpy(destination, buf, USLOSS_MmuPageSize());

            // unmap
            //result = USLOSS_MmuUnmap(0, page);
            if (result != USLOSS_MMU_OK) {
                USLOSS_Console("process %d: Pager failed unmapping: %d\n", getpid(), result);
                USLOSS_Halt(1);
            }

            // TODO diskblock stuff
        }
        else {
            // inc new
            sempReal(statSem);
            vmStats.new++;
            semvReal(statSem);

            // map the memory
            result = USLOSS_MmuMap(0, page, frame, 3);
            if (result != USLOSS_MMU_OK) {
                USLOSS_Console("process %d: Pager failed mapping: %d\n", getpid(), result);
                USLOSS_Halt(1);
            }

            // calculate where in the vmregion to write
            void *destination = vmRegion + (USLOSS_MmuPageSize() * page);

            // copy nothing into the fram
            memset(destination, 0, USLOSS_MmuPageSize());

            // unmap
            result = USLOSS_MmuUnmap(0, page);
            if (result != USLOSS_MMU_OK) {
                USLOSS_Console("process %d: Pager failed unmapping: %d\n", getpid(), result);
                USLOSS_Halt(1);
            }
        }

        // update the page table
        procTable[pid % MAXPROC].pageTable[page].memState = INCORE;
        procTable[pid % MAXPROC].pageTable[page].diskState = UNUSED;        
        procTable[pid % MAXPROC].pageTable[page].frame = frame;
        procTable[pid % MAXPROC].pageTable[page].diskBlock = -1;

        /* Unblock waiting (faulting) process */
        result = MboxSend(fault.replyMbox, "done", sizeof(char) * 4);
        if (result != USLOSS_MMU_OK) {
            USLOSS_Console("process %d: Pager failed sending: %d\n", getpid(), result);
            USLOSS_Halt(1);
        }
    }

    return 0;
} /* Pager */

void forkReal(int pid) {
    if (debugflag5) {
        USLOSS_Console("process %d: forkReal\n", pid);
    }

    // check if vm has started yet
    if (!vmOn) {
        return;
    }

    // create a new process
    procTable[pid % MAXPROC].numPages = numPages;
    procTable[pid % MAXPROC].pageTable = malloc(sizeof(PTE) * numPages);

    // fill in the page table
    for (int i = 0; i < numPages; i++) {
        procTable[pid % MAXPROC].pageTable[i].memState = UNUSED;
        procTable[pid % MAXPROC].pageTable[i].diskState = UNUSED;
        procTable[pid % MAXPROC].pageTable[i].frame = -1;
        procTable[pid % MAXPROC].pageTable[i].diskBlock = -1;
        procTable[pid % MAXPROC].pageTable[i].semaphore = semcreateReal(1); // TODO maybe start at 0
    }
}

void switchReal(int old, int new) {
    if (debugflag5) {
        USLOSS_Console("process %d: switchReal, old: %d, new: %d\n", old, old, new);
    }

    int result;

    // check if vm has started yet
    if (!vmOn) {
        return;
    }

    // update vmstats
    vmStats.switches++;

    // unmap the old's stuff
    if (procTable[old % MAXPROC].pageTable != NULL) {
        for (int i = 0; i < numPages; i++) {
            if (procTable[old % MAXPROC].pageTable[i].memState == INCORE) {
                result = USLOSS_MmuUnmap(0, i);
                if (result != USLOSS_MMU_OK) {
                    USLOSS_Console("process %d: switchReal failed unmap: %d\n", old, result);
//                    USLOSS_Halt(1);
                }
            }
        }
    }

    // map new's stuff
    if (procTable[new % MAXPROC].pageTable != NULL) {
        for (int i = 0; i < numPages; i++) {
            if (procTable[new % MAXPROC].pageTable[i].memState == INCORE) {
                result = USLOSS_MmuMap(0, i, procTable[new % MAXPROC].pageTable[i].frame, USLOSS_MMU_PROT_RW);
                if (result != USLOSS_MMU_OK) {
                    USLOSS_Console("process %d: switchReal failed map: %d\n", old, result);
//                    USLOSS_Halt(1);
                }
            }
        }
    }

}

void quitReal(int pid) {
    if (debugflag5) {
        USLOSS_Console("process %d: quitReal\n", pid);
    }

    // check if vm has started yet
    if (!vmOn) {
        return;
    }

    // release the sems for all PTE for this process
    for (int i = 0; i < procTable[pid % MAXPROC].numPages; i++) {
        semfreeReal(procTable[pid % MAXPROC].pageTable[i].semaphore);
    }

    // clean up all frames for this process
    for (int i = 0; i < numFrames; i++) {
        if (frameTable[i].pid == pid) {
            frameTable[i].state = OPEN;
            frameTable[i].pid = -1;
            frameTable[i].page = -1;
        }
    }

    // reset this value in the procTable
    procTable[pid % MAXPROC].numPages;
    free(procTable[pid % MAXPROC].pageTable);
}





/*VVVVVVVV User Functions VVVVVVVV*/
static void mboxCreate(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int numslots = (long) args->arg1;
    int slotsize = (long) args->arg2;

    int *id;
    int res = Mbox_Create(numslots, slotsize, id);

    args->arg1 = (void *) id;
    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

static void mboxRelease(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int id = (long) args->arg1;

    int res = Mbox_Release(id);

    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

static void mboxSend(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int id = (long) args->arg1;
    void *msg = args->arg2;
    int size = (long) args->arg3;

    int res = Mbox_Send(id, msg, size);

    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

static void mboxReceive(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int id = (long) args->arg1;
    void *msg = args->arg2;
    int size = (long) args->arg3;
    
    int res = Mbox_Receive(id, msg, size);
    
    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

static void mboxCondSend(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int id = (long) args->arg1;
    void *msg = args->arg2;
    int size = (long) args->arg3;
    
    int res = Mbox_CondSend(id, msg, size);
    
    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

static void mboxCondReceive(systemArgs *args) {
    CheckMode();

    // get sysarg variables
    int id = (long) args->arg1;
    void *msg = args->arg2;
    int size = (long) args->arg3;

    int res = Mbox_CondReceive(id, msg, size);

    args->arg4 = (void *) 0L;

    // check bad input
    if (res < 0) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
}

/*
 *----------------------------------------------------------------------
 *
 * VmInit --
 *
 * Stub for the VmInit system call.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      VM system is initialized.
 *
 *----------------------------------------------------------------------
 */
static void vmInit(systemArgs *args) {
    if (debugflag5) {
        USLOSS_Console("process %d: vmInit started\n", getpid());
    }

    CheckMode();

    // get sysarg variables
    int mappings = (long) args->arg1;
    int pages    = (long) args->arg2;
    int frames   = (long) args->arg3;
    int pagers  = (long) args->arg4;

    void *addr = vmInitReal(mappings, pages, frames, pagers);
    args->arg1 = (void *) addr;

    args->arg4 = (void *) 0L;
    // check bad input
    if ((long) addr == -1) {
        args->arg4 = (void *) -1L;
    }

    setUserMode();
} /* vmInit */

/*
 *----------------------------------------------------------------------
 *
 * vmDestroy --
 *
 * Stub for the VmDestroy system call.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      VM system is cleaned up.
 *
 *----------------------------------------------------------------------
 */

static void vmDestroy(systemArgs *args) {
    if (debugflag5) {
        USLOSS_Console("process %d: vmDestroy started\n", getpid());
    }

    CheckMode();

    // if the vm hasn't been init'd yet, do nothing
    if (vmOn == 0) {
        return;
    }

    vmDestroyReal();

    // set vmOn to false
    vmOn = 0;

    setUserMode();
} /* vmDestroy */

void setUserMode() {
    USLOSS_PsrSet(USLOSS_PsrGet() & ~USLOSS_PSR_CURRENT_MODE);
}
