# Recover function names from stripped binaries using debug functions
#@author mishellcode
#@category symbols_recovery
#@keybinding 
#@menupath 
#@toolbar 

import threading
from collections import deque
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *
from ghidra.program.model.address.Address import *
from ghidra.program.model.symbol import ReferenceManager
from ghidra.program.model.symbol import SourceType

listing = currentProgram.getListing()
ins_list = listing.getInstructions(1)
refmgr = currentProgram.getReferenceManager()

dbg_name = askString("Enter debug function name", "Function name:")
offset = askInt("Enter ESP param offset", "Offset:")


func = getFirstFunction()

while func is not None:
    if func.getName() == db_name:
        print "[+] Debug Found!"
        entry = func.getEntryPoint()
        break
    else:
        func = getFunctionAfter(func)

if entry:
    refs = refmgr.getReferencesTo(entry)
    visited = []
    renamed = []
else:
    print "[-] Debug not found :("

def worker(q):
    print "IM WORKING"
    while True:
        e = q.popleft()
        try:
            rename_ref(e)
        finally:
            q.task_done()

def rename_ref(e):
    call_addr = e.getFromAddress()
    callee = listing.getFunctionContaining(call_addr)
    #MUTEX LOCK
    if not callee:
        exit
    else:
        #MUTEX UNLOCK
        callee_name = callee.getName()
        if callee_name not in visited:
            visited.append(callee_name)
        if callee_name not in renamed:
            ins = listing.getInstructionAt(call_addr)
            if ins:
                curr_ins = ins
                for i in xrange(1, 10):
                    curr_ins = curr_ins.getPrevious()
                    print curr_ins
                    if str(curr_ins).startswith("MOV") and len(curr_ins.getOpObjects(0).tolist()) == 2:
                        if str(curr_ins.getOpObjects(0).tolist()[0]) == "ESP" and str(curr_ins.getOpObjects(0).tolist()[1]) == str(offset):
                            if curr_ins.getOpObjects(1):
                                str_addr = curr_ins.getOpObjects(1).tolist()[0]
                                if isinstance(curr_ins.getOpObjects(1).tolist()[0], ghidra.program.model.scalar.Scalar):
                                    off = str_addr.getValue()
                                    straddr = call_addr.getNewAddress(off, 0)
                                    if listing.getDataAt(straddr):
                                        sn_name = str(listing.getDataAt(straddr).getValue())
                                        if '(' in sn_name:
                                            sn_name =  sn_name.split('(')[0].split(' ')[1]
                                            callee.setName(sn_name, SourceType.USER_DEFINED)
                                        else:
                                            callee.setName(sn_name, SourceType.USER_DEFINED)
                                        #MUTEX LOCK
                                        renamed.append(sn_name)
                                        #MUTEX UNLOCK
                                        break
                                    else:
                                        print "[-] getData failed for: " + straddr.toString()
                                else:
                                    print "[-] Indirect reference: " + curr_ins.toString() + " " + e.toString()
            else:
                print "[-] Xref without valid instruction: " + e.toString()
        else:
            print "[*] skipping"
            #MUTEX UNLOCK


q = deque()


worker = threading.Thread(target=worker, args=q)
#worker.daemon = True
worker.start()

i = 0
for e in refs:
    q.append(e)


    
print "[+] Renamed: " + str(len(renamed)) + " functions over " + str(len(visited)) + " visited functions "                            
