#ifndef _INSTRUCTIONCLASS_H
#define _INSTRUCTIONCLASS_H

#include <iostream>
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

class InstructionClass {
public:
    ADDRINT address, previous_address = 0;
    bool hasNewTargAddr = 0;
    int index_in_routine = 0;
    //char encoded_ins[XED_MAX_INSTRUCTION_BYTES] = {0};
    xed_decoded_inst_t xedd;
    bool open_bbl = false, close_bbl = false;
    USIZE size_in_bytes;
    bool is_branch = false;

    InstructionClass(ADDRINT addr, xed_decoded_inst_t *xedd_ptr = nullptr,
        int index = 0, USIZE size = 0, 
        ADDRINT prev_address = 0,
        bool is_branch = false):
        address(addr), previous_address(prev_address),
        index_in_routine(index), xedd(*xedd_ptr),
        size_in_bytes(size),
        is_branch(is_branch)  {}

    bool operator==(const ADDRINT& a) const {
        return a == this->address;
    }
};

std::ostream& operator<<(std::ostream& os, const InstructionClass& self) {
    os << "Instruction index: " << self.index_in_routine << "\t";
    os << "Address: " << self.address << "\t";
    
    if (self.open_bbl && self.close_bbl) {
        os << "(Single instruction BBL)";
    } else if (self.open_bbl) {
        os << "(Opens BBL)";
    } else if (self.close_bbl) {
        os << "(Closes BBL)";
    }

    return os << std::endl;
}

#endif
