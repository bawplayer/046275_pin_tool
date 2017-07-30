#ifndef _INSTRUCTIONCLASS_H
#define _INSTRUCTIONCLASS_H

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

class InstructionClass {
public:
    ADDRINT address;
    bool hasNewTargAddr = 0;
    //char encoded_ins[XED_MAX_INSTRUCTION_BYTES] = {0};
    xed_decoded_inst_t xedd;
    //xed_category_enum_t category_enum;
    //unsigned int size = 0;
    //int new_targ_entry = 0;

    InstructionClass(ADDRINT addr, xed_decoded_inst_t *xedd_ptr = nullptr):
        address(addr), xedd(*xedd_ptr) {}

    bool operator==(const ADDRINT& a) const {
        return a == this->address;
    }
};

#endif
