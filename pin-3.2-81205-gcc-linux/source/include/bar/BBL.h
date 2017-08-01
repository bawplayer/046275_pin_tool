#ifndef _BBLCLASS_H
#define _BBLCLASS_H

#include "pin.H"
#include "Edge.h"
#include "InstructionClass.h"

class BBLClass {
private:
    int _rtn_id;

    bool _validateSourceAndDestination() {
        if (_src > _dst) {
            std::swap(_src, _dst);
        }
        return true;
    }
public:
    ADDRINT _src, _dst;
    ADDRINT _src_offset, _dst_offset;

    int first_instr_index = -1, last_instr_index = -1;
    unsigned int rank = 0;

    BBLClass(ADDRINT src, ADDRINT dst, const RTN& rtn): 
        _rtn_id(0), _src(src), _dst(dst),
        _src_offset(0), _dst_offset(0) {
        this->_rtn_id = RTN_Id(rtn);
        _validateSourceAndDestination();
    }

    BBLClass(ADDRINT src, ADDRINT dst, int rtn_id,
        int first_instr_index = (-1),
        int last_instr_index = (-1)):
        _rtn_id(rtn_id),
        _src(src), _dst(dst),
        _src_offset(0), _dst_offset(0),
        first_instr_index(first_instr_index),
        last_instr_index(last_instr_index) {}

    virtual ~BBLClass() {}

    int getRoutineId() const {
        return this->_rtn_id;
    }

    std::pair<ADDRINT, ADDRINT> setOffset(ADDRINT image_addr) {
        this->_src_offset = this->_src - image_addr;
        this->_dst_offset = this->_dst - image_addr;
        return std::pair<ADDRINT, ADDRINT>(
            this->_src_offset, this->_dst_offset);
    }

    bool isInstructionOffsetIn(ADDRINT off) const {
        return (off >= this->_src_offset) && (off <= this->_dst_offset);
    }

    ADDRINT extendStartAddress(ADDRINT addr) {
        if (addr < this->_src) {
            this->_src = addr;
        }
        return this->_src;
    }

    bool isEndingWithBranch() const {
        if ((this->last_instr_index < 0) || \
            (static_cast<unsigned>(this->last_instr_index) >= instructionsVector.size())) {
            return false;
        }
        return instructionsVector.at(this->last_instr_index).is_branch;
    }

    bool hasBranchInIt() const {
        if ((this->last_instr_index < 0) || \
            (static_cast<unsigned>(this->last_instr_index) >= instructionsVector.size())) {
            return false;
        } else if ((this->first_instr_index < 0) || \
            (this->first_instr_index > this->last_instr_index)) {
            return false;
        }

        for (int i=this->first_instr_index; i <= this->last_instr_index; ++i) {
            if (instructionsVector[i].is_branch) {
                return true;
            }
        }

        return false;
    }

    virtual unsigned int increaseRank(int x) {
        return this->rank += x;
    }

    unsigned getRank() const {
        return this->rank;
    }

    /*
        Essantially, BBLs are differentiated by their start address.
    */
    friend bool operator<(const BBLClass& a, const BBLClass& b) {
        return (a._dst < b._dst);
    }

    friend bool operator==(const BBLClass& ba, const BBLClass& bb) {
        return (ba._rtn_id == bb._rtn_id) && \
            !((ba < bb) || (bb < ba));
    }
}; // end of BBLClass

#endif
