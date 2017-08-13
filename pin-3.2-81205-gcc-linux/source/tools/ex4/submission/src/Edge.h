#ifndef _EDGECLASS_H
#define _EDGECLASS_H

#include "pin.H"

class EDGEClass {
private:
    int _rtn_id ;
    unsigned _icount, _taken_count;
    bool _conditional_branch, _is_call;
public:
    bool _exitRoutine;
    ADDRINT _src_offset, _dst_offset;
    ADDRINT _next_ins_offset;
        
    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n,
        bool cond_branch, bool is_call, const RTN& rtn) :
        _rtn_id(0), _icount(0), _taken_count(0),
        _conditional_branch(cond_branch), _is_call(is_call),
        _exitRoutine(false), _src_offset(s),
        _dst_offset(d), _next_ins_offset(n) {
        _rtn_id = RTN_Id(rtn);
    }

    EDGEClass(ADDRINT s, ADDRINT d, ADDRINT n, unsigned icount,
        bool cond_branch, bool is_call,
        unsigned tcount, int rtn_id):
        _rtn_id(rtn_id), _icount(icount), _taken_count(tcount),
        _conditional_branch(cond_branch), _is_call(is_call),
        _exitRoutine(false),
        _src_offset(s),_dst_offset(d), _next_ins_offset(n) {}

    unsigned getInstructionCount() const {
        return this->_icount;
    }

    unsigned incInstructionCount(int inc=1) {
        this->_icount += inc;
        return this->getInstructionCount();
    }

    unsigned getTakenCount() const {
        return this->_taken_count;
    }

    unsigned incTakenCount(int inc=1) {
        this->_taken_count += inc;
        return this->getTakenCount();
    }

    unsigned getFallThroughCount() const {
        return getInstructionCount() - getTakenCount();
    }

    int getRoutineId() const {
        return this->_rtn_id;
    }

    EDGEClass& operator+=(const EDGEClass& right) {
        this->incInstructionCount(right.getInstructionCount());
        this->incTakenCount(right.getTakenCount());
        return *this;
    }

    bool isConditionalBranch() const {
        return this->_conditional_branch;
    }

    bool isCall() const {
        return this->_is_call;
    }

    friend bool operator==(const EDGEClass& ea, const EDGEClass& eb) {
        return (ea.getRoutineId() == eb.getRoutineId()) && \
            (ea._src_offset == eb._src_offset) && (ea._dst_offset == eb._dst_offset) && \
            (ea._next_ins_offset == eb._next_ins_offset);
    }

    bool operator<(const EDGEClass& edge) const {
        return (this->_src_offset < edge._src_offset) || \
            ((this->_src_offset == edge._src_offset) && (this->_dst_offset < edge._dst_offset));
    }
}; // END of EDGEClass

bool compareEdgeTakenCounterIsGreaterThan(const EDGEClass& a, const EDGEClass& b) {
    return (a.getTakenCount() > b.getTakenCount()) || \
        ((a.getTakenCount() == b.getTakenCount()) && (b<a));
}

bool isEdgeExitsThisRoutine(const EDGEClass& edge) {
    return edge._exitRoutine;
}

#endif
