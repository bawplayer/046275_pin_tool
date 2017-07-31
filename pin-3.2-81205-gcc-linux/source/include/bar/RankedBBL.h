#ifndef _RANKEDBBL_H
#define _RANKEDBBL_H

#include <iostream>
#include "pin.H"
#include "BBL.h"

class RankedBBL : public BBLClass {
private:
    unsigned int _rank = 0;
    // bool _ends_with_jump = true;

public:
    RankedBBL *branch_bbl = nullptr;
    RankedBBL *nbranch_bbl = nullptr;

    RankedBBL(ADDRINT src, ADDRINT dst, int rtn_id,
        unsigned int rank = 0):
        BBLClass(src, dst, rtn_id),
        _rank(rank) {
    }

    unsigned int getRank() const {
        return this->_rank;
    }

/*    void increaseRankInFallthrough(int x) {
        if (this->isConditionalBranchEnding()) {
            return;
        }

        if (this->branch_bbl == nullptr) {
            return;
        }

        branch_bbl->increaseRank(x);
    }
*/
    unsigned int increaseRank(int x) {
        if (x < 0) {
            if (static_cast<unsigned int>(-x) > this->_rank) {
                // error -> ignore and return 0
                return 0;
            }
        }

        // this->_rank += x;
        // this->increaseRankInFallthrough(x);

        return this->getRank();
    }

/*    void setConditionalBranchEnding(bool p = true) {
        this->_is_conditional_branch = p;
    }

    bool isConditionalBranchEnding() const {
        return this->_is_conditional_branch;
    }*/

}; // end of RankedBBL

std::ostream& operator<<(std::ostream& os, const RankedBBL& self) {
    return os << "Source address: " << self._src << "\t" << "(rank: " << self.getRank() << ")" << std::endl;
}

class HasSameSourceAddress {
public:
    ADDRINT sourceAddress;
    explicit HasSameSourceAddress(ADDRINT a): sourceAddress(a) {
    }

    bool operator()(const RankedBBL& rbbl) const {
        return sourceAddress == rbbl._src;
    }
}; // end of HasSameSourceAddress

#endif
