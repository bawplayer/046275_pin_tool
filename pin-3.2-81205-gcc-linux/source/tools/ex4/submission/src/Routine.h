#ifndef _ROUTINECLASS_H
#define _ROUTINECLASS_H

#include "pin.H"
#include "Edge.h"
#include "BBL.h"

class RoutineClass {
private:
    int _id;
    string _name;
    ADDRINT _address; // absolute address
    unsigned _icount;
    unsigned _rcount;
    ADDRINT _imageAddress;

    int _findBBLIndex(ADDRINT off) const {
        int i = 0;
        for (std::vector<BBLClass>::const_iterator it = this->bbls.begin();
            it != this->bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            ++i;
            if (bbl.isInstructionOffsetIn(off)) {
                return i;
            }
        }

        return -1;
    }

public:
    bool obsoleteImageAddress;
    std::vector<EDGEClass> edges;
    std::vector<BBLClass> bbls;

    RoutineClass(int id = 0, const string& name = "", ADDRINT addr = 0, \
        unsigned icount = 0, unsigned rcount = 0, ADDRINT imageAddress = 0): \
        _id(id), _name(name), _address(addr), _icount(icount), \
        _rcount(rcount), _imageAddress(imageAddress),
        obsoleteImageAddress(false) {}
    RoutineClass(const RTN& rtn):
        _id(RTN_Id(rtn)), _name(RTN_Name(rtn)), _address(RTN_Address(rtn)),
        _icount(0), _rcount(0),
        _imageAddress(IMG_LowAddress(IMG_FindByAddress(_address))),
        obsoleteImageAddress(false) {}
    
    string getName() const {
        return this->_name;
    }

    ADDRINT getAddress() const {
        return this->_address;
    }

    int getId() const {
        return this->_id;
    }

    unsigned getInstructionCount() const {
        return this->_icount;
    }

    unsigned incInstructionCount(int inc=1) {
        _icount += inc;
        return this->getInstructionCount();
    }

    unsigned getRoutineCount() const {
        return this->_rcount;
    }

    unsigned incRoutineCount(int inc=1) {
        _rcount += inc;
        return this->getRoutineCount();
    }

    ADDRINT getRoutineOffsetFromImage() const {
        return this->_address - this->_imageAddress;
    }

    ADDRINT getImageAddress() const {
        return this->_imageAddress;
    }

    friend bool operator==(const RoutineClass& a, const RoutineClass& b) {
        return a.getId() == b.getId();
    }

    RoutineClass& operator+=(const RoutineClass& rc) {
        if (!(*this == rc)) {
            // not the same routine
            return *this;
        }

        RoutineClass tmp_rtn_obj(*this); // clone self

        // add counters
        tmp_rtn_obj.incInstructionCount(rc._icount);
        tmp_rtn_obj.incRoutineCount(rc._rcount);

        // append missing bbls
        for (std::vector<BBLClass>::const_iterator bbl_i_iter = rc.bbls.begin();
            bbl_i_iter != rc.bbls.end(); ++bbl_i_iter) {
            bool is_found = false;
            for (std::vector<BBLClass>::const_iterator bbl_j_iter = tmp_rtn_obj.bbls.begin();
                bbl_j_iter != tmp_rtn_obj.bbls.end(); ++bbl_j_iter) {
                if (bbl_i_iter->_src == bbl_j_iter->_src_offset) {
                    is_found = true;
                    break;
                }
            }

            if (!is_found) {
                BBLClass tmp_bbl(*bbl_i_iter);
                tmp_bbl._src += this->getImageAddress();
                tmp_bbl._dst += this->getImageAddress();
                tmp_bbl.setOffset(this->getImageAddress());
                tmp_rtn_obj.bbls.push_back(tmp_bbl);
            }
        }

        // merge edges
        for (std::vector<EDGEClass>::const_iterator it = rc.edges.begin();
            it != rc.edges.end(); ++it) {
            const EDGEClass& edge_right = *it;
            std::vector<EDGEClass>::iterator fit = std::find(
                tmp_rtn_obj.edges.begin(), tmp_rtn_obj.edges.end(),
                edge_right);
            if (fit == tmp_rtn_obj.edges.end()) {
                tmp_rtn_obj.edges.push_back(edge_right);
            } else {
                *fit += edge_right;
            }
        }

        *this = tmp_rtn_obj;
        return *this;
    }

    void cleanEdgesThatExitRoutine() {
        for (std::vector<EDGEClass>::iterator it = this->edges.begin();
            it != this->edges.end(); ++it) {
            int bbl1 = this->_findBBLIndex(it->_src_offset);
            int bbl2 = this->_findBBLIndex(it->_dst_offset);
            it->_exitRoutine = ((bbl1 == (-1)) || (bbl2 == (-1)));
        }

        this->edges.erase(std::remove_if(this->edges.begin(), this->edges.end(), 
            isEdgeExitsThisRoutine), this->edges.end());
    }

    friend std::ostream& operator<<(std::ostream& out, const RoutineClass& self) {
        const size_t array_len = 100;
        char char_array[array_len+1];
        char_array[array_len] = '\0';

        // Set buffer with routine data
        if (self.obsoleteImageAddress) {
            snprintf(char_array, array_len, "%s at: 0x%llx (rela) icount: %u\n",
                self.getName().c_str(), 
                static_cast<unsigned long long>(self.getRoutineOffsetFromImage()),
                self.getInstructionCount());
        } else {
            snprintf(char_array, array_len, "%s at: 0x%llx icount: %u\n",
                self.getName().c_str(), 
                static_cast<unsigned long long>(self.getAddress()),
                self.getInstructionCount());
        }
        out << std::string(char_array);

        int i = 1;
        for (std::vector<BBLClass>::const_iterator it = self.bbls.begin();
            it != self.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            snprintf(char_array, array_len, bblString.c_str(), i,
                static_cast<unsigned long long>(bbl._src),
                static_cast<unsigned long long>(bbl._dst));
            out << std::string(char_array);
            ++i;
        }

        i = 1;
        for (std::vector<EDGEClass>::const_iterator it = self.edges.begin();
            it != self.edges.end(); ++it) {
            const EDGEClass& edge = *it;
            // Set buffer with edge data
            int bbl1 = self._findBBLIndex(edge._src_offset), bbl2 = self._findBBLIndex(edge._dst_offset);
            if ((bbl1 == (-1)) || (bbl2 == (-1))) {
                // ignore edges that were not in the trace, or exiting the routine
                continue;
            }

            snprintf(char_array, array_len, edgeString.c_str(),
                i++, bbl1, bbl2, edge.getTakenCount());
            out << std::string(char_array);
        }

        return out;
    }

    std::ofstream& printProfile(std::ofstream& profileFile) const {
        RoutineClass const& self = *this;
        const size_t array_len = 200;
        char char_array[array_len+1];
        char_array[array_len] = '\0';

        // Set buffer with routine data
        snprintf(char_array, array_len, routineProfString.c_str(),
            self.getId(), self.getName().c_str(),
            static_cast<unsigned long long>(self.getRoutineOffsetFromImage()),
            self.getInstructionCount(), self.getRoutineCount());
        profileFile << std::string(char_array);

        int i = 1;
        for (std::vector<BBLClass>::const_iterator it = self.bbls.begin();
            it != self.bbls.end(); ++it) {
            const BBLClass& bbl = *it;
            snprintf(char_array, array_len, bblProfString.c_str(), i++,
                static_cast<unsigned long long>(bbl._src_offset),
                static_cast<unsigned long long>(bbl._dst_offset));
            profileFile << std::string(char_array);
        }

        i = 1;
        for (std::vector<EDGEClass>::const_iterator it = self.edges.begin();
            it != self.edges.end(); ++it) {
            const EDGEClass& edge = *it;
            // Set buffer with edge data
            snprintf(char_array, array_len, edgeProfString.c_str(),
                i++, edge._src_offset, edge._dst_offset,
                edge._next_ins_offset,
                edge.getTakenCount(),
                edge.getInstructionCount(),
                edge.isConditionalBranch(),
                edge.isCall()
                );
            profileFile << std::string(char_array);
        }

        return profileFile;
    }
}; // END of RoutineClass

bool compareRoutineIsGreaterThan(const RoutineClass& a, const RoutineClass& b) {
    return !(((a.getInstructionCount() < b.getInstructionCount()) \
        || ((a.getInstructionCount() == b.getInstructionCount()) \
            && (a.getId() < b.getId()))) \
        || (a.getInstructionCount() == b.getInstructionCount()));
}

#endif
