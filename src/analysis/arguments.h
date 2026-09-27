// Function signature recovery: parameters, return value and convention.
//
// A register is a parameter when it is read on some path from the entry
// before being written. That is computed on the lifted IR, where the entry
// values of locations are explicit, so the count matches what the function
// really consumes rather than what the convention allows.
//
// Because a call site reads its callee's argument registers, a caller's own
// parameter set depends on its callees. The pipeline therefore analyses
// functions in reverse call order and iterates upwards to a fixed point.
#pragma once

#include "analysis/calling_convention.h"
#include "analysis/program.h"
#include "ir/ir.h"
#include "lift/lifter.h"

#include <map>

namespace dc {

struct ParamLocation {
    bool isStack = false;
    x86::Family reg = x86::Family::None;
    int xmmIndex = -1;
    i64 stackOffset = 0;
    std::string str() const;
};

struct Signature {
    CallConv conv = CallConv::Unknown;
    std::vector<ir::Type> paramTypes;
    std::vector<ParamLocation> paramLocations;
    std::vector<bool> paramUsed;
    ir::Type returnType = ir::Type::voidTy();
    bool returnsValue = false;
    bool variadic = false;
    bool noReturn = false;
    unsigned stackBytesCleaned = 0;
    std::string name;
    bool known = false;

    size_t paramCount() const { return paramTypes.size(); }
    std::string str() const;
};

// Recovers the signature of one function from its lifted IR.
Signature recoverSignature(Program& prog, const Function& mf, const ir::Function& f, CallConv conv);

// A database of signatures, filled to a fixed point over the call graph.
class SignatureDatabase {
public:
    explicit SignatureDatabase(Program& prog) : prog_(prog) {}

    // Runs the fixed point over every discovered function.
    void build(int maxRounds = 4);

    const Signature* forFunction(u64 entry) const;
    const Signature* forImport(const pe::Import* imp) const;
    // Resolver suitable for LiftOptions.
    lift::SignatureResolver resolver() const;
    // Convention chosen for a function.
    CallConv conventionOf(u64 entry) const;

    int rounds() const { return rounds_; }
    size_t size() const { return byEntry_.size(); }

private:
    Program& prog_;
    std::map<u64, Signature> byEntry_;
    std::map<std::string, Signature> byImport_;
    int rounds_ = 0;
};

} // namespace dc
