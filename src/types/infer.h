// Type recovery.
//
// Evidence is collected from instruction semantics, memory access widths,
// pointer arithmetic, comparisons, constants and known API signatures, then
// propagated over equivalence classes formed by phis and copies. Nothing is
// guessed silently: every value carries the confidence its type was derived
// with, and a function's overall confidence comes from those.
#pragma once

#include "analysis/arguments.h"
#include "analysis/program.h"
#include "analysis/stack_frame.h"
#include "ir/ir.h"
#include "types/type_system.h"

#include <unordered_map>

namespace dc::types {

// What is known about one value while inference runs.
struct ValueFacts {
    Kind kind = Kind::Unknown;
    unsigned bits = 0;
    int signedVotes = 0;
    int unsignedVotes = 0;
    bool boolean = false;
    bool pointer = false;
    bool codePointer = false;
    TypeRef pointee = nullptr;      // when the target type is known
    TypeRef fixed = nullptr;        // an exact type from an API signature
    Confidence confidence = Confidence::None;

    bool isSigned() const { return signedVotes > unsignedVotes; }
};

// One field observed through a pointer.
struct AccessRecord {
    i64 offset = 0;
    unsigned size = 0;
    Kind kind = Kind::Unknown;
    bool isSigned = false;
    bool written = false;
    unsigned count = 0;
};

// Everything inference produced for one function.
struct TypeResult {
    std::unordered_map<ir::ValueId, TypeRef> valueTypes;
    std::unordered_map<ir::ValueId, Confidence> valueConfidence;
    // Accesses seen through each pointer root, used for struct recovery.
    std::unordered_map<ir::ValueId, std::vector<AccessRecord>> pointerAccesses;
    // Stride of an array walked through that root, when one was observed. It
    // is the size of the element, so the recovered structure is padded to it.
    std::unordered_map<ir::ValueId, u64> pointerStride;
    Confidence overall = Confidence::Medium;
    unsigned unknownValues = 0;

    TypeRef of(ir::ValueId v) const {
        auto it = valueTypes.find(v);
        return it == valueTypes.end() ? nullptr : it->second;
    }
    Confidence confidenceOf(ir::ValueId v) const {
        auto it = valueConfidence.find(v);
        return it == valueConfidence.end() ? Confidence::None : it->second;
    }
};

class TypeInference {
public:
    TypeInference(Program& prog, TypeTable& table, const SignatureDatabase& sigs)
        : prog_(prog), table_(table), sigs_(sigs) {}

    TypeResult run(ir::Function& f, const Signature& sig, const StackFrame& frame);

private:
    int find(int a);
    void unite(int a, int b);
    int classOf(ir::ValueId v);
    ValueFacts& facts(ir::ValueId v);
    void seed(ir::Function& f, const Signature& sig);
    void propagate(ir::Function& f);
    void collectPointerAccesses(ir::Function& f, TypeResult& out);
    TypeRef resolve(const ValueFacts& fc, unsigned ptrBits);

    Program& prog_;
    TypeTable& table_;
    const SignatureDatabase& sigs_;
    std::unordered_map<ir::ValueId, int> classIndex_;
    std::vector<int> parent_;
    std::vector<ValueFacts> classFacts_;
};

} // namespace dc::types
