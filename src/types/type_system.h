// Recovered C types.
//
// Separate from ir::Type, which only carries a width and a class. These are
// the types printed in the output, with Windows spellings, pointers, arrays
// and recovered structures.
#pragma once

#include "support/common.h"

#include <map>
#include <memory>

namespace dc::types {

enum class Kind : u8 {
    Void, Bool, Int, Float, Pointer, Array, Struct, Function, Unknown,
};

// How sure the inference is about a type. Uncertainty is tracked rather than
// hidden, and surfaces as a per-function confidence in the output.
enum class Confidence : u8 { None, Low, Medium, High, Certain };
const char* confidenceName(Confidence c);
inline Confidence weaker(Confidence a, Confidence b) { return a < b ? a : b; }

struct Type;
using TypeRef = const Type*;

struct StructField {
    u64 offset = 0;
    unsigned size = 0;
    TypeRef type = nullptr;
    std::string name;
    bool accessed = true;   // false for padding the layout implies
};

struct Type {
    Kind kind = Kind::Unknown;
    unsigned bits = 0;      // scalar width
    bool isSigned = false;
    TypeRef pointee = nullptr;      // Pointer
    TypeRef element = nullptr;      // Array
    u64 arrayCount = 0;
    std::string name;               // struct / typedef name
    std::vector<StructField> fields; // Struct
    std::vector<TypeRef> params;     // Function
    TypeRef returnType = nullptr;
    bool variadic = false;

    unsigned sizeInBytes() const;
    bool isVoid() const { return kind == Kind::Void; }
    bool isPointer() const { return kind == Kind::Pointer; }
    bool isInteger() const { return kind == Kind::Int || kind == Kind::Bool; }
    bool isFloat() const { return kind == Kind::Float; }
    bool isStruct() const { return kind == Kind::Struct; }
    // Windows spelling, e.g. "DWORD", "LONGLONG", "struct s_foo*".
    std::string spell(const std::string& declarator = {}) const;
};

// Owns every type and hands out stable pointers.
class TypeTable {
public:
    TypeTable();

    TypeRef voidType() const { return void_; }
    TypeRef boolType() const { return bool_; }
    TypeRef unknown() const { return unknown_; }
    TypeRef integer(unsigned bits, bool isSigned);
    TypeRef floating(unsigned bits);
    TypeRef pointer(TypeRef pointee);
    TypeRef array(TypeRef element, u64 count);
    TypeRef function(TypeRef ret, std::vector<TypeRef> params, bool variadic);
    // Creates (or returns) a named structure. Fields are filled in later.
    Type* makeStruct(const std::string& name);
    TypeRef byName(const std::string& name) const;
    const std::vector<std::unique_ptr<Type>>& all() const { return owned_; }
    std::vector<const Type*> structs() const;

    // Default integer type of a given width, used when nothing is known.
    TypeRef defaultInt(unsigned bits) { return integer(bits, true); }
    TypeRef pointerSized(unsigned ptrBits) { return integer(ptrBits, true); }

private:
    Type* alloc();
    std::vector<std::unique_ptr<Type>> owned_;
    std::map<std::pair<unsigned, bool>, TypeRef> ints_;
    std::map<unsigned, TypeRef> floats_;
    std::map<TypeRef, TypeRef> pointers_;
    std::map<std::pair<TypeRef, u64>, TypeRef> arrays_;
    std::map<std::string, Type*> named_;
    TypeRef void_ = nullptr;
    TypeRef bool_ = nullptr;
    TypeRef unknown_ = nullptr;
};

} // namespace dc::types
