#include "types/type_system.h"

#include <algorithm>

namespace dc::types {

const char* confidenceName(Confidence c) {
    switch (c) {
    case Confidence::None: return "NONE";
    case Confidence::Low: return "LOW";
    case Confidence::Medium: return "MEDIUM";
    case Confidence::High: return "HIGH";
    case Confidence::Certain: return "CERTAIN";
    }
    return "?";
}

unsigned Type::sizeInBytes() const {
    switch (kind) {
    case Kind::Void: return 0;
    case Kind::Bool: return 1;
    case Kind::Int:
    case Kind::Float: return (bits + 7) / 8;
    case Kind::Pointer:
    case Kind::Function: return bits ? (bits + 7) / 8 : 8;
    case Kind::Array: return element ? element->sizeInBytes() * (unsigned)arrayCount : 0;
    case Kind::Struct: {
        unsigned end = 0;
        for (const auto& f : fields) end = std::max(end, (unsigned)f.offset + f.size);
        return end;
    }
    default: return (bits + 7) / 8;
    }
}

namespace {
// Windows spellings, which is what a reader of decompiled Windows code
// expects to see.
const char* intName(unsigned bits, bool isSigned) {
    switch (bits) {
    case 1: return "bool";
    case 8: return isSigned ? "CHAR" : "BYTE";
    case 16: return isSigned ? "SHORT" : "WORD";
    case 32: return isSigned ? "INT" : "DWORD";
    case 64: return isSigned ? "LONGLONG" : "ULONGLONG";
    case 128: return isSigned ? "__int128" : "unsigned __int128";
    default: return isSigned ? "INT" : "DWORD";
    }
}
} // namespace

std::string Type::spell(const std::string& declarator) const {
    std::string base;
    std::string decl = declarator;
    switch (kind) {
    case Kind::Void: base = "void"; break;
    case Kind::Bool: base = "bool"; break;
    case Kind::Int: base = intName(bits, isSigned); break;
    case Kind::Float: base = bits == 32 ? "float" : (bits == 64 ? "double" : "long double"); break;
    case Kind::Unknown: base = "void"; break;
    case Kind::Struct: base = "struct " + (name.empty() ? std::string("s_anon") : name); break;
    case Kind::Pointer: {
        // void* rather than an endless chain when the target is unknown.
        if (!pointee) return "void*" + (decl.empty() ? "" : " " + decl);
        std::string inner = "*" + decl;
        if (pointee->kind == Kind::Array || pointee->kind == Kind::Function) inner = "(" + inner + ")";
        return pointee->spell(inner);
    }
    case Kind::Array: {
        std::string inner = decl + "[" + std::to_string(arrayCount) + "]";
        return element ? element->spell(inner) : "void " + inner;
    }
    case Kind::Function: {
        std::string args;
        for (size_t i = 0; i < params.size(); ++i) {
            if (i) args += ", ";
            args += params[i] ? params[i]->spell() : "void";
        }
        if (variadic) args += params.empty() ? "..." : ", ...";
        if (args.empty()) args = "void";
        std::string inner = decl + "(" + args + ")";
        return returnType ? returnType->spell(inner) : "void " + inner;
    }
    }
    if (decl.empty()) return base;
    if (!decl.empty() && decl[0] == '*') return base + decl;
    return base + " " + decl;
}

TypeTable::TypeTable() {
    Type* v = alloc();
    v->kind = Kind::Void;
    void_ = v;
    Type* b = alloc();
    b->kind = Kind::Bool;
    b->bits = 1;
    bool_ = b;
    Type* u = alloc();
    u->kind = Kind::Unknown;
    unknown_ = u;
}

Type* TypeTable::alloc() {
    owned_.push_back(std::make_unique<Type>());
    return owned_.back().get();
}

TypeRef TypeTable::integer(unsigned bits, bool isSigned) {
    if (bits == 1) return bool_;
    auto key = std::make_pair(bits, isSigned);
    auto it = ints_.find(key);
    if (it != ints_.end()) return it->second;
    Type* t = alloc();
    t->kind = Kind::Int;
    t->bits = bits;
    t->isSigned = isSigned;
    ints_[key] = t;
    return t;
}

TypeRef TypeTable::floating(unsigned bits) {
    auto it = floats_.find(bits);
    if (it != floats_.end()) return it->second;
    Type* t = alloc();
    t->kind = Kind::Float;
    t->bits = bits;
    floats_[bits] = t;
    return t;
}

TypeRef TypeTable::pointer(TypeRef pointee) {
    auto it = pointers_.find(pointee);
    if (it != pointers_.end()) return it->second;
    Type* t = alloc();
    t->kind = Kind::Pointer;
    t->pointee = pointee;
    pointers_[pointee] = t;
    return t;
}

TypeRef TypeTable::array(TypeRef element, u64 count) {
    auto key = std::make_pair(element, count);
    auto it = arrays_.find(key);
    if (it != arrays_.end()) return it->second;
    Type* t = alloc();
    t->kind = Kind::Array;
    t->element = element;
    t->arrayCount = count;
    arrays_[key] = t;
    return t;
}

TypeRef TypeTable::function(TypeRef ret, std::vector<TypeRef> params, bool variadic) {
    Type* t = alloc();
    t->kind = Kind::Function;
    t->returnType = ret;
    t->params = std::move(params);
    t->variadic = variadic;
    return t;
}

Type* TypeTable::makeStruct(const std::string& name) {
    auto it = named_.find(name);
    if (it != named_.end()) return it->second;
    Type* t = alloc();
    t->kind = Kind::Struct;
    t->name = name;
    named_[name] = t;
    return t;
}

TypeRef TypeTable::byName(const std::string& name) const {
    auto it = named_.find(name);
    return it == named_.end() ? nullptr : it->second;
}

std::vector<const Type*> TypeTable::structs() const {
    std::vector<const Type*> out;
    for (const auto& t : owned_)
        if (t->kind == Kind::Struct) out.push_back(t.get());
    std::sort(out.begin(), out.end(), [](const Type* a, const Type* b) { return a->name < b->name; });
    return out;
}

} // namespace dc::types
