/* Reference decompilation of tests/corpus/behemoth.dll exports.
 * The readability bar for this project. See README.md. */

/* confidence: HIGH */
INT count_leading_zeros(INT arg1) {
    if (arg1 == 0) {
        return 32;
    }
    INT var1 = 0;
    if ((uint32_t)arg1 <= 65535) {
        var1 = 16;
        arg1 <<= 16;
    }
    if ((uint32_t)arg1 <= 16777215) {
        var1 += 8;
        arg1 <<= 8;
    }
    if ((uint32_t)arg1 <= 268435455) {
        var1 += 4;
        arg1 <<= 4;
    }
    if ((uint32_t)arg1 > 1073741823) {
        return var1 + (arg1 < 0x80000000);
    }
    var1 += 2;
    arg1 <<= 2;
    return var1 + (arg1 < 0x80000000);
}

#pragma pack(push, 1)
struct s_decode_packet_arg1 {
    INT field_0;  /* +0x0, 4 bytes */
    DWORD field_4;  /* not accessed */
    INT field_8;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    ULONGLONG field_10;  /* +0x10, 8 bytes, address taken, width unobserved */
};
#pragma pack(pop)
INT decode_packet(struct s_decode_packet_arg1* arg1, INT arg2, LONGLONG* arg3, LONGLONG* arg4) {
    if (arg2 <= 15) {
        return -1;
    }
    if (arg1->field_0 != DEADBEEF) {
        return -2;
    }
    if ((uint32_t)arg1->field_8 > 65536) {
        return -3;
    }
    if ((arg1->field_8 + 15) >= arg2) {
        return -4;
    }
    INT var1 = arg1->field_8;
    if (var1 != 0) {
        BYTE* p = (BYTE*)(&arg1->field_10);
        INT var2 = 0;
        INT* var3 = (INT*)(p + var1);
        do {
            var1 = var2 + *p;
            ++p;
            var2 = var1;
        } while ((int64_t)(p) != (int64_t)(var3));
    }
    if (arg1->field_c != var1) {
        return -5;
    }
    *arg3 = *(int64_t*)&arg1->field_0;
    arg3[1] = *(int64_t*)&arg1->field_8;
    *arg4 = (int64_t)(&arg1->field_10);
    return arg1->field_8 + 16;
}

/* confidence: HIGH */
#pragma pack(push, 1)
struct s_dict_get_arg1 {
    LONGLONG field_0;  /* +0x0, 8 bytes */
    DWORD field_8;  /* +0x8, 4 bytes */
    DWORD field_c;  /* not accessed */
    LONGLONG field_10;  /* +0x10, 8 bytes */
};
#pragma pack(pop)
INT dict_get(const struct s_dict_get_arg1* arg1, CHAR* arg2, INT arg3, INT* arg4) {
    ULONGLONG var1 = FNV1A_OFFSET_64;
    INT* var8 = 0;
    INT result = 0;

    if (arg3 != 0) {
        BYTE* p = (BYTE*)arg2;
        do {
            var1 = (*p ^ var1) * FNV1A_PRIME_64;
            ++p;
        } while ((int64_t)(arg3 + arg2) != (int64_t)(p));
    }
    const DWORD var3 = arg1->field_8;
    const ULONGLONG var4 = var1 / var3;
    ULONGLONG var5 = var1 % var3;
    LONGLONG* var6 = (LONGLONG*)arg1->field_0;
    INT var7 = 0;
    const INT var9 = var5;
    while (true) {
        result = *(int32_t*)(((char*)var6 + (int32_t)var5 * 24) + 16);
        if (result == 0) break;
        if (*(int64_t*)((char*)var6 + (int32_t)var5 * 24) == var1 && result == arg3) {
            var8 = (INT*)((char*)var6 + (int32_t)var5 * 24);
            if (arg3 <= 0) {
                var7 = 1;
                break;
            }
            LONGLONG count = 0;
            while ((uint8_t)((CHAR*)(var8[2] + arg1->field_10))[count] == *(uint8_t*)(arg2 + count)) {
                ++count;
                if (arg3 != count) continue;
                var7 = 1;
                *arg4 = var8[3];
                return 1;
            }
        }
        const INT t80 = var5 + 1;
        const DWORD var11 = t80 / var3;
        const INT t81 = t80 % var3;
        var5 = t81;
        if (var9 != t81) continue;
        var7 = 2;
        break;
    }
    if (var7 == 0) {
        return result;
    } else if (var7 == 1) {
        *arg4 = var8[3];
        return 1;
    }
    return 0;
}

/* confidence: HIGH */
#pragma pack(push, 1)
struct s_dict_set_arg1 {
    void* field_0;  /* +0x0, 8 bytes */
    INT field_8;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    LONGLONG field_10;  /* +0x10, 8 bytes */
    INT field_18;  /* +0x18, 4 bytes */
    INT field_1c;  /* +0x1c, 4 bytes */
};
#pragma pack(pop)
#pragma pack(push, 1)
struct s_shape_35d90eab {
    LONGLONG field_0;  /* +0x0, 8 bytes */
    INT field_8;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    INT field_10;  /* +0x10, 4 bytes */
    INT field_14;  /* +0x14, 4 bytes */
};
#pragma pack(pop)
#pragma pack(push, 1)
struct s_shape_47f953cf {
    LONGLONG field_0;  /* +0x0, 8 bytes */
    INT field_8;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    INT field_10;  /* +0x10, 4 bytes */
};
#pragma pack(pop)
INT dict_set(struct s_dict_set_arg1* arg1, CHAR* arg2, CHAR* arg3, INT arg4) {
    DWORD result;
    struct s_dict_set_var13* var9 = 0;
    struct s_dict_set_var19* var13;
    INT var15 = 0;

    if ((uint32_t)arg1->field_c >= (arg1->field_8 - 1)) {
        result = -1;
    } else {
        if ((uint32_t)arg1->field_1c < (arg1->field_18 + (int32_t)(arg3 + 1))) {
            return -2;
        }
        ULONGLONG var1 = FNV1A_OFFSET_64;
        const DWORD var2 = arg1->field_8;
        CHAR* var3 = (CHAR*)arg1->field_18;
        if (arg3 != 0) {
            BYTE* p = (BYTE*)arg2;
            do {
                var1 = ((uint32_t)(*p) ^ var1) * FNV1A_PRIME_64;
                ++p;
            } while ((int64_t)(arg3 + (int64_t)arg2) != (int64_t)(p));
        }
        const ULONGLONG var5 = var1 / (uint64_t)(var2);
        ULONGLONG var6 = var1 % (uint64_t)(var2);
        LONGLONG* var7 = (LONGLONG*)(var6 * 24);
        INT var8 = 0;
        if (*(int32_t*)(((char*)arg1->field_0 + var6 * 24) + 16)) {
            struct s_dict_set_var13* var10 = (struct s_dict_set_var13*)((char*)arg1->field_0 + var6 * 24);
            INT var11 = var10->field_10;
            var15 = 0;
            do {
                if (var10->field_0 == var1 && (int32_t)arg3 == var11) {
                    var9 = var10;
                    if ((int32_t)arg3 <= 0) {
                        var15 = 1;
                        var8 = 0;
                        break;
                    }
                    LONGLONG count2 = 0;
                    while ((uint8_t)((CHAR*)(arg1->field_10 + var10->field_8))[count2] == *(uint8_t*)((char*)arg2 + count2)) {
                        ++count2;
                        if ((int64_t)(arg3) != (int64_t)(count2)) continue;
                        var8 = 2 != 0 ? 1 : 0;
                        if (var8 != 0) {
                            var9->field_c = arg4;
                        } else {
                            j_memcpy(arg1->field_10 + (int32_t)var3, arg2, (int64_t)arg3);
                            *(int8_t*)((char*)((int32_t)(arg3 + (int64_t)var3)) + arg1->field_10) = 0;
                            arg1->field_18 += (int32_t)(arg3 + 1);
                            var13 = (struct s_dict_set_var19*)((char*)var7 + (int64_t)arg1->field_0);
                            var13->field_0 = var1;
                            var13->field_10 = (int32_t)arg3;
                            var13->field_14 = -1;
                            var13->field_8 = (int32_t)var3;
                            var13->field_c = arg4;
                            ++arg1->field_c;
                        }
                        return 0;
                    }
                }
                const INT t150 = var6 + 1;
                const DWORD var14 = (uint32_t)t150 / var2;
                const INT t151 = (uint32_t)t150 % var2;
                var7 = (LONGLONG*)(t151 * 24);
                var10 = (struct s_dict_set_var13*)((char*)arg1->field_0 + (int64_t)var7);
                var11 = var10->field_10;
                var8 = var15;
                var6 = t151;
            } while (var11 != 0);
        }
        if (var15 != 0) {
            var8 = 1;
        }
        if (var8 != 0) {
            var9->field_c = arg4;
        } else {
            j_memcpy(arg1->field_10 + (int32_t)var3, arg2, (int64_t)arg3);
            *(int8_t*)((char*)((int32_t)(arg3 + (int64_t)var3)) + arg1->field_10) = 0;
            arg1->field_18 += (int32_t)(arg3 + 1);
            var13 = (struct s_dict_set_var19*)((char*)var7 + (int64_t)arg1->field_0);
            var13->field_0 = var1;
            var13->field_10 = (int32_t)arg3;
            var13->field_14 = -1;
            var13->field_8 = (int32_t)var3;
            var13->field_c = arg4;
            ++arg1->field_c;
        }
        result = 0;
    }
    return result;
}

/* confidence: HIGH */
INT djb2(const BYTE* arg1) {
    INT result = 5381;

    if (*arg1 == 0) {
        return result;
    }
    INT var1 = *arg1;
    do {
        result = result + (result << 5) + var1;
        ++arg1;
        var1 = *arg1;
    } while (*arg1 != 0);
    return result;
}

#pragma pack(push, 1)
struct s_encode_packet_arg1 {
    INT field_0;  /* +0x0, 4 bytes */
    SHORT field_4;  /* +0x4, 2 bytes */
    SHORT field_6;  /* +0x6, 2 bytes */
    INT field_8;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    ULONGLONG field_10;  /* +0x10, 8 bytes, address taken, width unobserved */
};
#pragma pack(pop)
DWORD encode_packet(struct s_encode_packet_arg1* arg1, INT arg2, WORD arg3, WORD arg4, BYTE* arg5, DWORD arg6) {
    INT var1;
    const INT result = arg6 + 16;

    if (result > arg2) {
        return -1;
    }
    arg1->field_0 = DEADBEEF;
    arg1->field_4 = arg3;
    arg1->field_6 = arg4;
    arg1->field_8 = arg6;
    if (arg6 == 0) {
        arg6 = 0;
        arg1->field_c = 0;
        j_memcpy(&arg1->field_10, arg5, arg6);
        return result;
    }
    var1 = 0;
    BYTE* p = arg5;
    do {
        var1 += (uint32_t)(*p);
        ++p;
    } while ((int64_t)(p) != (int64_t)(arg5 + arg6));
    arg1->field_c = var1;
    j_memcpy(&arg1->field_10, arg5, arg6);
    return result;
}

/* confidence: HIGH */
INT fnv1a_hash(BYTE* arg1, LONGLONG arg2) {
    BYTE* var2;

    if (arg2 == 0) {
        return FNV1A_OFFSET_32;
    }
    DWORD result = FNV1A_OFFSET_32;
    CHAR* var1 = (CHAR*)(arg2 + arg1);
    do {
        result = (result ^ *arg1) * 16777619;
        var2 = arg1;
        ++arg1;
    } while ((int64_t)(var1) != (int64_t)(var2 + 1));
    return result;
}

LONGLONG fnv1a_hash64(CHAR* arg1, LONGLONG arg2) {
    LONGLONG result = FNV1A_OFFSET_64;

    if (arg2 == 0) {
        return result;
    }
    BYTE* p = (BYTE*)arg1;
    do {
        result = (result ^ *p) * FNV1A_PRIME_64;
        ++p;
    } while ((int64_t)(arg2 + arg1) != (int64_t)(p));
    return result;
}

/* confidence: HIGH */
ULONGLONG gcd(ULONGLONG arg1, ULONGLONG arg2) {
    ULONGLONG var2;

    if (arg2 == 0) {
        return arg1;
    }
    do {
        const ULONGLONG var1 = arg1 / arg2;
        var2 = arg1 % arg2;
        arg1 = arg2;
        arg2 = var2;
    } while (var2 != 0);
    return arg1;
}

/* confidence: HIGH */
bool is_prime(ULONGLONG arg1, LONGLONG arg2, LONGLONG arg3, LONGLONG arg4) {
    INT var5 = 0;

    if (arg1 <= 1) {
        return 0;
    }
    if (arg1 <= 3) {
        return 1;
    }
    const bool result = false;
    if ((!(arg1 & 1)) || (arg1 * -6148914691236517205LL) <= 0x5555555555555555LL) {
        return result;
    }
    if (arg1 > 24) {
        if ((arg1 * -3689348814741910323LL) <= 0x3333333333333333LL || (arg1 * 0x6db6db6db6db6db7LL) <= 0x2492492492492492LL) {
            return result;
        }
        ULONGLONG var1 = 5;
        var5 = 0;
        while (true) {
            const LONGLONG var2 = var1 + 6;
            if (arg1 < (var2 * var2)) break;
            const ULONGLONG var3 = arg1 / var2;
            if ((arg1 % var2) == 0) {
                var5 = 1;
                break;
            }
            const LONGLONG t25 = var1 + 8;
            const ULONGLONG var4 = arg1 / t25;
            var1 = var2;
            if (arg1 % t25) continue;
            var5 = 2;
            break;
        }
    }
    const bool flag = var5 != 0 ? 1 : 0;
    if (flag) {
        return 0;
    }
    return 1;
}

/* confidence: HIGH */
INT* mat4_mul(INT* arg1, INT* arg2, INT* arg3) {
    INT i = 0;
    INT* p2;
    INT* q = arg2 + 16;

    do {
        LONGLONG count = 0;
        INT* var1 = q;
        do {
            p2 = q - 16;
            INT var2 = 0;
            INT* p = arg1;
            do {
                var2 += *p * *p2;
                p2 = p2 + 4;
                p = p + 1;
            } while (q != p2);
            arg3[count] = var2;
            ++count;
            q = q + 1;
        } while (count != 4);
        arg1 = arg1 + 4;
        i += 4;
        arg3 = arg3 + 4;
        q = var1;
    } while (i != 16);
    return (p2 + 4);
}

/* confidence: HIGH */
#pragma pack(push, 1)
struct s_mat4_trace_arg1 {
    INT field_0;  /* +0x0, 4 bytes */
    DWORD field_4;  /* not accessed */
    ULONGLONG field_8;  /* not accessed */
    DWORD field_10;  /* not accessed */
    INT field_14;  /* +0x14, 4 bytes */
    ULONGLONG field_18;  /* not accessed */
    ULONGLONG field_20;  /* not accessed */
    INT field_28;  /* +0x28, 4 bytes */
    DWORD field_2c;  /* not accessed */
    ULONGLONG field_30;  /* not accessed */
    DWORD field_38;  /* not accessed */
    INT field_3c;  /* +0x3c, 4 bytes */
};
#pragma pack(pop)
INT mat4_trace(const struct s_mat4_trace_arg1* arg1) {
    return arg1->field_14 + arg1->field_0 + arg1->field_28 + arg1->field_3c;
}

/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* 2 loops */
/* confidence: HIGH */
void mat4_transpose(INT* arg1, LONGLONG arg2) {
    INT* var1 = (INT*)(arg2 + 64);
    INT i = 0;

    for (; i != 4; ++i) {
        INT* q = var1 - 16;
        INT* p = arg1;
        do {
            *q = *p;
            q = q + 4;
            p = p + 1;
        } while (q != var1);
        arg1 = arg1 + 4;
        var1 = q + 5;
    }
}

/* modpow @ 0x2fe0  size=199 */
/* frame: prolog 14 bytes, no frame pointer (sp-relative), 0x40 bytes reserved, saves rbx, rsi, rdi, rbp, r12, r13, r14   (from .pdata) */
/* calls j___umodti3; one loop */
/* confidence: HIGH */
ULONGLONG modpow(ULONGLONG arg1, ULONGLONG arg2, ULONGLONG arg3) {
    ULONGLONG var1 = 0;
    ULONGLONG var2 = 0;

    if (arg3 == 1) {
        return 0;
    }
    const ULONGLONG var3 = arg1 / arg3;
    ULONGLONG var4 = arg1 % arg3;
    if (arg2 == 0) {
        return 1;
    }
    ULONGLONG result = 1;
    BYTE* var5 = (BYTE*)&var2;
    BYTE* var6 = (BYTE*)&var1;
    do {
        if (arg2 & 1) {
            var2 = arg3;
            var1 = result * var4;
            j___umodti3(var6, var5);
            result = arg1;
        }
        var2 = arg3;
        var1 = var4 * var4;
        j___umodti3(var6, var5);
        arg2 >>= 1;
        var4 = arg1;
    } while (arg2 != 0);
    return result;
}

/* murmur3_32 @ 0x1410  size=204 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* calls _rotl; one loop */
/* confidence: HIGH */
DWORD murmur3_32(INT* arg1, INT arg2, DWORD arg3) {
    const INT var2 = (arg2 >= 0 ? arg2 : (arg2 + 3)) >> 2;
    INT t53;
    INT var4;

    if (arg2 > 3) {
        LONGLONG count = 0;
        DWORD var1 = arg3;
        do {
            const DWORD Value = arg1[count] * 0xcc9e2d51;
            arg3 = _rotl((uint32_t)(_rotl(Value, 15) * 461845907 ^ var1), 13) + _rotl((uint32_t)(_rotl(Value, 15) * 461845907 ^ var1), 13) * 4 - 0x19ab949c;
            var1 = _rotl((uint32_t)(_rotl(Value, 15) * 461845907 ^ var1), 13) + _rotl((uint32_t)(_rotl(Value, 15) * 461845907 ^ var1), 13) * 4 - 0x19ab949c;
            ++count;
        } while (var2 > (int32_t)count);
    }
    const LONGLONG t55 = (int64_t)((char*)arg1 + (var2 << 2));
    switch (arg2 & 3) {
        case 1:
            BYTE* var3 = (BYTE*)t55;
            arg3 ^= _rotl((uint32_t)((*var3 ^ 0) * 0xcc9e2d51), 15) * 461845907;
            break;
        case 3:
            var3 = (BYTE*)t55;
            arg3 ^= _rotl((uint32_t)((*var3 ^ (((uint32_t)var3[1] << 8) ^ ((uint32_t)*(uint8_t*)(t55 + 2) << 16))) * 0xcc9e2d51), 15) * 461845907;
            t53 = (arg2 ^ arg3 >> 16) ^ (arg2 ^ arg3);
            var4 = (((uint32_t)(t53 * 0x85ebca6b) >> 13) ^ t53 * 0x85ebca6b) * 0xc2b2ae35;
            return ((uint32_t)var4 >> 16) ^ var4;
        case 2:
            var3 = (BYTE*)t55;
            arg3 ^= _rotl((uint32_t)((*var3 ^ (((uint32_t)var3[1] << 8) ^ 0)) * 0xcc9e2d51), 15) * 461845907;
            t53 = (arg2 ^ arg3 >> 16) ^ (arg2 ^ arg3);
            var4 = (((uint32_t)(t53 * 0x85ebca6b) >> 13) ^ t53 * 0x85ebca6b) * 0xc2b2ae35;
            return ((uint32_t)var4 >> 16) ^ var4;
        default:
            break;
    }
    t53 = (arg2 ^ arg3 >> 16) ^ (arg2 ^ arg3);
    var4 = (((uint32_t)(t53 * 0x85ebca6b) >> 13) ^ t53 * 0x85ebca6b) * 0xc2b2ae35;
    return ((uint32_t)var4 >> 16) ^ var4;
}

/* next_power_of_2 @ 0x3370  size=51 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* confidence: HIGH */
DWORD next_power_of_2(INT arg1) {
    if ((uint32_t)arg1 <= 1) {
        return 1;
    }
    const INT t11 = ((uint32_t)(arg1 - 1) >> 1) | (arg1 - 1);
    const INT var1 = (((uint32_t)t11 >> 2) | t11 >> 4) | (((uint32_t)t11 >> 2) | t11);
    return ((((uint32_t)var1 >> 8) | var1 >> 16) | (((uint32_t)var1 >> 8) | var1)) + 1;
}

/* parse_hex @ 0x1610  size=215 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* one loop */
/* confidence: HIGH */
INT parse_hex(BYTE* arg1, INT* arg2) {
    INT i = 0;
    INT var2 = 0;
    CHAR var3 = 0;
    INT var4;

    if ((arg1 == 0) || (arg2 == 0)) {
        return 0;
    }
    if (*arg1 == 48) {
        i = 0;
        var2 = ((uint8_t)(arg1[1] & 0xffffffdf) == 88) * 2;
        if (arg1[var2] == 0) {
            return 0;
        }
    } else {
        var2 = 0;
        i = 0;
        if (*arg1 == 0) {
            return 0;
        }
    }
    BYTE* p = arg1 + var2;
    INT var1 = 0;
    const bool flag = false;
    while (true) {
        var3 = *p;
        if (var3 >= '0' && var3 <= '9') {
            var4 = (int32_t)var3 - 48;
        } else if ((uint32_t)*p < 97 || (uint32_t)*p > 102) {
            if (var3 < 'A' || var3 > 'F') break;
            var4 = (int32_t)var3 - 55;
        } else {
            var4 = (int32_t)*p - 87;
        }
        ++p;
        var1 = (var1 << 4) | var4;
        ++i;
        ++var2;
        if (i != 8) continue;
        *arg2 = var1;
        return var2;
    }
    if (i == 0) {
        return i;
    }
    *arg2 = var1;
    return var2;
}

/* parse_int @ 0x1510  size=250 */
/* frame: prolog 3 bytes, no frame pointer (sp-relative), saves rbx, rsi, rdi   (from .pdata) */
/* 2 loops */
/* confidence: HIGH */
BYTE* parse_int(BYTE* arg1, INT* arg2) {
    INT var1;
    LONGLONG var2;
    INT var3;
    INT var4 = 0;
    const BYTE t61 = arg1 == NULL | arg2 == NULL;
    LONGLONG var7 = 0;

    if (t61 != 0) {
        return 0;
    }
    if (*arg1 == 9 || *arg1 == 32) {
        LONGLONG count = 1;
        do {
            var1 = arg1[count];
            var2 = var7;
            var7 = count;
            ++count;
            if (arg1[var7] == 9) continue;
            var4 = t61;
        } while (arg1[var2] == 32);
    } else {
        var2 = 0;
        var1 = *arg1;
        var4 = t61;
    }
    if (var1 == 45) {
        var3 = var2 + 1;
        var4 = 1;
    } else {
        var3 = var2 + (var1 == 43);
    }
    if (arg1[var3] < '0' || arg1[var3] > '9') {
        return 0;
    }
    BYTE* result = (BYTE*)(var3 + 1);
    INT var5 = arg1[var3];
    INT var6 = 0;
    bool flag = false;
    while ((int32_t)(((uint64_t)((uint32_t)(INT32_MAX - (int8_t)(var5 - 48))) * 0xcccccccd) >> 35) >= var6) {
        if (arg1[(int64_t)result] < '0' || arg1[(int64_t)result] > '9') {
            flag = true;
            break;
        }
        var6 = (int8_t)(var5 - 48) + (var6 * 5) * 2;
        var5 = (arg1[(int64_t)result]);
        result = (result + 1);
    }
    if (flag) {
        const LONGLONG t59 = (int8_t)(var5 - 48) + (var6 * 5) * 2;
        *arg2 = (uint8_t)var4 != 0 ? -(t59) : (int32_t)t59;
        return result;
    }
    return 0;
}

/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* calls _byteswap_ulong */
/* confidence: HIGH */
DWORD reverse_bits(DWORD arg1) {
    const INT t11 = ((arg1 >> 1) & 0x55555555) | (arg1 * 2 & 0xaaaaaaaa);

    const INT var1 = (((uint32_t)t11 >> 2) & 0x33333333) | ((t11 << 2) & MSVC_UNINIT_STACK);
    return _byteswap_ulong((((uint32_t)var1 >> 4) & 0xf0f0f0f) | ((var1 << 4) & 0xf0f0f0f0));
}

/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* confidence: HIGH */
#pragma pack(push, 1)
struct s_ring_alloc_arg1 {
    LONGLONG field_0;  /* +0x0, 8 bytes */
    INT count;  /* +0x8, 4 bytes */
    INT field_c;  /* +0xc, 4 bytes */
    INT field_10;  /* +0x10, 4 bytes */
    INT field_14;  /* +0x14, 4 bytes */
};
#pragma pack(pop)
LONGLONG ring_alloc(struct s_ring_alloc_arg1* arg1, DWORD arg2) {
    if ((arg2 == 0) || (arg1->count - arg1->field_14) < arg2) {
        return 0;
    }
    const INT t9 = (arg2 + 7) & 0xfffffff8;
    if ((uint32_t)(arg1->count - arg1->field_14) < t9) {
        return 0;
    }
    const INT var1 = arg1->field_c;
    const DWORD var2 = var1 + t9;
    if (arg1->count >= var2) {
        arg1->field_c = var2;
        arg1->field_14 += t9;
        return var1 + arg1->field_0;
    }
    if ((uint32_t)arg1->field_10 < t9) {
        return 0;
    }
    arg1->field_c = (t9);
    arg1->field_14 += t9;
    return 0 + arg1->field_0;
}

/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* confidence: HIGH */
#pragma pack(push, 1)
struct s_ring_free_arg1 {
    ULONGLONG field_0;  /* not accessed */
    INT field_8;  /* +0x8, 4 bytes */
    DWORD field_c;  /* not accessed */
    INT field_10;  /* +0x10, 4 bytes */
    INT field_14;  /* +0x14, 4 bytes */
};
#pragma pack(pop)
INT ring_free(struct s_ring_free_arg1* arg1, INT arg2) {
    if (arg1->field_14 < ((arg2 + 7) & 0xfffffff8)) {
        return -1;
    }
    const INT var1 = arg1->field_10 + ((arg2 + 7) & 0xfffffff8);
    const INT var2 = arg1->field_8;
    arg1->field_14 -= (arg2 + 7) & 0xfffffff8;
    arg1->field_10 = (uint32_t)var1 < var2 ? var1 : var1 - var2;
    return 0;
}

/* ring_init @ 0x1890  size=23 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* confidence: HIGH */
#pragma pack(push, 1)
struct s_ring_init_arg1 {
    LONGLONG field_0;  /* +0x0, 8 bytes */
    INT field_8;  /* +0x8, 4 bytes */
    INT flag;  /* +0xc, 4 bytes */
    LONGLONG field_10;  /* +0x10, 8 bytes */
};
#pragma pack(pop)
void ring_init(struct s_ring_init_arg1* arg1, LONGLONG arg2, INT arg3) {
    arg1->field_0 = arg2;
    arg1->field_8 = arg3;
    arg1->flag = 0;
    arg1->field_10 = 0;
}

/* 3 loops; has gotos */
/* confidence: MEDIUM - 1 residual goto */
INT split_words(const BYTE* arg1, CHAR* arg2, INT arg3, INT* arg4, INT arg5) {
    BYTE* var4;
    BYTE var8;

    if (arg5 <= 0 || *arg1 == 0) {
        return 0;
    }
    INT var1 = *arg1;
    INT result = 0;
    BYTE* var2 = NULL;
    bool flag = false;
    INT var3 = 0;
    do {
        if (var1 >= 9 && var1 <= 10) {
loc_172d:
            BYTE* q = (BYTE*)(int32_t)(var2 + 1);
            do {
                var4 = var2;
                var2 = q;
                ++q;
                if (arg1[(int64_t)var2] >= '\t' && arg1[(int64_t)var2] <= '\n') continue;
            } while (arg1[(int64_t)var4] == 32);
            if (arg1[(int64_t)var2] == 0) break;
        } else if ((uint8_t)var1 == 32) {
            goto loc_172d;  /* join of 2 paths */
        }
        *arg4 = var3;
        if (arg1[(int64_t)var2] != 0) {
            INT var5 = arg1[(int64_t)var2];
            BYTE* p = (BYTE*)((int32_t)var2 + 1);
            CHAR* var6 = (CHAR*)(var3 - (int64_t)((int32_t)var2) + arg2);
            INT var7 = flag;
            while (true) {
                if ((int8_t)var5 <= '\n') {
                    var2 = (BYTE*)(int32_t)(p - 1);
                    if ((int8_t)var5 > 8) break;
                } else {
                    var2 = (BYTE*)(int32_t)(p - 1);
                    if ((uint8_t)var5 == 32) break;
                }
                if (var3 >= (arg3 - 1)) {
                    var7 = 2;
                    break;
                }
                *((var6 + (int64_t)p) - 1) = var5;
                if (arg1[(int64_t)p] == 0) {
                    var7 = 1;
                    break;
                }
                var5 = arg1[(int64_t)p];
                ++p;
                ++var3;
            }
            if (var7 != 0) {
                if (var7 != 1) {
                    flag = true;
                    break;
                }
                ++var3;
                var2 = (BYTE*)(uint32_t)p;
            }
        }
        if (var3 >= (arg3 - 1)) {
            flag = true;
            break;
        }
        arg2[var3] = 0;
        ++result;
        if (arg5 <= result) break;
        var8 = arg1[(int64_t)var2];
        arg4 = arg4 + 1;
        ++var3;
        var1 = var8;
    } while (var8 != 0);
    if (flag) {
        return -1;
    }
    return result;
}

/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* one loop */
/* confidence: HIGH */
INT strcasecmp_custom(const CHAR* arg1, const CHAR* arg2, INT arg3) {
    INT var2 = 0;
    INT var3 = 0;
    INT var5 = 0;

    INT var1 = *arg1;
    if (*arg1 == 0) {
        return 0 - (*arg2);
    }
    while (true) {
        CHAR var4 = *arg2;
        var2 = var4;
        if (var4 == 0) break;
        var3 = (uint8_t)(var4 - 65) < 26 ? (var4 + 32) : var4;
        if ((uint8_t)((uint8_t)(var1 - 65) < 26 ? (var1 + 32) : var1) != (uint8_t)var3) {
            var5 = 1;
            break;
        }
        if (*(arg1 + 1) == 0) {
            var5 = 2;
            break;
        }
        ++arg1;
        var1 = *arg1;
        ++arg2;
    }
    if (var5 == 0) {
        return var1 - var2;
    }
    if (var5 == 1) {
        return (int8_t)((uint8_t)(var1 - 65) < 26 ? (var1 + 32) : var1) - (int8_t)var3;
    }
    return 0 - arg2[1];
}

/* tree_insert @ 0x1ca0  size=68 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* one loop */
/* confidence: HIGH */
#pragma pack(push, 1)
struct s_shape_81eed7f4 {
    INT count;  /* +0x0, 4 bytes */
    DWORD field_4;  /* not accessed */
    LONGLONG field_8;  /* +0x8, 8 bytes */
    LONGLONG field_10;  /* +0x10, 8 bytes */
};
#pragma pack(pop)
LONGLONG* tree_insert(LONGLONG* arg1, const INT* arg2) {
    LONGLONG* var3;

    if (arg1 == 0) {
        return (int64_t*)arg2;
    }
    const INT var1 = *arg2;
    struct s_tree_insert_var2* var2 = (struct s_tree_insert_var2*)arg1;
    while (true) {
        if (var1 < var2->count) {
            var3 = (LONGLONG*)var2->field_8;
            if (var3 == 0) {
                var2->field_8 = (int64_t)arg2;
                return arg1;
            }
        } else {
            var3 = (LONGLONG*)var2->field_10;
            if (var3 == 0) {
                var2->field_10 = (int64_t)arg2;
                return arg1;
            }
        }
        var2 = (struct s_tree_insert_var2*)var3;
    }
}

/* one loop */
/* confidence: HIGH */
#pragma pack(push, 1)
struct s_tree_search_arg1 {
    INT count;  /* +0x0, 4 bytes */
    DWORD field_4;  /* not accessed */
    LONGLONG field_8;  /* +0x8, 8 bytes */
    LONGLONG field_10;  /* +0x10, 8 bytes */
};
#pragma pack(pop)
LONGLONG* tree_search(const struct s_tree_search_arg1* arg1, INT arg2) {
    bool flag = false;

    if (arg1 == 0) {
        return 0;
    }
    while (arg1->count != arg2) {
        arg1 = (struct s_tree_search_arg1*)(1 ? arg1->field_10 : arg1->field_8);
        if (arg1 != 0) continue;
        flag = true;
        break;
    }
    if (flag) {
        return 0;
    }
    return (int64_t*)arg1;
}

/* xoshiro_next @ 0x2e10  size=72 */
/* frame: prolog 0 bytes, no frame pointer (sp-relative)   (from .pdata) */
/* calls _rotr64, _rotl64 */
/* confidence: HIGH */
ULONGLONG xoshiro_next(LONGLONG* arg1) {
    const LONGLONG var1 = arg1[2] ^ *arg1;
    const LONGLONG t10 = arg1[1];
    *arg1 ^= arg1[3] ^ t10;
    const ULONGLONG var2 = _rotr64((arg1[3] ^ t10), 19);
    const LONGLONG var3 = arg1[1] << 17;
    arg1[1] = t10 ^ var1;
    arg1[3] = var2;
    arg1[2] = var3 ^ var1;
    return _rotl64((t10 * 5), 7) * 9;
}

/* xoshiro_seed @ 0x2e60  size=103 */
/* frame: prolog 1 bytes, no frame pointer (sp-relative), saves rbx   (from .pdata) */
/* one loop */
/* confidence: HIGH */
void xoshiro_seed(LONGLONG* arg1, LONGLONG arg2) {
    LONGLONG i = arg2;

    do {
        i -= 0x61c8864680b583ebLL;
        const LONGLONG t16 = ((uint64_t)i >> 30) ^ i;
        const LONGLONG var2 = (((uint64_t)(t16 * -4658895280553007687LL) >> 27) ^ t16 * -4658895280553007687LL) * -7723592293110705685LL;
        *arg1 = var2 ^ ((uint64_t)var2 >> 31);
        arg1 = arg1 + 1;
    } while (i != arg2 + 0x78dde6e5fd29f054LL);
}
