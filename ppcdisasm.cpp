#include <iostream>
#include <string>
#include "ppcdisasm.h"

using namespace std;

template< typename... Args >
std::string my_sprintf(const char* format, Args... args)
{
    int length = std::snprintf( nullptr, 0, format, args... );
    if (length <= 0)
        return {}; /* empty string in C++11 */

    char* buf = new char[length + 1];
    std::snprintf(buf, length + 1, format, args...);

    std::string str(buf);
    delete[] buf;
    return str;
}

const char *bx_mnem[4] = {
    "b", "bl", "ba", "bla"
};

const char *opc_idx_ldst[24] = { /* indexed load/store opcodes */
    "lwzx", "lwzux", "lbzx", "lbzux", "stwx", "stwux", "stbx", "stbux", "lhzx",
    "lhzux", "lhax", "lhaux", "sthx", "sthux", "", "", "lfsx", "lfsux", "lfdx",
    "lfdux", "stfsx", "stfsux", "stfdx", "stfdux"
};

const char *opc_logic[16] = { /* indexed load/store opcodes */
    "and", "andc", "", "nor", "", "", "", "", "eqv", "xor", "", "", "orc", "or",
    "nand", ""
};

const char *opc_subs[16] = { /* subtracts & friends */
    "subfc", "subf", "", "neg", "subfe", "", "subfze", "subfme", "doz", "", "",
    "abs", "", "", "", "nabs"
};


/** various formatting helpers. */
void fmt_twoop(string& buf, const char *opc, int dst, int src)
{
    buf = my_sprintf("%-8sr%d, r%d", opc, dst, src);
}

void fmt_twoop_imm(string& buf, const char *opc, int dst, int imm)
{
    buf = my_sprintf("%-8sr%d, 0x%04X", opc, dst, imm);
}

void fmt_threeop(string& buf, const char *opc, int dst, int src1, int src2)
{
    buf = my_sprintf("%-8sr%d, r%d, r%d", opc, dst, src1, src2);
}

void fmt_threeop_imm(string& buf, const char *opc, int dst, int src1, int imm)
{
    buf = my_sprintf("%-8sr%d, r%d, 0x%04X", opc, dst, src1, imm);
}

void opc_illegal(PPCDisasmContext *ctx)
{
    ctx->instr_str = my_sprintf("%-8s0x%08X", "dc.l", ctx->instr_code);
}

void opc_twi(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_group4(PPCDisasmContext *ctx)
{
    printf("Altivec group 4 not supported yet\n");
}

void opc_mulli(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_subfic(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void power_dozi(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_cmpli(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_cmpi(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_addic(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_addicdot(PPCDisasmContext *ctx)
{
    //return "DEADBEEF";
}

void opc_addi(PPCDisasmContext *ctx)
{
    auto ra  = (ctx->instr_code >> 16) & 0x1F;
    auto rd  = (ctx->instr_code >> 21) & 0x1F;
    auto imm = ctx->instr_code & 0xFFFF;

    if (ra == 0 && ctx->simplified)
        fmt_twoop_imm(ctx->instr_str, "li", rd, imm);
    else
        fmt_threeop_imm(ctx->instr_str, "addi", rd, ra, imm);
}

void opc_bx(PPCDisasmContext *ctx)
{
    uint32_t dst = ((ctx->instr_code & 2) ? 0 : ctx->instr_addr)
                    + SIGNEXT(ctx->instr_code & 0x3FFFFFC, 25);

    ctx->instr_str = my_sprintf("%-8s0x%08X", bx_mnem[ctx->instr_code & 3], dst);
}

void opc_ori(PPCDisasmContext *ctx)
{
    auto ra  = (ctx->instr_code >> 16) & 0x1F;
    auto rs  = (ctx->instr_code >> 21) & 0x1F;
    auto imm = ctx->instr_code & 0xFFFF;

    if (!ra && !rs && !imm && ctx->simplified) {
        ctx->instr_str = "nop";
        return;
    }
    if (imm == 0 && ctx->simplified) { /* inofficial, produced by IDA */
        fmt_twoop(ctx->instr_str, "mr", ra, rs);
        return;
    }
    fmt_threeop_imm(ctx->instr_str, "ori", ra, rs, imm);
}

void opc_group31(PPCDisasmContext *ctx)
{
    char opcode[10];

    auto rb = (ctx->instr_code >> 11) & 0x1F;
    auto ra = (ctx->instr_code >> 16) & 0x1F;
    auto rs = (ctx->instr_code >> 21) & 0x1F;

    int  ext_opc = (ctx->instr_code >> 1) & 0x3FF; /* extract extended opcode */
    int  index   = ext_opc >> 5;
    bool rc_set  = ctx->instr_code & 1;

    switch(ext_opc & 0x1F) {
        case 8: /* subtracts & friends */
            index &= 0xF; /* strip OE bit */
            if (!strlen(opc_subs[index])) {
                opc_illegal(ctx);
            } else {
                strcpy(opcode, opc_subs[index]);
                if (ext_opc & 0x200) /* check OE bit */
                    strcat(opcode, "o");
                if (rc_set)
                    strcat(opcode, ".");
                if (index == 3 || index == 6 || index == 7 || index == 11 ||
                    index == 15) { /* ugly check for two-operands instructions */
                    if (rb != 0)
                        opc_illegal(ctx);
                    else
                        fmt_twoop(ctx->instr_str, opcode, rs, ra);
                } else
                    fmt_threeop(ctx->instr_str, opcode, rs, ra, rb);
            }
            return;

        case 0x1C: /* logical instructions */
            if (index == 13 && rs == rb && ctx->simplified) {
                fmt_twoop(ctx->instr_str, rc_set ? "mr." : "mr", ra, rs);
            } else {
                strcpy(opcode, opc_logic[index]);
                if (!strlen(opcode)) {
                    opc_illegal(ctx);
                } else {
                    if (rc_set)
                        strcat(opcode, ".");
                    fmt_threeop(ctx->instr_str, opcode, ra, rs, rb);
                }
            }
            return;

        case 0x17: /* indexed load/store instructions */
            if (index > 23 || rc_set || strlen(opc_idx_ldst[index]) == 0) {
                opc_illegal(ctx);
                return;
            }
            if (index < 16)
                fmt_threeop(ctx->instr_str, opc_idx_ldst[index], rs, ra, rb);
            else
                ctx->instr_str = my_sprintf("%-8sfp%d, r%d, r%d",
                    opc_idx_ldst[index], rs, ra, rb);
            return;
        break;
    }

    switch(ext_opc) {
        case 4:
            if (rc_set)
                opc_illegal(ctx);
            else
                ctx->instr_str = my_sprintf("%-8s%d, r%d, r%d", "tw", rs, ra, rb);
            break;
        default:
            opc_illegal(ctx);
    }
}

string disassemble_single(PPCDisasmContext *ctx)
{
    OpcodeDispatchTable[ctx->instr_code >> 26](ctx);

    ctx->instr_addr += 4;

    return ctx->instr_str;
}
