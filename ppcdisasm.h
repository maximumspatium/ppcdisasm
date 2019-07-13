#ifndef PPCDISASM_H
#define PPCDISASM_H

#include <string>
#include <map>

typedef struct PPCDisasmContext {
    uint32_t    instr_addr;
    uint32_t    instr_code;
    //char        instr_str[100];
    std::string instr_str;
    bool        simplified; /* true if we should output simplified mnemonics */
} PPCDisasmContext;

/** forward declaration of opcode handlers. */
void opc_illegal(PPCDisasmContext *ctx);
void opc_twi(PPCDisasmContext *ctx);
void opc_group4(PPCDisasmContext *ctx);
void opc_mulli(PPCDisasmContext *ctx);
void opc_subfic(PPCDisasmContext *ctx);
void power_dozi(PPCDisasmContext *ctx);
void opc_cmpli(PPCDisasmContext *ctx);
void opc_cmpi(PPCDisasmContext *ctx);
void opc_addic(PPCDisasmContext *ctx);
void opc_addicdot(PPCDisasmContext *ctx);
void opc_addi(PPCDisasmContext *ctx);
void opc_bx(PPCDisasmContext *ctx);
void opc_ori(PPCDisasmContext *ctx);
void opc_group31(PPCDisasmContext *ctx);
std::string disassemble_single(PPCDisasmContext *ctx);

#define DWORD_BE(p) (((p)[0] << 24) | ((p)[1] << 16) | ((p)[2] << 8) | (p)[3])

/** sign-extend an integer. */
#define SIGNEXT(x, sb) ((x) | (((x) & (1 << (sb))) ? ~((1 << (sb))-1) : 0))

/** main dispatch table. */
static std::map<uint8_t, std::function<void(PPCDisasmContext*)> > OpcodeDispatchTable = {
    { 0, &opc_illegal},   { 1, &opc_illegal},   { 2, &opc_illegal},
    { 3, &opc_twi},       { 4, &opc_group4},    { 5, &opc_illegal},
    { 6, &opc_illegal},   { 7, &opc_mulli},     { 8, &opc_subfic},
    { 9, &power_dozi},    {10, &opc_cmpli},     {11, &opc_cmpi},
    {12, &opc_addic},     {13, &opc_addicdot},  {14, &opc_addi},
    /*{15, &opc_addis},     {16, &opc_opcode16},  {17, &opc_sc},*/
    {18, &opc_bx},        /*{19, &opc_opcode19},  {20, &opc_rlwimi},
    {21, &opc_rlwinm},    {22, &power_rlmi},    {23, &opc_rlwnm},*/
    {24, &opc_ori},       /*{25, &opc_oris},      {26, &opc_xori},
    {27, &opc_xoris},     {28, &opc_andidot},   {29, &opc_andisdot},
    {30, &opc_illegal},*/   {31, &opc_group31},  /*{32, &opc_lwz},
    {33, &opc_lwzu},      {34, &opc_lbz},       {35, &opc_lbzu},
    {36, &opc_stw},       {37, &opc_stwu},      {38, &opc_stb},
    {39, &opc_stbu},      {40, &opc_lhz},       {41, &opc_lhzu},
    {42, &opc_lha},       {43, &opc_lhau},      {44, &opc_sth},
    {45, &opc_sthu},      {46, &opc_lmw},       {47, &opc_stmw},
    {48, &opc_lfs},       {49, &opc_lfsu},      {50, &opc_lfd},
    {51, &opc_lfdu},      {52, &opc_stfs},      {53, &opc_stfsu},
    {54, &opc_stfd},      {55, &opc_stfdu},     {56, &opc_psq_l},
    {57, &opc_psq_lu},    {58, &opc_illegal},   {59, &opc_illegal},
    {60, &opc_psq_st},    {61, &opc_psq_stu},   {62, &opc_illegal},
    {63, &opc_opcode63}*/
};

#endif // PPCDISASM_H
