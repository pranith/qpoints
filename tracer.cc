/*
 * Copyright (C) 2020, Pranith Kumar <bobby.prani@gmail.com>
 *
 */
extern "C" {
#include "qemu-plugin.h"
}

#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>

#include "cs_disas.h"

#define INTERVAL_SIZE 10000000 /* 100M instructions */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static enum qemu_plugin_mem_rw rw = QEMU_PLUGIN_MEM_RW;
static qemu_plugin_id_t plugin_id;

/* Plugins need to take care of their own locking */
static std::mutex lock;

static uint64_t inst_count = 0; /* executed instruction count */
static uint64_t inst_dumped = 0; /* traced instruction count  */

static std::ifstream simpts_file;
static std::set<uint64_t> interval_set;

static bool tracing_enabled = false;
static uint32_t interval_id = 0;

static std::map<uint64_t, struct qemu_plugin_insn *> instructions;

static cs_disas dis;

void plugin_exit(qemu_plugin_id_t id, void *p)
{
    simpts_file.close();
}

static void plugin_init(std::string& bench_name, std::string& arch)
{
    std::string simpts_file_name = bench_name + ".simpts";
    simpts_file.open(simpts_file_name.c_str(), std::ifstream::in);
    cs_err ret;

    if (arch == "arm64") {
        ret = dis.init(CS_ARCH_ARM64, CS_MODE_ARM);
    } else if (arch == "riscv64") {
        ret = dis.init(CS_ARCH_RISCV, CS_MODE_RISCV64);
    } else if (arch == "riscv64c") {
        ret = dis.init(CS_ARCH_RISCV, CS_MODE_RISCVC);
    } else {
        ret = dis.init(CS_ARCH_X86, CS_MODE_64);
    }

    if (ret) {
        std::cerr << "Capstone initialization failed. Check library installation" << std::endl;
        exit(1);
    }

    while (!simpts_file.eof())
    {
        std::string line, interval, seq_no;
        std::getline(simpts_file, line);

        // not good enough, FIXME
        if (!line.empty()) {
            interval_set.insert(atoi(strtok((char *)line.c_str(), " ")));
        }
    }
}

static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    uint64_t pc = (uint64_t)udata;

    assert(instructions.find(pc) != instructions.end());

    std::cout << "Executing inst at pc:" << std::hex << pc << std::endl;

    /*
    TODO: capstone disassembly does not work for RISCV, investigate
    cs_insn *cs_insn;
    auto insn = instructions.at(pc);
    int count = dis.decode(qemu_plugin_insn_data(insn), qemu_plugin_insn_size(insn), cs_insn);

    if (0) {
        static uint64_t disas_count = 0;
        if (count > 0) {
            disas_count++;
            for (int i = 0; i < count; i++) {
                std::cout << "Inst callback 0x" << std::hex << pc << " " << cs_insn[i].mnemonic << " " << cs_insn[i].op_str << std::endl;
            }
        } else {
            std::cout << "Inst decode failed for insn at pc:" << std::hex << pc << std::endl;
            assert(0);
        }
    }
    assert(count > 0);
    */


    inst_dumped++;
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo, uint64_t vaddr, void *udata) {
    uint64_t pc = (uint64_t)udata;
    std::cout << "Mem callback 0x" << std::hex << pc << " vaddr:" << vaddr
              << " store:" << qemu_plugin_mem_is_store(meminfo) << std::endl;
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

static void callback_reset(qemu_plugin_id_t id)
{
    std::cout << "Resetting plugin" << std::endl;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
}

static void tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t interval = inst_count / INTERVAL_SIZE;

    lock.lock();

    if (tracing_enabled) {
        if (inst_dumped > INTERVAL_SIZE) {
            tracing_enabled = false;
            qemu_plugin_reset(plugin_id, callback_reset);
        }
    }

    if (interval_set.find(interval) != interval_set.end()) {
        tracing_enabled = true;
        inst_dumped = 0;
        interval_id++;
    }

    lock.unlock();
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &inst_count, insns);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);

    if (tracing_enabled) {
        // Start tracing the execution
        for (size_t i = 0; i < insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            
            uint64_t pc = qemu_plugin_insn_vaddr(insn);

            if (instructions.find(pc) == instructions.end()) {
                instructions.insert(std::make_pair(pc, insn));
            }
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS, (void *)pc);
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS, rw, (void *)pc);
            
            std::cout << "Installing inst and mem cbs for insn " << qemu_plugin_insn_disas(insn) << " insn: " << std::hex << insn << " at pc:" << std::hex << pc << std::endl;
        }
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    std::string bench_name("trace");
    std::string arch("arm64");

    if (argc < 2) {
        std::cerr << "Tracer plugin usage: pass bench name and architecture as arguments" << std::endl;
        exit(1);
    }

    bench_name = argv[0];
    arch = argv[1];

    plugin_id = id;
    plugin_init(bench_name, arch);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
