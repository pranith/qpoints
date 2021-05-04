/*
 * Copyright (C) 2020, Pranith Kumar <bobby.prani@gmail.com>
 *
 * Find the hot regions of code in intervals of 100M instructions
 *
 */
extern "C" {
#include "qemu-plugin.h"
}

#include <iostream>
#include <sstream>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iterator>

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <zlib.h>

#define INTERVAL_SIZE 100000000 /* 100M instructions */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Plugins need to take care of their own locking */
static std::mutex lock;
static GHashTable *hotblocks;

static uint64_t unique_trans_id = 0; /* unique id assigned to TB */
static uint64_t inst_count = 0; /* executed instruction count */

static gzFile bbv_file;
static std::ofstream pc_file;

/*
 * Counting Structure
 *
 * The internals of the TCG are not exposed to plugins so we can only
 * get the starting PC for each block. We cheat this slightly by
 * xor'ing the number of instructions to the hash to help
 * differentiate.
 */
class ExecCount {
public:
    uint64_t start_addr;
    uint64_t exec_count;
    uint64_t id;
    uint64_t pc;
    int      trans_count;
    unsigned long insns;

    bool operator < (const ExecCount& elem) const
    {
        return (exec_count > elem.exec_count);
    }
};

static std::unordered_map<uint64_t, ExecCount> hotblocks_map;

static gint cmp_exec_count(gconstpointer a, gconstpointer b)
{
    ExecCount *ea = (ExecCount *) a;
    ExecCount *eb = (ExecCount *) b;
    return (ea->exec_count * ea->insns) > (eb->exec_count * eb->insns) ? -1 : 1;
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    GList *it;

    lock.lock();
    hotblocks_map.clear();
    it = g_hash_table_get_values(hotblocks);

    if (it) {
        g_list_free(it);
    }

    lock.unlock();
    gzclose(bbv_file);
    pc_file.close();
}

static void plugin_init(std::string& bench_name)
{
    std::string bbv_file_name = bench_name + "_bbv.gz";
    std::string pc_file_name  = bench_name + "_pc.txt";

    bbv_file = gzopen(bbv_file_name.c_str(), "w");
    pc_file.open(pc_file_name.c_str(), std::ofstream::out);

    hotblocks = g_hash_table_new(NULL, g_direct_equal);
}

static void tb_exec(unsigned int cpu_index, void *udata)
{
    static int interval_cnt = 0;

    lock.lock();
    if (inst_count >= INTERVAL_SIZE) {
        std::ostringstream bb_stat;
        GList *counts, *it;
        int tb_count = 0;

        std::vector<ExecCount> hotblocks_vec;
        std::transform(hotblocks_map.begin(), hotblocks_map.end(),
                       std::back_inserter(hotblocks_vec),
                       [] (auto &el) {return el.second;});
        std::sort(hotblocks_vec.begin(), hotblocks_vec.end());
        counts = g_hash_table_get_values(hotblocks);
        it = g_list_sort(counts, cmp_exec_count);

        if (it) {
            bb_stat << "T";
            while (tb_count < 100) {
                ExecCount *rec = (ExecCount *) it->data;
                pc_file << std::dec << interval_cnt << ":O:" << std::hex << "0x" << rec->pc << " counts:" << std::dec << rec->exec_count << std::endl;
                pc_file << std::dec << interval_cnt << ":N:" << std::hex << "0x" << hotblocks_vec[tb_count].pc << " counts:" << std::dec << hotblocks_vec[tb_count].exec_count << std::endl;
                tb_count++;

                if (rec->exec_count) {
                    bb_stat << " :" << rec->id << ":" << rec->exec_count * rec->insns;
                    rec->exec_count = 0;
                }
                it = it->next;
            }

            bb_stat << std::endl;
            gzwrite(bbv_file, bb_stat.str().c_str(), bb_stat.str().length());
            inst_count = 0;
            interval_cnt++;
        }
    }
    lock.unlock();
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    ExecCount *cnt;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t insns = qemu_plugin_tb_n_insns(tb);
    uint64_t hash = pc ^ insns;

    lock.lock();
    auto el = hotblocks_map.find(hash);
    cnt = (ExecCount *) g_hash_table_lookup(hotblocks, (gconstpointer) hash);
    if (cnt) {
        assert(el != hotblocks_map.end());
        assert(el->second.trans_count == cnt->trans_count);
        cnt->trans_count++;
    } else {
        cnt = g_new0(ExecCount, 1);
        cnt->start_addr = pc;
        cnt->trans_count = 1;
        cnt->id = ++unique_trans_id;
        cnt->insns = insns;
        cnt->pc = pc;
        g_hash_table_insert(hotblocks, (gpointer) hash, (gpointer) cnt);
    }

    if (hotblocks_map.find(hash) != hotblocks_map.end()) {
        el->second.trans_count++;
    } else {
        hotblocks_map.insert(std::make_pair(hash, *cnt));
    }

    lock.unlock();

    /* count the number of instructions executed */
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cnt->exec_count, 1);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &inst_count, insns);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)hash);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    std::string bench_name("trace");
    if (argc) {
        bench_name = argv[0];
    }
    plugin_init(bench_name);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
