#include "capstone/capstone.h"

struct platform {
    cs_arch arch;
    cs_mode mode;
};

class cs_disas {

public:
    cs_disas();
    ~cs_disas();

    cs_err init(cs_arch arch, cs_mode mode);
    int decode(const void *code, int size, cs_insn *&insn); 
    void free_insn(cs_insn *insn, int count);
    bool get_regs_access(cs_insn *insn, cs_regs regs_read, cs_regs regs_write, uint8_t *regs_read_count,
                                        uint8_t *regs_write_count);
private:
    csh handle;
    struct platform pf;
};
