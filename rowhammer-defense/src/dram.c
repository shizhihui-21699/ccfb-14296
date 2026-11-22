/* dram.c - DRAM address mapping model + timing-based inference */
#include "rh.h"

void map_default(dram_map_t *m, int banks, int rows_per_bank)
{
    /* typical desktop part: column bits below, then bank bits, then row.
     * (real parts XOR-fold several address bits into the bank hash; the
     *  inference below only assumes "some bits select the bank") */
    m->banks = banks;
    m->rows_per_bank = rows_per_bank;
    m->n_bank_bits = 4;                 /* 16 banks */
    m->bank_bits[0] = 13;
    m->bank_bits[1] = 14;
    m->bank_bits[2] = 15;
    m->bank_bits[3] = 16;
    m->row_shift = 17;
}

int map_bank(const dram_map_t *m, uint64_t addr)
{
    int b = 0;
    for (int i = 0; i < m->n_bank_bits; i++)
        b |= ((addr >> m->bank_bits[i]) & 1) << i;
    return b;
}

int map_row(const dram_map_t *m, uint64_t addr)
{
    return (int)(addr >> m->row_shift) % m->rows_per_bank;
}

uint64_t map_addr(const dram_map_t *m, int bank, int row, uint64_t col)
{
    uint64_t a = col & ((1ull<<m->row_shift)-1);
    a &= ~0ull; /* keep low bits; bank bits set explicitly below */
    for (int i = 0; i < m->n_bank_bits; i++) {
        if ((bank>>i)&1) a |= (1ull << m->bank_bits[i]);
        else             a &= ~(1ull << m->bank_bits[i]);
    }
    a &= ~(((uint64_t)m->rows_per_bank-1) << m->row_shift);
    a |= ((uint64_t)row) << m->row_shift;
    return a;
}

/*
 * Timing oracle: access a then b. Same bank + different open row forces a
 * precharge/activate pair (row-buffer conflict) which is measurably slower.
 * On real hardware this is measured with rdtsc over many repetitions to
 * average out noise; here the oracle is exact.
 */
double hw_pair_latency_ns(const dram_map_t *hw, uint64_t a, uint64_t b)
{
    if (map_bank(hw,a) == map_bank(hw,b) && map_row(hw,a) != map_row(hw,b))
        return 85.0;    /* conflict: tRP + tRCD */
    return 42.0;        /* row hit or different bank */
}

/*
 * Infer the mapping without documentation:
 *  1. row_shift = lowest address bit whose toggling turns a same-address
 *     pair into a row-buffer conflict (same bank, new row).
 *  2. bank bits = bits below row_shift whose toggling makes an otherwise
 *     conflicting pair stop conflicting (they moved to another bank).
 */
void infer_mapping(const dram_map_t *hw, dram_map_t *out)
{
    int rs = -1;
    for (int b = 1; b < 40; b++) {
        if (hw_pair_latency_ns(hw, 0, 1ull<<b) > 60.0) { rs = b; break; }
    }
    out->row_shift = rs;
    out->n_bank_bits = 0;
    for (int i = 0; i < rs && out->n_bank_bits < 8; i++) {
        uint64_t a1 = 1ull << rs;                    /* row 1, bank 0 */
        uint64_t a2 = (2ull << rs) | (1ull << i);    /* row 2, maybe other bank */
        if (hw_pair_latency_ns(hw, a1, a2) < 60.0)
            out->bank_bits[out->n_bank_bits++] = i;  /* conflict vanished */
    }
    out->banks = 1 << out->n_bank_bits;
    out->rows_per_bank = hw->rows_per_bank;
}
