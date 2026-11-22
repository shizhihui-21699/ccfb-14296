/*
 * rh.h - Rowhammer defense & simulation toolkit
 *
 * Components:
 *  - DRAM physical-address -> (bank,row) mapping model + timing-based inference
 *  - tenant-isolating physical row allocator (guard rows)
 *  - integrity check + repair for critical structures (page tables, key material)
 *  - analytic Rowhammer attack simulator used to quantify protection levels
 */
#ifndef RH_H
#define RH_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#define ROW_BITS        13              /* 8 KB DRAM rows */
#define ROW_SIZE        (1u<<ROW_BITS)
#define PAGE_BITS       12
#define PAGE_SIZE       (1u<<PAGE_BITS)
#define BITS_PER_PAGE   (PAGE_SIZE*8)   /* 32768 */
#define TRC_NS          45.0            /* row cycle time */
#define TREFRESH_MS     64.0            /* refresh period: resets disturbance */
#define EXPLOIT_DELAY_MS 1.0            /* attacker needs this long to use a flip */

/* ------------------------------------------------------------------ */
/* DRAM address mapping                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    int banks;
    int rows_per_bank;
    int row_shift;          /* address bits below the row field */
    int n_bank_bits;
    int bank_bits[8];       /* bank index = concatenation of these addr bits */
} dram_map_t;

void     map_default(dram_map_t *m, int banks, int rows_per_bank);
int      map_bank(const dram_map_t *m, uint64_t addr);
int      map_row (const dram_map_t *m, uint64_t addr);
uint64_t map_addr (const dram_map_t *m, int bank, int row, uint64_t col);

/* simulated "hardware" timing oracle: row-buffer conflict is observable */
double   hw_pair_latency_ns(const dram_map_t *hw, uint64_t a, uint64_t b);
/* reverse-engineer the mapping using only the timing oracle */
void     infer_mapping(const dram_map_t *hw, dram_map_t *out);

/* ------------------------------------------------------------------ */
/* tenant-isolating physical allocator                                 */
/* ------------------------------------------------------------------ */
enum { F_FREE=0, F_GUARD, F_TENANT_A, F_TENANT_B, F_SENS };

typedef struct {
    dram_map_t map;
    uint8_t   *state;       /* per (bank,row) frame state */
    long       total;
    long       n_guard, n_used;
} alloc_t;

void   alloc_init(alloc_t *a, const dram_map_t *m);
void   alloc_destroy(alloc_t *a);
int    alloc_tenant_rows(alloc_t *a, int who, int nrows, int guard);
int    alloc_sensitive_rows(alloc_t *a, int nrows, int guard);
/* min same-bank row distance from any `who` row to any sensitive row */
int    alloc_min_dist_to_sensitive(const alloc_t *a, int who);
double alloc_waste_frac(const alloc_t *a);

/* ------------------------------------------------------------------ */
/* sensitive page: contents + per-bit flip vulnerability + integrity   */
/* ------------------------------------------------------------------ */
typedef struct {
    int      bank, row;
    uint64_t data[PAGE_SIZE/8];     /* live contents (e.g. a PTE page)   */
    uint64_t shadow[PAGE_SIZE/8];   /* known-good copy for repair        */
    uint32_t *th_sorted;            /* per-bit flip thresholds, sorted   */
    uint32_t *th_index;             /* bit index parallel to th_sorted   */
    uint8_t  *target_bm;            /* bitmap: bits an exploit cares about */
} spage_t;

void     spage_init(spage_t *p, int bank, int row, uint64_t seed,
                    double base, double sigma);
void     spage_destroy(spage_t *p);
uint64_t spage_hash(const uint64_t *words);
void     spage_flip_bit(spage_t *p, long bit);
/* recompute hash, on mismatch restore from shadow; returns 1 if repaired */
int      spage_scrub(spage_t *p);
/* analytic helpers over the sorted thresholds */
long     spage_count_below(const spage_t *p, double D);
long     spage_count_target_below(const spage_t *p, double D);

/* ------------------------------------------------------------------ */
/* experiment configuration / results                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    int    guard_rows;
    int    scrub_on;
    double I0_ms, Imin_ms, Imax_ms;   /* adaptive scrub interval bounds */
    int    trr_on;
    double trr_threshold;
    double scan_cost_us_per_page;
    int    n_spages;
} defense_t;

typedef struct {
    const char *name;
    int    type;          /* 0=double-sided 1=half-double 2=many-sided */
    double rate_aps;      /* aggressor activations per second */
    int    bypasses_trr;
    double hd_factor;     /* disturbance leak to +-2 rows (half-double) */
} attack_t;

typedef struct {
    double flips_per_sec;
    double detects_per_sec;
    double exploits_per_hour;
    double scrub_cpu_frac;
    double mem_waste_frac;
    double avg_interval_ms;
    int    min_dist;
} result_t;

result_t run_experiment(const defense_t *def, const attack_t *atk,
                        uint64_t seed, double sim_seconds);

#endif
