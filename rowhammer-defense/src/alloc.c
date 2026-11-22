/* alloc.c - tenant-isolating physical row allocator with guard rows */
#include "rh.h"

void alloc_init(alloc_t *a, const dram_map_t *m)
{
    a->map = *m;
    a->total = (long)m->banks * m->rows_per_bank;
    a->state = calloc((size_t)a->total, 1);
    a->n_guard = a->n_used = 0;
}

void alloc_destroy(alloc_t *a)
{
    free(a->state);
    a->state = NULL;
}

static long idx_of(const alloc_t *a, int bank, int row)
{
    return (long)bank * a->map.rows_per_bank + row;
}

/*
 * First-fit contiguous block of `nrows` inside one bank, with `guard`
 * free rows reserved on both sides (same bank). Guards are what keep one
 * tenant's aggressor rows from sitting next to another tenant's victims.
 */
static int alloc_block(alloc_t *a, int who, int nrows, int guard)
{
    int R = a->map.rows_per_bank;
    for (int b = 0; b < a->map.banks; b++) {
        for (int r = guard; r + nrows + guard <= R; r++) {
            int ok = 1;
            for (int k = -guard; k < nrows + guard && ok; k++)
                if (a->state[idx_of(a,b,r+k)] != F_FREE) ok = 0;
            if (!ok) continue;
            for (int k = -guard; k < 0; k++) {
                a->state[idx_of(a,b,r+k)] = F_GUARD; a->n_guard++;
            }
            for (int k = 0; k < nrows; k++) {
                a->state[idx_of(a,b,r+k)] = (uint8_t)who; a->n_used++;
            }
            for (int k = nrows; k < nrows + guard; k++) {
                a->state[idx_of(a,b,r+k)] = F_GUARD; a->n_guard++;
            }
            return 0;
        }
    }
    return -1;
}

int alloc_tenant_rows(alloc_t *a, int who, int nrows, int guard)
{
    return alloc_block(a, who, nrows, guard);
}

int alloc_sensitive_rows(alloc_t *a, int nrows, int guard)
{
    return alloc_block(a, F_SENS, nrows, guard);
}

int alloc_min_dist_to_sensitive(const alloc_t *a, int who)
{
    int R = a->map.rows_per_bank;
    int best = 1<<28;
    for (int b = 0; b < a->map.banks; b++) {
        for (int r = 0; r < R; r++) {
            if (a->state[idx_of(a,b,r)] != (uint8_t)who) continue;
            /* scan outward for nearest sensitive row in this bank */
            for (int d = 1; d < best && (r-d >= 0 || r+d < R); d++) {
                if (r-d >= 0 && a->state[idx_of(a,b,r-d)] == F_SENS) best = d;
                if (r+d <  R && a->state[idx_of(a,b,r+d)] == F_SENS) best = d;
            }
        }
    }
    return best;
}

double alloc_waste_frac(const alloc_t *a)
{
    return (double)a->n_guard / (double)a->total;
}
