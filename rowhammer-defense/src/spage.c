/* spage.c - sensitive page model: vulnerability thresholds + integrity */
#include "rh.h"

static uint64_t rng_state;
static uint64_t xnext(void)     /* splitmix64 */
{
    uint64_t z = (rng_state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static double unif(void) { return (xnext() >> 11) * (1.0/9007199254740992.0); }
static double gauss(void)
{
    double u1 = unif(); if (u1 < 1e-12) u1 = 1e-12;
    return sqrt(-2.0*log(u1)) * cos(2.0*M_PI*unif());
}

typedef struct { uint32_t th, idx; } thpair_t;
static int cmp_th(const void *a, const void *b)
{
    uint32_t x = ((const thpair_t*)a)->th, y = ((const thpair_t*)b)->th;
    return (x > y) - (x < y);
}

/*
 * Per-bit flip thresholds: lognormal bulk (base, sigma) plus a small
 * fraction of weak cells, matching published Rowhammer characterizations.
 * target bitmap models the bits an attacker wants (e.g. PFN bits 12..30
 * of every 64-bit PTE in the page).
 */
void spage_init(spage_t *p, int bank, int row, uint64_t seed,
                double base, double sigma)
{
    p->bank = bank; p->row = row;
    rng_state = seed ? seed : 1;
    for (size_t i = 0; i < PAGE_SIZE/8; i++) {
        p->data[i] = xnext();
        p->shadow[i] = p->data[i];
    }
    p->th_sorted = malloc(BITS_PER_PAGE * sizeof(uint32_t));
    p->th_index  = malloc(BITS_PER_PAGE * sizeof(uint32_t));
    p->target_bm = calloc(BITS_PER_PAGE/8, 1);

    thpair_t *tmp = malloc(BITS_PER_PAGE * sizeof(thpair_t));
    for (long i = 0; i < BITS_PER_PAGE; i++) {
        double th;
        if (unif() < 0.001)                 /* weak cell */
            th = 2000.0 + unif()*48000.0;
        else
            th = base * exp(sigma * gauss());
        if (th > 2e6) th = 2e6;
        tmp[i].th = (uint32_t)th;
        tmp[i].idx = (uint32_t)i;
    }
    qsort(tmp, BITS_PER_PAGE, sizeof(thpair_t), cmp_th);
    for (long i = 0; i < BITS_PER_PAGE; i++) {
        p->th_sorted[i] = tmp[i].th;
        p->th_index[i]  = tmp[i].idx;
    }
    free(tmp);

    for (size_t w = 0; w < PAGE_SIZE/8; w++)    /* PTE PFN field bits */
        for (int b = 12; b <= 30; b++) {
            long bit = (long)w*64 + b;
            p->target_bm[bit>>3] |= (uint8_t)(1u << (bit&7));
        }
}

void spage_destroy(spage_t *p)
{
    free(p->th_sorted); free(p->th_index); free(p->target_bm);
}

uint64_t spage_hash(const uint64_t *words)      /* FNV-1a 64 */
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < PAGE_SIZE/8; i++) {
        uint64_t w = words[i];
        for (int b = 0; b < 8; b++) {
            h ^= (w >> (b*8)) & 0xff;
            h *= 1099511628211ull;
        }
    }
    return h;
}

void spage_flip_bit(spage_t *p, long bit)
{
    p->data[bit/64] ^= 1ull << (bit%64);
}

int spage_scrub(spage_t *p)
{
    if (spage_hash(p->data) == spage_hash(p->shadow)) return 0;
    memcpy(p->data, p->shadow, PAGE_SIZE);      /* repair from known-good */
    return 1;
}

static long lower_bound(const uint32_t *a, long n, double v)
{
    long lo = 0, hi = n;
    while (lo < hi) {
        long mid = (lo+hi)/2;
        if ((double)a[mid] < v) lo = mid+1; else hi = mid;
    }
    return lo;
}

/* bits that flip when disturbance reaches D */
long spage_count_below(const spage_t *p, double D)
{
    if (D <= 0) return 0;
    return lower_bound(p->th_sorted, BITS_PER_PAGE, D);
}

/* exploit-relevant bits that flip when disturbance reaches D */
long spage_count_target_below(const spage_t *p, double D)
{
    if (D <= 0) return 0;
    long hi = lower_bound(p->th_sorted, BITS_PER_PAGE, D);
    long n = 0;
    for (long i = 0; i < hi; i++) {
        uint32_t bit = p->th_index[i];
        if (p->target_bm[bit>>3] & (1u << (bit&7))) n++;
    }
    return n;
}
