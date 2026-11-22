/* main.c - demos + protection-level experiment matrix */
#include "rh.h"

static void demo_mapping(void)
{
    printf("=== 1. DRAM address mapping inference (no docs, timing only) ===\n");
    dram_map_t hw; map_default(&hw, 16, 4096);
    dram_map_t inf; infer_mapping(&hw, &inf);
    printf("hardware : row_shift=%d bank_bits={%d,%d,%d,%d}\n",
           hw.row_shift, hw.bank_bits[0], hw.bank_bits[1],
           hw.bank_bits[2], hw.bank_bits[3]);
    printf("inferred : row_shift=%d bank_bits={", inf.row_shift);
    for (int i = 0; i < inf.n_bank_bits; i++)
        printf("%s%d", i?",":"", inf.bank_bits[i]);
    printf("}\n");
    int ok = 1;
    uint64_t s = 12345;
    for (int i = 0; i < 10000; i++) {       /* verify on random addresses */
        s = s*6364136223846793005ull + 1442695040888963407ull;
        uint64_t addr = s >> 16;
        if (map_bank(&hw,addr) != map_bank(&inf,addr) ||
            map_row (&hw,addr) != map_row (&inf,addr)) ok = 0;
    }
    printf("verification over 10000 random addresses: %s\n\n",
           ok ? "OK" : "MISMATCH");
}

static void demo_integrity(void)
{
    printf("=== 2. Integrity check + repair (functional test) ===\n");
    spage_t p; spage_init(&p, 0, 10, 42, 200000.0, 0.6);
    printf("flip bit 12345 in a PTE page (simulated Rowhammer hit)\n");
    spage_flip_bit(&p, 12345);
    int detected = spage_scrub(&p);
    int clean = memcmp(p.data, p.shadow, PAGE_SIZE) == 0;
    printf("scrub: detected=%d, repaired, data==shadow: %s\n\n",
           detected, clean ? "yes" : "NO");
    spage_destroy(&p);
}

int main(void)
{
    demo_mapping();
    demo_integrity();

    printf("=== 3. Protection level vs attack (simulated, avg of %d seeds, "
           "%.0fs each) ===\n", 5, 20.0);
    defense_t defs[] = {
        {"P0 none",            0, 0,  0,   0,   0,  0, 0,      0.3, 32},
        {"P1 coarse scrub",    0, 1, 10.0, 2.0, 50, 0, 0,      0.3, 32},
        {"P2 fine scrub",      0, 1,  2.0, 0.2, 10, 0, 0,      0.3, 32},
        {"P3 guard1+scrub",    1, 1,  2.0, 0.5, 10, 0, 0,      0.3, 32},
        {"P4 guard2+scrub+TRR",2, 1,  1.0, 0.2,  5, 1, 100000, 0.3, 32},
    };
    attack_t atks[] = {
        {"double-sided", 0, 1e9/TRC_NS, 0, 0.0 },
        {"half-double",  1, 1e9/TRC_NS, 0, 0.15},
        {"many-sided",   2, 1e9/TRC_NS, 1, 0.0 },
    };
    printf("%-22s %-13s %4s %10s %10s %12s %8s %8s %8s\n",
           "defense", "attack", "dist", "flips/s", "detects/s",
           "exploits/hr", "scrubCPU", "memWaste", "avgI ms");
    FILE *csv = fopen("results.csv", "w");
    fprintf(csv, "defense,attack,dist,flips_per_s,detects_per_s,"
                 "exploits_per_h,scrub_cpu,mem_waste,avg_I_ms\n");
    for (unsigned d = 0; d < sizeof(defs)/sizeof(defs[0]); d++) {
        for (unsigned k = 0; k < sizeof(atks)/sizeof(atks[0]); k++) {
            result_t acc; memset(&acc, 0, sizeof acc);
            for (int s = 1; s <= 5; s++) {
                result_t r = run_experiment(&defs[d], &atks[k], s, 20.0);
                acc.flips_per_sec     += r.flips_per_sec;
                acc.detects_per_sec   += r.detects_per_sec;
                acc.exploits_per_hour += r.exploits_per_hour;
                acc.scrub_cpu_frac    += r.scrub_cpu_frac;
                acc.mem_waste_frac    += r.mem_waste_frac;
                acc.avg_interval_ms   += r.avg_interval_ms;
                acc.min_dist = r.min_dist;
            }
            int n = 5;
            printf("%-22s %-13s %4d %10.1f %10.1f %12.2f %7.2f%% %7.3f%% %8.2f\n",
                   defs[d].name, atks[k].name, acc.min_dist,
                   acc.flips_per_sec/n, acc.detects_per_sec/n,
                   acc.exploits_per_hour/n, 100.0*acc.scrub_cpu_frac/n,
                   100.0*acc.mem_waste_frac/n, acc.avg_interval_ms/n);
            fprintf(csv, "%s,%s,%d,%.2f,%.2f,%.4f,%.5f,%.6f,%.3f\n",
                    defs[d].name, atks[k].name, acc.min_dist,
                    acc.flips_per_sec/n, acc.detects_per_sec/n,
                    acc.exploits_per_hour/n, acc.scrub_cpu_frac/n,
                    acc.mem_waste_frac/n, acc.avg_interval_ms/n);
        }
    }
    fclose(csv);
    printf("\nresults written to results.csv\n");
    return 0;
}
