/* sim.c - analytic Rowhammer attack/defense simulator
 *
 * Model:
 *  - Each aggressor activation adds 1 unit of disturbance to physically
 *    adjacent (+-1) victim rows; half-double leaks a fraction to +-2.
 *  - A victim cell flips when accumulated disturbance passes its threshold.
 *  - Refresh (64 ms) and integrity scrubs both restore victim charge, i.e.
 *    reset accumulated disturbance; a scrub also repairs data from shadow.
 *  - An exploit succeeds when a target bit flips at least EXPLOIT_DELAY_MS
 *    before the next scrub repairs it.
 */
#include "rh.h"

result_t run_experiment(const defense_t *def, const attack_t *atk,
                        uint64_t seed, double sim_seconds)
{
    /* --- build machine geometry and place tenants --- */
    dram_map_t m; map_default(&m, 16, 4096);
    alloc_t a; alloc_init(&a, &m);
    alloc_tenant_rows(&a, F_TENANT_A, 400, 0);                 /* victim VM  */
    alloc_sensitive_rows(&a, def->n_spages, def->guard_rows);  /* PTEs/keys  */
    alloc_tenant_rows(&a, F_TENANT_B, 400, 0);  /* attacker: unguarded */
    int dist = alloc_min_dist_to_sensitive(&a, F_TENANT_B);

    /* --- effective disturbance rate on sensitive rows (per ns) --- */
    double r = atk->rate_aps / 1e9;
    double r_eff = 0.0;
    if (dist == 1)      r_eff = r;
    else if (dist == 2) {
        if (atk->type == 1)      r_eff = r * atk->hd_factor;
        else if (atk->type == 2) r_eff = r * 0.05;
    }

    /* --- sensitive pages sit in the sensitive rows --- */
    spage_t *pages = malloc(sizeof(spage_t) * def->n_spages);
    int placed = 0;
    for (long i = 0; i < a.total && placed < def->n_spages; i++)
        if (a.state[i] == F_SENS) {
            spage_init(&pages[placed], (int)(i / m.rows_per_bank),
                       (int)(i % m.rows_per_bank),
                       seed*7919 + placed, 200000.0, 0.6);
            placed++;
        }

    result_t res; memset(&res, 0, sizeof res);
    res.min_dist = dist;
    res.mem_waste_frac = alloc_waste_frac(&a);
    double T_ms = sim_seconds * 1000.0;

    if (!def->scrub_on) {
        /* no integrity defense: disturbance accumulates a full refresh
         * window, flips become permanent, no detection possible */
        double D = r_eff * TREFRESH_MS * 1e6;
        if (def->trr_on && !atk->bypasses_trr)
            D = fmin(D, def->trr_threshold * 1.5);
        long f = 0, s = 0;
        for (int i = 0; i < placed; i++) {
            f += spage_count_below(&pages[i], D);
            s += spage_count_target_below(&pages[i], D);
        }
        double win_s = TREFRESH_MS / 1000.0;
        res.flips_per_sec     = f / win_s;
        res.exploits_per_hour = (s > 0 ? 1.0 : 0.0) / win_s * 3600.0;
        res.avg_interval_ms   = TREFRESH_MS;
        goto out;
    }

    {
        double I = def->I0_ms, t = 0, Isum = 0;
        long intervals = 0, flips = 0, succ = 0, detects = 0;
        while (t < T_ms) {
            double D = r_eff * I * 1e6;
            if (def->trr_on && !atk->bypasses_trr)
                D = fmin(D, def->trr_threshold * 1.5);
            long f = 0, s = 0;
            for (int i = 0; i < placed; i++) {
                f += spage_count_below(&pages[i], D);
                if (I > EXPLOIT_DELAY_MS)
                    s += spage_count_target_below(&pages[i],
                              r_eff * (I - EXPLOIT_DELAY_MS) * 1e6);
            }
            flips += f;
            if (s > 0) succ++;
            if (f > 0) { detects++; I = fmax(def->Imin_ms, I/2.0); }
            else                  I = fmin(def->Imax_ms, I*1.5);
            Isum += I; intervals++;
            t += I;
        }
        double T_s = T_ms / 1000.0;
        res.flips_per_sec     = flips / T_s;
        res.detects_per_sec   = detects / T_s;
        res.exploits_per_hour = succ / T_s * 3600.0;
        res.avg_interval_ms   = Isum / intervals;
        res.scrub_cpu_frac    = (double)def->n_spages *
                                def->scan_cost_us_per_page /
                                (res.avg_interval_ms * 1000.0);
    }
out:
    for (int i = 0; i < placed; i++) spage_destroy(&pages[i]);
    free(pages);
    alloc_destroy(&a);
    return res;
}
