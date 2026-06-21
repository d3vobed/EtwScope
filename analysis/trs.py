"""Telemetry Resilience Score (TRS) and Detection Decay Function (DDF) Engine.

Implements Equations 1.2 and 1.3 from the STCMF thesis:
  TRS = w1*(F_m/F_b) + w2*(H_m/H_b) + w3*(1 - CV_t)
  TRS(I) = TRS_max * e^(-lambda * I) + epsilon
"""
import math
from typing import Dict, Any, List, Tuple, Optional


class TRSEngine:
    """Computes Telemetry Resilience Score against a known baseline."""

    def __init__(self, baseline_f: int = 0, baseline_h: float = 0.0,
                 w1: float = 0.45, w2: float = 0.35, w3: float = 0.20):
        self.base_f = baseline_f
        self.base_h = baseline_h
        self.w1 = w1
        self.w2 = w2
        self.w3 = w3

    def set_baseline(self, metrics: Dict[str, Any]):
        """Set baseline from computed metrics dict."""
        self.base_f = metrics.get("F", 0)
        self.base_h = metrics.get("H", 0.0)

    def compute(self, current_metrics: Dict[str, Any]) -> float:
        """Compute TRS bounded [0, 1]."""
        f_mut = current_metrics.get("F", 0)
        h_mut = current_metrics.get("H", 0.0)
        cv_t_mut = current_metrics.get("CV_t", 0.0)

        if self.base_f == 0:
            vol_ratio = 1.0 if f_mut > 0 else 0.0
        else:
            vol_ratio = min(f_mut / self.base_f, 1.0)

        if self.base_h == 0.0:
            ent_ratio = 1.0 if h_mut > 0.0 else 0.0
        else:
            ent_ratio = min(h_mut / self.base_h, 1.0)

        timing_cmp = max(1.0 - cv_t_mut, 0.0)

        trs = self.w1 * vol_ratio + self.w2 * ent_ratio + self.w3 * timing_cmp
        return max(0.0, min(trs, 1.0))

    def compute_full_report(self, base_metrics: Dict, mut_metrics: Dict) -> Dict[str, Any]:
        """Compute TRS with full breakdown for reporting."""
        self.set_baseline(base_metrics)
        trs = self.compute(mut_metrics)

        f_b = base_metrics.get("F", 0)
        f_m = mut_metrics.get("F", 0)
        h_b = base_metrics.get("H", 0.0)
        h_m = mut_metrics.get("H", 0.0)
        cv_t = mut_metrics.get("CV_t", 0.0)

        vol_ratio = min(f_m / f_b, 1.0) if f_b > 0 else (1.0 if f_m > 0 else 0.0)
        ent_ratio = min(h_m / h_b, 1.0) if h_b > 0 else (1.0 if h_m > 0 else 0.0)
        timing_cmp = max(1.0 - cv_t, 0.0)

        return {
            "trs": round(trs, 6),
            "volume_ratio": round(vol_ratio, 6),
            "entropy_ratio": round(ent_ratio, 6),
            "timing_component": round(timing_cmp, 6),
            "weights": {"w1": self.w1, "w2": self.w2, "w3": self.w3},
            "baseline": {"F": f_b, "H": round(h_b, 6)},
            "mutated": {"F": f_m, "H": round(h_m, 6), "CV_t": round(cv_t, 6)},
            "visibility_pct": round(trs * 100, 2),
        }


def fit_ddf(trs_values: List[float], intensities: Optional[List[float]] = None) -> Dict[str, float]:
    """Fit the Detection Decay Function: TRS(I) = TRS_max * e^(-lambda*I) + epsilon.
    
    Uses scipy if available, otherwise falls back to a basic least-squares grid search.
    Returns dict with keys: trs_max, lambda, epsilon, r_squared.
    """
    n = len(trs_values)
    if n < 2:
        return {"trs_max": 1.0, "lambda": 0.0, "epsilon": trs_values[0] if trs_values else 0.0, "r_squared": 0.0}

    if intensities is None:
        intensities = [i / (n - 1) for i in range(n)]

    try:
        from scipy.optimize import curve_fit
        import numpy as np

        def ddf_model(I, trs_max, lam, eps):
            return trs_max * np.exp(-lam * np.array(I)) + eps

        x = np.array(intensities, dtype=float)
        y = np.array(trs_values, dtype=float)

        try:
            popt, _ = curve_fit(ddf_model, x, y, p0=[1.0, 1.0, 0.5],
                                bounds=([0, 0, 0], [2.0, 50.0, 1.0]),
                                maxfev=10000)
            trs_max, lam, eps = popt

            y_pred = ddf_model(x, *popt)
            ss_res = np.sum((y - y_pred) ** 2)
            ss_tot = np.sum((y - np.mean(y)) ** 2)
            r_sq = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

            return {
                "trs_max": round(float(trs_max), 6),
                "lambda": round(float(lam), 6),
                "epsilon": round(float(eps), 6),
                "r_squared": round(float(r_sq), 6),
            }
        except Exception:
            pass
    except ImportError:
        pass

    # Fallback: basic estimation
    eps = min(trs_values)
    trs_max = max(trs_values) - eps
    if trs_max > 0 and n > 1:
        mid_idx = n // 2
        mid_val = trs_values[mid_idx] - eps
        if mid_val > 0 and intensities[mid_idx] > 0:
            lam = -math.log(mid_val / trs_max) / intensities[mid_idx]
        else:
            lam = 1.0
    else:
        lam = 0.0

    return {
        "trs_max": round(trs_max, 6),
        "lambda": round(lam, 6),
        "epsilon": round(eps, 6),
        "r_squared": 0.0,
    }
