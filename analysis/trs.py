from typing import Dict, Any

class TRSEngine:
    def __init__(self, baseline_f: int, baseline_h: float, w1: float=0.45, w2: float=0.35, w3: float=0.20):
        self.base_f = baseline_f
        self.base_h = baseline_h
        self.w1 = w1
        self.w2 = w2
        self.w3 = w3

    def compute(self, current_metrics: Dict[str, Any]) -> float:
        """Compute TRS based on a known baseline."""
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
