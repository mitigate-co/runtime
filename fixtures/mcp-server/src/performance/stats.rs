use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub(super) struct Case {
    name: &'static str,
    count: usize,
    warmup: usize,
    warmed: usize,
    values: Vec<u64>,
    failure: Option<Value>,
    deadline: Instant,
}
impl Case {
    pub(super) fn new(name: &'static str, count: usize, warmup: usize) -> Self {
        Self {
            name,
            count,
            warmup,
            warmed: 0,
            values: Vec::new(),
            failure: None,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }
    pub(super) fn next(&mut self) -> bool {
        if self.failure.is_some() || self.values.len() == self.count {
            return false;
        }
        if Instant::now() >= self.deadline {
            self.failure = Some(json!({"phase":"case_budget","duration_ns":0}));
            return false;
        }
        true
    }
    pub(super) fn record(&mut self, elapsed: Duration, ok: bool) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        if !ok {
            self.failure = Some(
                json!({"phase":if self.warmed < self.warmup {"warmup"} else {"sample"},"duration_ns":ns}),
            );
        } else if self.warmed < self.warmup {
            self.warmed += 1;
        } else {
            self.values.push(ns);
        }
    }
    pub(super) fn finish(self) -> Value {
        let mut ordered = self.values.clone();
        ordered.sort_unstable();
        let quantile = |percent: usize| {
            ordered
                .get((ordered.len() * percent).div_ceil(100).saturating_sub(1))
                .copied()
        };
        json!({"case":self.name,"status":if self.failure.is_none() && self.values.len()==self.count {"ok"} else {"failed"},
            "warmup_requested":self.warmup,"warmup_completed":self.warmed,"samples_requested":self.count,
            "samples_ns":self.values,"failure":self.failure,"min_ns":ordered.first(),
            "median_ns":quantile(50),"p95_ns":quantile(95),"max_ns":ordered.last()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nearest_rank_summaries_keep_observed_order_and_exclude_only_declared_warmup() {
        let mut case = Case::new("fixture", 20, 1);
        case.record(Duration::from_nanos(999), true);
        for n in (1..=20).rev() {
            assert!(case.next());
            case.record(Duration::from_nanos(n), true);
        }
        assert!(!case.next());
        let value = case.finish();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["median_ns"], 10);
        assert_eq!(value["p95_ns"], 19);
        assert_eq!(value["min_ns"], 1);
        assert_eq!(value["max_ns"], 20);
        assert_eq!(value["samples_ns"][0], 20);
        assert_eq!(value["warmup_completed"], 1);
    }
    #[test]
    fn failures_remain_visible_and_stop_sampling_without_retry() {
        let mut case = Case::new("fixture", 5, 0);
        case.record(Duration::from_nanos(3), true);
        case.record(Duration::from_nanos(7), false);
        assert!(!case.next());
        let value = case.finish();
        assert_eq!(value["status"], "failed");
        assert_eq!(value["samples_ns"], json!([3]));
        assert_eq!(value["failure"], json!({"phase":"sample","duration_ns":7}));
        let mut case = Case::new("fixture", 5, 1);
        case.record(Duration::ZERO, false);
        let value = case.finish();
        assert_eq!(value["failure"]["phase"], "warmup");
        assert_eq!(value["median_ns"], Value::Null);
    }
}
