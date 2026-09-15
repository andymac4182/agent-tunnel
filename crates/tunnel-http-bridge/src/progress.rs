//! Transport progress budgets (docs/http-forwarding.md "Backpressure,
//! streaming, and deadlines").
//!
//! * **first HEAD**: the request receiver gets the first `REQUEST_HEAD`
//!   within the budget after the exchange starts;
//! * **record**: a partly received record completes within the budget from
//!   its first byte; trickled bytes of the same record do not restart it;
//! * **credit stall**: a sender blocked on output credit makes progress
//!   within the budget;
//! * **FIN after END**: the outer FIN follows END within the budget.
//!
//! A budget clock advances only while its endpoint is actually waiting on
//! the carrier.  It stops while this endpoint's recorded rotation freeze
//! prevents sending ([`PauseSignal`]) and while the receiver is itself
//! blocked on its downstream (deliberately withheld credit: the waiting time
//! is simply not measured).  The absolute application deadline is separate
//! and never pauses.  Every budget is finite and at most
//! [`MAX_PROGRESS_BUDGET`].

use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::ConfigError;

/// Starting budget for the first request HEAD.
pub const DEFAULT_FIRST_HEAD_BUDGET: Duration = Duration::from_secs(10);
/// Starting budget for completing a partly received record.
pub const DEFAULT_RECORD_BUDGET: Duration = Duration::from_secs(10);
/// Starting budget for an output-credit stall.
pub const DEFAULT_CREDIT_STALL_BUDGET: Duration = Duration::from_secs(30);
/// Starting budget for FIN after END.
pub const DEFAULT_FIN_AFTER_END_BUDGET: Duration = Duration::from_secs(10);
/// Hard ceiling on every configured progress budget.
pub const MAX_PROGRESS_BUDGET: Duration = Duration::from_secs(10 * 60);

/// Which progress budget expired.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProgressKind {
    FirstHead,
    Record,
    CreditStall,
    FinAfterEnd,
}

impl ProgressKind {
    /// Closed diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstHead => "first_head",
            Self::Record => "record",
            Self::CreditStall => "credit_stall",
            Self::FinAfterEnd => "fin_after_end",
        }
    }
}

/// The four transport progress budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressBudgets {
    first_head: Duration,
    record: Duration,
    credit_stall: Duration,
    fin_after_end: Duration,
}

impl Default for ProgressBudgets {
    fn default() -> Self {
        Self {
            first_head: DEFAULT_FIRST_HEAD_BUDGET,
            record: DEFAULT_RECORD_BUDGET,
            credit_stall: DEFAULT_CREDIT_STALL_BUDGET,
            fin_after_end: DEFAULT_FIN_AFTER_END_BUDGET,
        }
    }
}

const fn checked(budget: Duration) -> Result<Duration, ConfigError> {
    if budget.is_zero() || budget.as_nanos() > MAX_PROGRESS_BUDGET.as_nanos() {
        Err(ConfigError::ProgressBudget)
    } else {
        Ok(budget)
    }
}

impl ProgressBudgets {
    /// # Errors
    /// [`ConfigError::ProgressBudget`] for zero or above the ceiling.
    pub const fn with_first_head(self, budget: Duration) -> Result<Self, ConfigError> {
        match checked(budget) {
            Ok(first_head) => Ok(Self { first_head, ..self }),
            Err(error) => Err(error),
        }
    }

    /// # Errors
    /// [`ConfigError::ProgressBudget`] for zero or above the ceiling.
    pub const fn with_record(self, budget: Duration) -> Result<Self, ConfigError> {
        match checked(budget) {
            Ok(record) => Ok(Self { record, ..self }),
            Err(error) => Err(error),
        }
    }

    /// # Errors
    /// [`ConfigError::ProgressBudget`] for zero or above the ceiling.
    pub const fn with_credit_stall(self, budget: Duration) -> Result<Self, ConfigError> {
        match checked(budget) {
            Ok(credit_stall) => Ok(Self {
                credit_stall,
                ..self
            }),
            Err(error) => Err(error),
        }
    }

    /// # Errors
    /// [`ConfigError::ProgressBudget`] for zero or above the ceiling.
    pub const fn with_fin_after_end(self, budget: Duration) -> Result<Self, ConfigError> {
        match checked(budget) {
            Ok(fin_after_end) => Ok(Self {
                fin_after_end,
                ..self
            }),
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub const fn get(&self, kind: ProgressKind) -> Duration {
        match kind {
            ProgressKind::FirstHead => self.first_head,
            ProgressKind::Record => self.record,
            ProgressKind::CreditStall => self.credit_stall,
            ProgressKind::FinAfterEnd => self.fin_after_end,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PauseState {
    paused_since: Option<Instant>,
    /// Paused time accumulated before `paused_since`.
    paused_total: Duration,
}

impl PauseState {
    fn paused_total_at(&self, now: Instant) -> Duration {
        self.paused_total.saturating_add(
            self.paused_since
                .map_or(Duration::ZERO, |since| now.saturating_duration_since(since)),
        )
    }
}

/// Publishes one endpoint's recorded rotation freeze.
#[derive(Debug)]
pub struct PauseController {
    tx: watch::Sender<PauseState>,
}

impl Default for PauseController {
    fn default() -> Self {
        Self::new(false)
    }
}

impl PauseController {
    #[must_use]
    pub fn new(paused: bool) -> Self {
        let (tx, _) = watch::channel(PauseState {
            paused_since: paused.then(Instant::now),
            paused_total: Duration::ZERO,
        });
        Self { tx }
    }

    /// Record the freeze state; repeated values change nothing.
    pub fn set(&self, paused: bool) {
        let now = Instant::now();
        self.tx
            .send_if_modified(|state| match (state.paused_since, paused) {
                (None, true) => {
                    state.paused_since = Some(now);
                    true
                }
                (Some(since), false) => {
                    state.paused_total = state
                        .paused_total
                        .saturating_add(now.saturating_duration_since(since));
                    state.paused_since = None;
                    true
                }
                _ => false,
            });
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.tx.borrow().paused_since.is_some()
    }

    #[must_use]
    pub fn signal(&self) -> PauseSignal {
        PauseSignal {
            rx: Some(self.tx.subscribe()),
        }
    }
}

/// One endpoint's freeze, observed by its budget clocks.
#[derive(Clone, Debug, Default)]
pub struct PauseSignal {
    rx: Option<watch::Receiver<PauseState>>,
}

impl PauseSignal {
    /// A signal that is never paused.
    #[must_use]
    pub const fn never() -> Self {
        Self { rx: None }
    }

    fn state(&self) -> PauseState {
        self.rx.as_ref().map_or(
            PauseState {
                paused_since: None,
                paused_total: Duration::ZERO,
            },
            |rx| *rx.borrow(),
        )
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state().paused_since.is_some()
    }

    /// Resolve on the next freeze-state change.  Pends forever for a signal
    /// that can never change.
    pub async fn changed(&mut self) {
        match self.rx.as_mut() {
            Some(rx) => {
                if rx.changed().await.is_err() {
                    // The controller is gone: nothing can pause any more.
                    self.rx = None;
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    }
}

/// The start of one wait on the carrier.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WaitMark {
    at: Instant,
    paused_total: Duration,
}

impl WaitMark {
    pub(crate) fn now(pause: &PauseSignal) -> Self {
        let at = Instant::now();
        Self {
            at,
            paused_total: pause.state().paused_total_at(at),
        }
    }

    /// Unpaused time since this mark.
    fn active_elapsed(&self, pause: &PauseSignal, now: Instant) -> Duration {
        let paused = pause
            .state()
            .paused_total_at(now)
            .saturating_sub(self.paused_total);
        now.saturating_duration_since(self.at)
            .saturating_sub(paused)
    }
}

/// One budget's accumulated active waiting time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BudgetClock {
    kind: ProgressKind,
    budget: Duration,
    used: Duration,
    armed: bool,
}

impl BudgetClock {
    pub(crate) fn new(kind: ProgressKind, budgets: &ProgressBudgets) -> Self {
        Self {
            kind,
            budget: budgets.get(kind),
            used: Duration::ZERO,
            armed: false,
        }
    }

    pub(crate) fn arm(&mut self) {
        if !self.armed {
            self.armed = true;
            self.used = Duration::ZERO;
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
        self.used = Duration::ZERO;
    }

    #[cfg(test)]
    pub(crate) const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Account for one finished wait.
    pub(crate) fn end_wait(&mut self, mark: WaitMark, pause: &PauseSignal) {
        if self.armed {
            self.used = self
                .used
                .saturating_add(mark.active_elapsed(pause, Instant::now()));
        }
    }

    fn remaining(&self, mark: WaitMark, pause: &PauseSignal, now: Instant) -> Option<Duration> {
        self.armed.then(|| {
            self.budget
                .saturating_sub(self.used)
                .saturating_sub(mark.active_elapsed(pause, now))
        })
    }
}

/// Keep the record clock on the decoder's partly received record: a new
/// record (by ordinal) starts a fresh budget, trickled bytes of the same
/// record keep the accumulated time, and a completed record disarms it.
pub(crate) fn track_partial_record(
    partial: Option<tunnel_http_forward::PartialRecord>,
    clock: &mut BudgetClock,
    ordinal: &mut Option<u64>,
) {
    match partial {
        Some(partial) if *ordinal == Some(partial.ordinal) => {}
        Some(partial) => {
            clock.disarm();
            clock.arm();
            *ordinal = Some(partial.ordinal);
        }
        None => {
            clock.disarm();
            *ordinal = None;
        }
    }
}

/// Account a finished wait on every clock.
pub(crate) fn end_wait(clocks: &mut [&mut BudgetClock], mark: WaitMark, pause: &PauseSignal) {
    for clock in clocks {
        clock.end_wait(mark, pause);
    }
}

/// Resolve with the first armed clock to run out during the wait that began
/// at `mark`.  Pends forever when none is armed.  Cancel-safe: it mutates
/// nothing, so a select may drop it at any point.
pub(crate) async fn expired<const N: usize>(
    clocks: [BudgetClock; N],
    mark: WaitMark,
    mut pause: PauseSignal,
) -> ProgressKind {
    loop {
        let now = Instant::now();
        let soonest = clocks
            .iter()
            .filter_map(|clock| {
                clock
                    .remaining(mark, &pause, now)
                    .map(|remaining| (remaining, clock.kind))
            })
            .min_by_key(|(remaining, _)| *remaining);
        let Some((remaining, kind)) = soonest else {
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        };
        if remaining.is_zero() {
            return kind;
        }
        if pause.is_paused() {
            pause.changed().await;
            continue;
        }
        tokio::select! {
            () = tokio::time::sleep(remaining) => {}
            () = pause.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_finite_and_bounded() {
        let budgets = ProgressBudgets::default();
        assert_eq!(
            budgets.get(ProgressKind::FirstHead),
            Duration::from_secs(10)
        );
        assert_eq!(
            budgets.get(ProgressKind::CreditStall),
            Duration::from_secs(30)
        );
        assert_eq!(
            budgets.with_record(Duration::ZERO),
            Err(ConfigError::ProgressBudget)
        );
        assert_eq!(
            budgets.with_fin_after_end(MAX_PROGRESS_BUDGET + Duration::from_nanos(1)),
            Err(ConfigError::ProgressBudget)
        );
        assert!(budgets.with_credit_stall(MAX_PROGRESS_BUDGET).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_clock_expires_after_its_active_budget() {
        let budgets = ProgressBudgets::default()
            .with_record(Duration::from_secs(2))
            .expect("budget");
        let mut clock = BudgetClock::new(ProgressKind::Record, &budgets);
        let pause = PauseSignal::never();
        let mark = WaitMark::now(&pause);
        let started = Instant::now();
        // Unarmed: never expires.
        assert!(
            tokio::time::timeout(
                Duration::from_secs(60),
                expired([clock], mark, pause.clone())
            )
            .await
            .is_err()
        );
        clock.arm();
        let mark = WaitMark::now(&pause);
        let started_armed = Instant::now();
        assert_eq!(
            expired([clock], mark, pause.clone()).await,
            ProgressKind::Record
        );
        assert_eq!(started_armed.elapsed(), Duration::from_secs(2));
        assert!(started.elapsed() >= Duration::from_secs(62));
    }

    #[tokio::test(start_paused = true)]
    async fn trickled_waits_accumulate_and_do_not_restart_the_budget() {
        let budgets = ProgressBudgets::default()
            .with_record(Duration::from_secs(10))
            .expect("budget");
        let mut clock = BudgetClock::new(ProgressKind::Record, &budgets);
        let pause = PauseSignal::never();
        clock.arm();
        for _ in 0..9 {
            // Each trickled byte arrives after one second of waiting.
            let mark = WaitMark::now(&pause);
            tokio::time::sleep(Duration::from_secs(1)).await;
            clock.end_wait(mark, &pause);
            // Re-arming the same record keeps the accumulated time.
            clock.arm();
        }
        // Time spent blocked downstream is not a wait on the carrier.
        tokio::time::sleep(Duration::from_secs(100)).await;
        let mark = WaitMark::now(&pause);
        let started = Instant::now();
        assert_eq!(expired([clock], mark, pause).await, ProgressKind::Record);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_recorded_freeze_pauses_the_clock_and_the_soonest_budget_wins() {
        let budgets = ProgressBudgets::default()
            .with_first_head(Duration::from_secs(3))
            .and_then(|budgets| budgets.with_record(Duration::from_secs(5)))
            .expect("budgets");
        let controller = PauseController::new(false);
        let pause = controller.signal();
        let mut first = BudgetClock::new(ProgressKind::FirstHead, &budgets);
        let mut record = BudgetClock::new(ProgressKind::Record, &budgets);
        first.arm();
        record.arm();
        let mark = WaitMark::now(&pause);
        let started = Instant::now();
        let task = tokio::spawn(expired([first, record], mark, pause.clone()));
        tokio::time::sleep(Duration::from_secs(1)).await;
        controller.set(true);
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(!task.is_finished(), "a freeze stops the clock");
        controller.set(false);
        let kind = task.await.expect("join");
        assert_eq!(kind, ProgressKind::FirstHead);
        assert_eq!(started.elapsed(), Duration::from_secs(23));
        // The finished wait accounts only the unpaused three seconds.
        record.end_wait(mark, &pause);
        assert_eq!(record.used, Duration::from_secs(3));
        record.disarm();
        assert!(!record.is_armed());
    }
}
