//! Defer an authenticated, nearly valid reader credential until the guest's
//! own clock enters its original signed window. Only a real-time verification
//! result may be returned. The original application request owns the deadline.
use std::time::{Duration, Instant};

use mvm_contract::protocol::mailbox::MailboxDeliveryError;
use mvm_core::mailbox::{MailboxError, frame::Refusal};

pub(super) const MAX_WINDOW_WAIT: Duration = Duration::from_secs(2);

pub(super) fn verify<T>(
    issued_ms: i64,
    wait_until: Instant,
    check: impl Fn(i64) -> Result<T, MailboxError>,
) -> Result<T, Refusal> {
    verify_using(
        issued_ms,
        wait_until,
        check,
        super::now_unix_ms,
        std::thread::sleep,
    )
}

fn verify_using<T>(
    issued_ms: i64,
    wait_until: Instant,
    check: impl Fn(i64) -> Result<T, MailboxError>,
    mut wall_now: impl FnMut() -> Result<i64, Refusal>,
    wait: impl FnOnce(Duration),
) -> Result<T, Refusal> {
    let observed = wall_now()?;
    match check(observed) {
        Ok(verified) => return Ok(verified),
        Err(MailboxError::DeliveryContract(MailboxDeliveryError::NotYetValid)) => {}
        Err(_) => return Err(Refusal::NotAuthorized),
    }
    let delay_ms = issued_ms
        .checked_sub(observed)
        .and_then(|delta| u64::try_from(delta).ok())
        .filter(|delta| *delta > 0)
        .ok_or(Refusal::NotAuthorized)?;
    let delay = Duration::from_millis(delay_ms);
    if delay >= wait_until.saturating_duration_since(Instant::now()) {
        return Err(Refusal::NotAuthorized);
    }
    // Preflight the exact signed credential and scope at the first valid
    // instant, before spending the bounded wait. Discard this result.
    drop(check(issued_ms).map_err(|_| Refusal::NotAuthorized)?);
    if delay >= wait_until.saturating_duration_since(Instant::now()) {
        return Err(Refusal::NotAuthorized);
    }
    wait(delay);
    let observed = wall_now()?;
    if observed < issued_ms || Instant::now() >= wait_until {
        return Err(Refusal::NotAuthorized);
    }
    check(observed).map_err(|_| Refusal::NotAuthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn window(now: i64) -> Result<i64, MailboxError> {
        if now < 1000 {
            Err(MailboxDeliveryError::NotYetValid.into())
        } else if now >= 1500 {
            Err(MailboxDeliveryError::Expired.into())
        } else {
            Ok(now)
        }
    }

    #[test]
    fn only_current_guest_time_grants_enrollment_or_lease() {
        let times = RefCell::new([394, 1001].into_iter());
        let slept = Cell::new(Duration::ZERO);
        let result = verify_using(
            1000,
            Instant::now() + MAX_WINDOW_WAIT,
            window,
            || Ok(times.borrow_mut().next().unwrap()),
            |d| slept.set(d),
        );
        assert_eq!(slept.get(), Duration::from_millis(606));
        assert_eq!(result, Ok(1001));
    }

    #[test]
    fn clock_rollback_and_crossed_expiry_never_release_authority() {
        for second in [990, 1500, 2000] {
            let times = RefCell::new([999, second].into_iter());
            assert_eq!(
                verify_using(
                    1000,
                    Instant::now() + MAX_WINDOW_WAIT,
                    window,
                    || Ok(times.borrow_mut().next().unwrap()),
                    |_| ()
                ),
                Err(Refusal::NotAuthorized)
            );
        }
    }

    #[test]
    fn invalid_future_signature_revocation_and_elapsed_budget_refuse_without_wait() {
        for failure in [
            MailboxError::ReaderEnrollmentSignatureInvalid,
            MailboxError::CapabilityRevoked,
            MailboxError::DeliveryContract(MailboxDeliveryError::StaleConsumerBoot),
        ] {
            let check = |now| {
                if now < 1000 {
                    window(now)
                } else {
                    Err(failure.clone())
                }
            };
            assert_eq!(
                verify_using(
                    1000,
                    Instant::now() + MAX_WINDOW_WAIT,
                    check,
                    || Ok(999),
                    |_| panic!("invalid original identity used the guest clock budget")
                ),
                Err(Refusal::NotAuthorized)
            );
        }
        for (now, until) in [
            (-2500, Instant::now() + MAX_WINDOW_WAIT),
            (999, Instant::now()),
        ] {
            assert_eq!(
                verify_using(
                    1000,
                    until,
                    window,
                    || Ok(now),
                    |_| panic!("wait outside original bound")
                ),
                Err(Refusal::NotAuthorized)
            );
        }
    }
}
