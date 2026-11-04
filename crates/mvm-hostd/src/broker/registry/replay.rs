use super::*;

pub(super) struct OwnedKey {
    service: Box<str>,
    verb: Box<str>,
    request: Box<str>,
}
pub(super) enum ReplaySet {
    General(HashSet<(CapabilityId, AgentRequestId)>),
    Owned {
        entries: Vec<OwnedKey>,
        limit: usize,
    },
}
impl ReplaySet {
    pub(super) fn general() -> Self {
        Self::General(HashSet::new())
    }
    pub(super) fn owned(limit: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            usize::BITS == 64
                && std::mem::size_of::<OwnedKey>() <= 48
                && (1..=8192).contains(&limit),
            "owned replay layout/capacity"
        );
        let mut entries = Vec::new();
        entries.try_reserve_exact(limit)?;
        anyhow::ensure!(entries.capacity() == limit, "owned replay backing capacity");
        Ok(Self::Owned { entries, limit })
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        match self {
            Self::General(entries) => entries.len(),
            Self::Owned { entries, .. } => entries.len(),
        }
    }
    #[cfg(test)]
    pub(super) fn owned_layout(&self) -> (usize, usize, usize) {
        match self {
            Self::Owned { entries, .. } => (
                std::mem::size_of::<OwnedKey>(),
                entries.capacity(),
                entries
                    .iter()
                    .map(|key| key.service.len() + key.verb.len() + key.request.len())
                    .sum(),
            ),
            Self::General(_) => panic!("not the owned replay profile"),
        }
    }
    pub(super) fn insert(
        &mut self,
        capability: &CapabilityId,
        request: &AgentRequestId,
    ) -> Result<bool, ServiceError> {
        match self {
            Self::General(entries) => Ok(entries.insert((capability.clone(), request.clone()))),
            Self::Owned { entries, limit } => {
                let probe = (
                    capability.service.as_str(),
                    capability.verb.as_str(),
                    request.as_str(),
                );
                let position = match entries.binary_search_by(|key| {
                    (
                        key.service.as_ref(),
                        key.verb.as_ref(),
                        key.request.as_ref(),
                    )
                        .cmp(&probe)
                }) {
                    Ok(_) => return Ok(false),
                    Err(position) => position,
                };
                let bytes = probe
                    .0
                    .len()
                    .checked_add(probe.1.len())
                    .and_then(|bytes| bytes.checked_add(probe.2.len()));
                if bytes.is_none_or(|bytes| bytes > 256) {
                    return Err(ServiceError::new(
                        ServiceErrorCode::BadRequest,
                        "owned replay identity bytes",
                    ));
                }
                if entries.len() >= *limit {
                    return Err(ServiceError::new(
                        ServiceErrorCode::Unavailable,
                        "owned capability replay capacity exhausted",
                    ));
                }
                // Exact-sized immutable boxed strings avoid retained String capacity.
                entries.insert(
                    position,
                    OwnedKey {
                        service: probe.0.into(),
                        verb: probe.1.into(),
                        request: probe.2.into(),
                    },
                );
                Ok(true)
            }
        }
    }
}
