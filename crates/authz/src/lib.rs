use identity::InstanceRole;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("forbidden")]
    Forbidden,
}

pub type Result<T> = std::result::Result<T, AuthorizationError>;

/// Returns true if `actor`'s instance role meets or exceeds `required`.
///
/// Owner ⊇ Admin ⊇ User: Owner satisfies any role, Admin satisfies Admin
/// or User, User satisfies only User.
pub fn satisfies(actor: InstanceRole, required: InstanceRole) -> bool {
    rank(actor) >= rank(required)
}

/// Convenience: returns `Err(Forbidden)` when `satisfies` would be false.
pub fn require(actor: InstanceRole, required: InstanceRole) -> Result<()> {
    if satisfies(actor, required) {
        Ok(())
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

/// Returns true when `actor` strictly outranks `target` — i.e., an Owner
/// can act on Admin or User but not another Owner; an Admin can act on
/// User but not another Admin or any Owner.
///
/// Stricter than [`satisfies`] (which is `>=`). Used by mutation actions
/// where "peer-on-peer" is disallowed — currently the lifecycle
/// transitions in `/admin/users/{id}/*`. Invitations still use
/// `satisfies` because creating a peer (Admin invites Admin) is allowed.
pub fn outranks(actor: InstanceRole, target: InstanceRole) -> bool {
    rank(actor) > rank(target)
}

fn rank(role: InstanceRole) -> u8 {
    match role {
        InstanceRole::User => 0,
        InstanceRole::Admin => 1,
        InstanceRole::Owner => 2,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn owner_satisfies_every_role() {
        assert!(satisfies(InstanceRole::Owner, InstanceRole::Owner));
        assert!(satisfies(InstanceRole::Owner, InstanceRole::Admin));
        assert!(satisfies(InstanceRole::Owner, InstanceRole::User));
    }

    #[test]
    fn admin_satisfies_admin_and_user_but_not_owner() {
        assert!(!satisfies(InstanceRole::Admin, InstanceRole::Owner));
        assert!(satisfies(InstanceRole::Admin, InstanceRole::Admin));
        assert!(satisfies(InstanceRole::Admin, InstanceRole::User));
    }

    #[test]
    fn user_satisfies_only_user() {
        assert!(!satisfies(InstanceRole::User, InstanceRole::Owner));
        assert!(!satisfies(InstanceRole::User, InstanceRole::Admin));
        assert!(satisfies(InstanceRole::User, InstanceRole::User));
    }

    #[test]
    fn require_succeeds_when_role_satisfies() {
        require(InstanceRole::Owner, InstanceRole::Admin).unwrap();
        require(InstanceRole::Admin, InstanceRole::Admin).unwrap();
        require(InstanceRole::Owner, InstanceRole::Owner).unwrap();
    }

    #[test]
    fn require_returns_forbidden_when_role_insufficient() {
        assert!(matches!(
            require(InstanceRole::User, InstanceRole::Admin),
            Err(AuthorizationError::Forbidden)
        ));
        assert!(matches!(
            require(InstanceRole::Admin, InstanceRole::Owner),
            Err(AuthorizationError::Forbidden)
        ));
    }

    #[test]
    fn outranks_is_strict() {
        // Owner outranks Admin and User; not another Owner.
        assert!(outranks(InstanceRole::Owner, InstanceRole::Admin));
        assert!(outranks(InstanceRole::Owner, InstanceRole::User));
        assert!(!outranks(InstanceRole::Owner, InstanceRole::Owner));

        // Admin outranks User; not Owner or another Admin.
        assert!(outranks(InstanceRole::Admin, InstanceRole::User));
        assert!(!outranks(InstanceRole::Admin, InstanceRole::Admin));
        assert!(!outranks(InstanceRole::Admin, InstanceRole::Owner));

        // User outranks nobody.
        assert!(!outranks(InstanceRole::User, InstanceRole::User));
        assert!(!outranks(InstanceRole::User, InstanceRole::Admin));
        assert!(!outranks(InstanceRole::User, InstanceRole::Owner));
    }
}
