# Verified Permissions

Floci provides the JSON 1.0 `VerifiedPermissions.IsAuthorized` wire operation
needed by local applications that use the explicit `local-policy-store`
development sentinel.

This is a local authorization fixture, not a Cedar policy engine. A
structurally valid request for `local-policy-store` returns `ALLOW`; any other
policy store ID returns `ResourceNotFoundException`. The fixture keeps local
development flows unblocked without treating arbitrary or production policy
store IDs as authorized.

## Supported operation

| Operation | Target | Behavior |
|---|---|---|
| `IsAuthorized` | `VerifiedPermissions.IsAuthorized` | Returns `ALLOW` for `local-policy-store` after validating the required principal, action, and resource identifiers |

## Example

```sh
aws --endpoint-url http://localhost:4566 verifiedpermissions is-authorized \
  --policy-store-id local-policy-store \
  --principal entityType=Core::User,entityId=user-alpha \
  --action actionType=Accounts::Action,actionId=ListAccounts \
  --resource entityType=Accounts::Account,entityId='*'
```

Management-plane policy store and Cedar policy evaluation operations are not
implemented.
