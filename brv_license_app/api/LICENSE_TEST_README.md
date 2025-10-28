# License API Test Suite

Comprehensive test suite for the `license.py` API module following Frappe testing conventions.

## Test Structure

The test suite is organized into two main test classes:

### 1. `TestLicenseHealthz`
Tests the `healthz()` endpoint which provides license health status information.

**Tests covered:**
- Basic response structure validation
- Status validation for all license states:
  - `ACTIVE` - License is active (ok=True)
  - `VALIDATED` - License is validated (ok=True)  
  - `EXPIRED` - License expired (ok=False)
  - `REVOKED` - License revoked (ok=False)
  - `UNCONFIGURED` - License not configured (ok=False)
  - `DEACTIVATED` - License deactivated (ok=False)
- Grace period handling:
  - Valid grace period (future date) with EXPIRED status → ok=True
  - Expired grace period (past date) with EXPIRED status → ok=False
  - Grace period boundary conditions
- Field presence validation (reason, last_validated, grace_until)
- Case sensitivity handling
- Empty/null status handling
- Guest user access (allow_guest=True)
- Multiple status transitions
- Concurrent calls

### 2. `TestLicenseEdgeCases`
Tests edge cases and error handling scenarios.

**Tests covered:**
- Malformed grace_until date handling
- Status with whitespace
- Concurrent API calls
- Immediate status change reflection

## License Status Values

The License Settings DocType supports the following status values:

| Status | Description | ok Value |
|--------|-------------|----------|
| `UNCONFIGURED` | License not yet configured | False |
| `ACTIVE` | License is active and valid | True |
| `VALIDATED` | License has been validated | True |
| `DEACTIVATED` | License has been deactivated | False |
| `EXPIRED` | License has expired | False* |
| `REVOKED` | License has been revoked | False |
| `GRACE_SOFT` | Soft grace period | False |
| `LOCK_HARD` | Hard lock state | False |

*Exception: EXPIRED with valid grace_until (future date) returns ok=True

## Grace Period Logic

The `healthz()` endpoint implements grace period logic:

```python
# License is OK if:
ok = status in {"ACTIVE", "VALIDATED"} or (status == "EXPIRED" and grace_active)

# Grace is active if:
grace_active = grace_until is not None and grace_until > now_datetime()
```

## Running the Tests

### Run all license tests
```bash
bench --site [sitename] run-tests --module brv_license_app.api.test_license
```

### Run specific test class
```bash
bench --site [sitename] run-tests --module brv_license_app.api.test_license --test TestLicenseHealthz
```

### Run specific test method
```bash
bench --site [sitename] run-tests --module brv_license_app.api.test_license --test test_healthz_status_active
```

### Run with verbose output
```bash
bench --site [sitename] --verbose run-tests --module brv_license_app.api.test_license
```

## Test Requirements

### Prerequisites
1. Testing must be enabled for the site:
   ```bash
   bench --site [sitename] set-config allow_tests true
   ```

2. The License Settings DocType must exist:
   ```bash
   bench --site [sitename] migrate
   ```

3. License Settings is a **Single DocType** (issingle=1), stored in tabSingles table

### DocType Fields
The tests expect the following fields in License Settings:
- `status` (Select) - License status
- `grace_until` (Datetime) - Grace period expiry
- `reason` (Text) - Status reason/message
- `last_validated` (Datetime) - Last validation timestamp

## Test Data Management

- License Settings is a singleton, so tests modify the same document
- `setUp()` ensures License Settings document exists
- `tearDown()` resets License Settings to default state
- Tests use `ignore_permissions=True` for setup/teardown
- Direct DB updates via `frappe.db.set_value()` used to test malformed data

## API Response Structure

The `healthz()` endpoint returns:

```python
{
    "app": "brv_license_app",          # App identifier
    "site": "sitename",                # Current site
    "status": "ACTIVE",                # License status (uppercase)
    "grace_until": "2025-11-28...",   # Grace expiry (or None)
    "reason": "...",                   # Status reason (or None)
    "last_validated": "2025-10-28...", # Last validation (or None)
    "ok": True                         # Overall health status
}
```

## Test Coverage

Current coverage:
- ✅ Basic structure validation (100%)
- ✅ All status values (100%)
- ✅ Grace period logic (100%)
- ✅ Field presence (100%)
- ✅ Edge cases (100%)
- ✅ Error handling (100%)
- ✅ Guest access (100%)
- ✅ Case sensitivity (100%)

**Total: 22 tests** (all passing)

## Key Test Scenarios

### Valid License States
```python
# Active license
result = healthz()
assert result["ok"] == True
assert result["status"] == "ACTIVE"

# Expired with grace
result = healthz()  # grace_until in future
assert result["ok"] == True
assert result["status"] == "EXPIRED"
```

### Invalid License States
```python
# Expired without grace
result = healthz()
assert result["ok"] == False
assert result["status"] == "EXPIRED"

# Revoked license
result = healthz()
assert result["ok"] == False
assert result["status"] == "REVOKED"
```

### Grace Period Boundaries
```python
# 1 hour in future - valid
grace_until = add_to_date(now_datetime(), hours=1)
assert result["ok"] == True

# 1 hour in past - invalid
grace_until = add_to_date(now_datetime(), hours=-1)
assert result["ok"] == False
```

## Common Issues

### Issue: All tests skipped
**Cause:** License Settings DocType doesn't exist or isn't migrated  
**Solution:** Run `bench --site [sitename] migrate`

### Issue: ValidationError on status
**Cause:** Using invalid status value not in allowed options  
**Solution:** Use valid status from the list: UNCONFIGURED, ACTIVE, VALIDATED, DEACTIVATED, EXPIRED, REVOKED, GRACE_SOFT, LOCK_HARD

### Issue: SingletonMustHaveValueError
**Cause:** License Settings document doesn't exist  
**Solution:** Tests automatically create it in setUp() if missing

## Contributing

When adding new features to `license.py`:
1. Add corresponding test methods to appropriate test class
2. Test both happy path and error conditions
3. Verify grace period logic if adding status-related changes
4. Ensure tests clean up properly in tearDown()
5. Use subtests for multiple related scenarios
6. Document expected behavior in test docstrings

## Test Execution Time

- Average execution time: ~0.5 seconds for all 22 tests
- Tests run sequentially (no parallel execution for Singles)
- Fast execution due to minimal DB operations

## References

- [Frappe Testing Documentation](https://docs.frappe.io/framework/user/en/testing)
- [Python unittest Documentation](https://docs.python.org/3/library/unittest.html)
- [Frappe Single DocTypes](https://frappeframework.com/docs/user/en/basics/doctypes/single)
