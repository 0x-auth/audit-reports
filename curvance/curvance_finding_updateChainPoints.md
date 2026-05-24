# Curvance Protocol — Security Finding
**Severity:** Medium  
**Category:** State Inconsistency / Latent Double-Deduction Risk  
**File:** `contracts/token/VeCVE.sol`  
**Lines:** 950–954 (vs. 934–943 for comparison)

---

## Summary

`updateChainPoints()` deducts from `chainPoints` but does **not** zero out `chainUnlocksByEpoch[epoch]` afterward. Its sibling function `updateUserPoints()` correctly deletes the mapping after deduction. This asymmetry leaves a live value in `chainUnlocksByEpoch[epoch]` after the epoch is processed, creating a latent double-deduction risk if the epoch delivery control flow ever changes.

---

## Vulnerable Code

**`updateChainPoints` — missing cleanup (VeCVE.sol:950–954):**
```solidity
function updateChainPoints(uint256 epoch) external {
    _validateCallbackFromRewardManager();
    chainPoints = chainPoints - chainUnlocksByEpoch[epoch];
    // chainUnlocksByEpoch[epoch] is NOT zeroed after deduction
}
```

**`updateUserPoints` — correct pattern (VeCVE.sol:934–943):**
```solidity
function updateUserPoints(address user, uint256 epoch) external {
    _validateCallbackFromRewardManager();
    if (isShutdown != 2) {
        _canModifyState();
    }
    userPoints[user] = userPoints[user] - userUnlocksByEpoch[user][epoch];
    delete userUnlocksByEpoch[user][epoch];  // ← correctly zeroed
}
```

The two functions are designed as a pair — one updates per-user points, the other updates the global chain total. They should be symmetric. They are not.

---

## Root Cause — Broken Causal Arrow

In the Lambda_G / causal flow model:

```
Correct causal order (updateUserPoints):
  t=0: READ  userUnlocksByEpoch[user][epoch]   → get value
  t=1: WRITE userPoints -= value               → apply effect
  t=2: DELETE userUnlocksByEpoch[user][epoch]  → close the cause

Broken causal order (updateChainPoints):
  t=0: READ  chainUnlocksByEpoch[epoch]        → get value
  t=1: WRITE chainPoints -= value              → apply effect
  t=2: (missing) cause never closed            → D_E += 1
```

The cause (`chainUnlocksByEpoch[epoch]`) remains live after its effect has been applied. This is a causal inversion: the system has consumed the value but left the trigger intact, meaning any future read of `chainUnlocksByEpoch[epoch] > 0` will return `true` even though the deduction already happened.

---

## Current Exploitability

The current control flow in `RewardManager` prevents exploitation:

- `recordEpochRewards()` (line 207–210): checks `chainUnlocksByEpoch(epoch) > 0`, calls `updateChainPoints(epoch)`, then does `nextEpochToDeliver++`
- `overrideRecordEpochRewards()` (line 136–139): same pattern

Both paths increment `nextEpochToDeliver` after calling `updateChainPoints`, so the same epoch index cannot be re-entered through either path. The epoch counter acts as an accidental guard.

**However**, the missing `delete` is dangerous because:

1. Any future refactor that reads `chainUnlocksByEpoch[epoch]` for a delivered epoch will see a non-zero value and potentially apply the deduction again
2. Any new code path that calls `updateChainPoints` without the `nextEpochToDeliver++` guard would cause `chainPoints` to underflow
3. Off-chain tooling or indexers reading `chainUnlocksByEpoch` post-delivery will see stale non-zero values, misrepresenting protocol state

---

## Impact

If the double-deduction were triggered:

- `chainPoints` (the denominator in reward-per-point calculation) would be artificially reduced
- `epochRewardsPerPoint = feeTokensHeld * WAD_SQUARED / chainPoints` would be inflated
- All users claiming rewards after this point receive more than their fair share
- Eventually `chainPoints` underflows to zero or wraps, breaking all reward distribution permanently

---

## Proof of Inconsistency

The protocol's own comment at line 947 says:
> "This function is only called when `chainUnlocksByEpoch[epoch] > 0`"

If the value were zeroed after the call (as in `updateUserPoints`), this comment would be trivially satisfied by construction — the mapping would be 0 after delivery so the guard would prevent re-entry naturally. The fact that the comment exists as a *documentation note* rather than an *enforced invariant* is itself evidence of the missing cleanup.

---

## Fix

```solidity
function updateChainPoints(uint256 epoch) external {
    _validateCallbackFromRewardManager();
    chainPoints = chainPoints - chainUnlocksByEpoch[epoch];
    delete chainUnlocksByEpoch[epoch];  // mirror updateUserPoints
}
```

One line. Makes the invariant self-enforcing rather than documentation-dependent.

---

## References

- `VeCVE.sol:950–954` — `updateChainPoints`
- `VeCVE.sol:934–943` — `updateUserPoints` (correct pattern)
- `RewardManager.sol:136–139` — `overrideRecordEpochRewards` caller
- `RewardManager.sol:207–210` — `recordEpochRewards` caller
