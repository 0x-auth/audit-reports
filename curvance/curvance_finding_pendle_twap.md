# Curvance Protocol — Security Finding
**Severity:** Critical  
**Category:** Oracle Manipulation / Single-Oracle TWAP Exploit  
**Files:**
- `contracts/oracles/adaptors/pendle/PendleLPTokenAdaptor.sol` (line 97)
- `contracts/oracles/OracleManager.sol` (lines 484, 227)
- `contracts/market/isolated/MarketManagerIsolated.sol` (line 1629)

---

## Summary

`PendleLPTokenAdaptor` prices Pendle LP tokens using a TWAP with a minimum duration of **12 seconds**. The OracleManager's deviation-bound protection (CAUTION/BAD_SOURCE error codes) only activates when **two oracles are configured** for an asset. On a new deployment — specifically Monad at launch — Pendle LP markets are likely configured with a single oracle. This means:

1. A 12-second TWAP on a shallow-liquidity pool can be manipulated in 1–2 blocks
2. The manipulated price returns `NO_ERROR` — no safety net catches it
3. The inflated collateral value allows a borrower to drain the entire debt vault

---

## Vulnerable Code Path

### Step 1 — TWAP price with no runtime cardinality check
**`PendleLPTokenAdaptor.getPrice` (line 97):**
```solidity
uint256 lpRate = IPMarket(asset).getLpToAssetRate(config.twapDuration);
```
- `config.twapDuration >= 12` seconds (minimum enforced at `addAsset` time only)
- `getLpToAssetRate` returns whatever the TWAP says — no error code, no manipulation check
- If the TWAP window is manipulated, `lpRate` is inflated silently
- Result: `result.price = (price * lpRate) / WAD` — inflated, `hadError = false`

### Step 2 — Single oracle = zero deviation protection
**`OracleManager.setDeviationBounds` (line 484):**
```solidity
if (config.adaptors.length < 2) {
    revert OracleManager__InvalidParameter();
}
```
Deviation bounds (CAUTION/BAD_SOURCE error codes from dual-oracle divergence) **cannot be set** for single-oracle assets. With one adaptor, there is no cross-check. The manipulated price flows through as `NO_ERROR`.

### Step 3 — Inflated price goes directly into borrow capacity
**`MarketManagerIsolated._getLiquidationConfig` (line 1627–1629) and `_canBorrow`:**
```solidity
(tData.collateralSharesPrice, tData.debtUnderlyingPrice) =
    CommonLib._oracleManager(centralRegistry)
        .getPriceIsolatedPair(collateralToken, debtToken, BAD_SOURCE);
```
`BAD_SOURCE` (errorCode = 2) is the only thing that blocks borrow/liquidation. A manipulated TWAP returns `NO_ERROR` (0) — never reaches the revert threshold.

---

## Attack Steps

```
Prerequisites:
- Pendle LP token listed as collateral in Curvance isolated market on Monad
- Configured with single oracle (PendleLPTokenAdaptor, twapDuration = 12s)
- Shallow LP liquidity (typical at chain launch)

Attack:

t=0: Attacker acquires large Pendle LP position (flash loan or own capital)

t=1: Attacker executes large swap IN the Pendle pool, moving spot price up
     significantly. On low-liquidity pool, 1 block = enough to skew TWAP.

t=2 (12 seconds later, same or next block on Monad):
     TWAP window now reflects manipulated spot price.
     getLpToAssetRate() returns inflated lpRate.
     Curvance prices the LP collateral at 2x–10x fair value.
     Error code = NO_ERROR — no circuit breaker fires.

t=3: Attacker calls depositAsCollateral() with their Pendle LP.
     Collateral is valued at inflated price.
     canBorrow() allows borrowing against inflated collateral value.

t=4: Attacker borrows entire USDC/ETH vault against inflated collateral.
     Protocol takes on bad debt equal to (inflated value - true value) * amount.

t=5: TWAP reverts to fair value. Attacker's collateral is now underwater.
     Protocol has bad debt, lenders lose funds.
```

**Net result:** Attacker walks away with borrowed assets. Protocol is left with uncollateralized bad debt.

---

## Why the Existing Defenses Don't Help

| Defense | Why it fails |
|---|---|
| Dual oracle deviation bounds | Only active with 2 adaptors. Single-oracle = no deviation check. |
| `BAD_SOURCE` error code gate | Only triggers on errorCode = 2. Manipulated TWAP returns errorCode = 0. |
| `_checkPtTwap` at addAsset | Only runs once at setup. No runtime re-check of cardinality or observation freshness. |
| `MINIMUM_TWAP_DURATION = 12s` | 12 seconds is 1–2 blocks on Monad. Not meaningful protection on a fast chain. |
| PriceGuard / `_adjustPrice` | Only clamps if configured. Not guaranteed to be set for new Monad markets. |

---

## Causal Flow Analysis

In Lambda_G terms, the broken arrow of time is:

```
Correct order (secure):
  t=0: READ  spot price (current)
  t=1: VERIFY price is consistent with second source
  t=2: USE   price for collateral valuation

Broken order (vulnerable, single oracle):
  t=0: READ  spot price (manipulated TWAP)
  t=1: (VERIFY step missing — no second source)
  t=2: USE   manipulated price for collateral valuation

D_E += 1: cause (verification) missing before effect (lending decision)
```

The missing verification step is not a code bug per se — the code supports dual oracles. The bug is **the protocol allows single-oracle configuration for complex yield assets on new low-liquidity chains without enforcing a minimum TWAP duration appropriate for that chain's block time.**

---

## Impact

- **Direct fund loss:** Full debt vault can be drained in a single transaction
- **Scope:** Any Pendle LP market on Monad configured with single oracle
- **Likelihood:** High at chain launch — second oracle sources (Chainlink, Redstone) often not available for new Pendle markets on new chains
- **Severity:** Critical — complete protocol insolvency possible

---

## Fix Options

**Option A (Immediate): Enforce minimum TWAP duration per chain**
```solidity
// In addAsset, enforce chain-appropriate minimum
uint32 public constant MONAD_MINIMUM_TWAP_DURATION = 900; // 15 minutes
```

**Option B (Immediate): Require dual oracle for all LP collateral assets**
```solidity
// In MarketManagerIsolated.listToken for cTokens backed by LP assets
require(
    oracleManager.getAdaptorCount(underlying) >= 2,
    "LP collateral requires dual oracle"
);
```

**Option C (Best): Runtime TWAP health check in getPrice**
```solidity
// In PendleLPTokenAdaptor.getPrice, re-check observation before using
(bool increaseCardinalityRequired, , bool oldestObservationSatisfied) =
    ptOracle.getOracleState(asset, config.twapDuration);
if (increaseCardinalityRequired || !oldestObservationSatisfied) {
    result.hadError = true;
    return result;
}
```
This makes the setup-time check (`_checkPtTwap`) also a runtime check, returning `hadError = true` if TWAP health degrades — which then bubbles up as `BAD_SOURCE` and blocks the borrow.

---

## References

- `PendleLPTokenAdaptor.sol:37` — `MINIMUM_TWAP_DURATION = 12`
- `PendleLPTokenAdaptor.sol:97` — `getLpToAssetRate(config.twapDuration)` no error code
- `PendleLPTokenAdaptor.sol:180–193` — `_checkPtTwap` only at addAsset, not getPrice
- `OracleManager.sol:484` — deviation bounds require 2 adaptors
- `OracleManager.sol:227` — single adaptor path has no cross-check
- `MarketManagerIsolated.sol:1629` — `getPriceIsolatedPair` with `BAD_SOURCE` threshold
