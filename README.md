# Slither Custom Detectors

Custom [Slither](https://github.com/crytic/slither) detectors developed during our audit practice. These focus on vulnerability patterns commonly missed by built-in detectors.

## Detectors

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SM-01 | `erc4626-donation` | High | Detects ERC-4626 vaults vulnerable to donation-based share inflation |
| SM-02 | `exchange-rate-manipulation` | High | Flags exchange rate calculations that read `balanceOf(address(this))` |
| SM-03 | `flash-loan-deposit` | Medium | Identifies deposit functions callable within flash loan callbacks |
| SM-04 | `missing-slippage` | Medium | Detects swap operations without minimum output checks |
| SM-05 | `unprotected-initialize` | High | Finds initializer functions without access control |

## Usage

```bash
pip install slither-analyzer
slither . --detect sm-erc4626-donation,sm-exchange-rate
```

## References

- [ERC-4626 Share Inflation Attacks](https://securitymath.com/blog/erc4626-share-inflation-attacks)
- [Flash Loan Attack Taxonomy](https://securitymath.com/blog/flash-loan-attack-taxonomy)

## License

MIT