"""
SM-01: ERC-4626 Donation Attack Detector

Detects vaults where totalAssets() reads balanceOf(address(this)),
making them vulnerable to share price inflation via direct transfers.

Severity: High
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ERC4626Donation(AbstractDetector):
    ARGUMENT = "sm-erc4626-donation"
    HELP = "ERC-4626 vault vulnerable to donation-based share inflation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://securitymath.com/blog/erc4626-share-inflation-attacks"
    WIKI_TITLE = "ERC-4626 Donation Attack"
    WIKI_DESCRIPTION = (
        "Detects ERC-4626 vaults where totalAssets() uses "
        "balanceOf(address(this)), making the share price manipulable "
        "via direct token transfers."
    )

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            has_deposit = any(f.name == "deposit" for f in contract.functions)
            has_total_assets = any(
                f.name == "totalAssets" for f in contract.functions
            )

            if not (has_deposit and has_total_assets):
                continue

            for func in contract.functions:
                if func.name != "totalAssets":
                    continue

                for node in func.nodes:
                    for ir in node.irs:
                        if hasattr(ir, "function") and hasattr(
                            ir.function, "name"
                        ):
                            if ir.function.name == "balanceOf":
                                has_offset = self._has_virtual_shares(contract)
                                if not has_offset:
                                    info = [
                                        contract,
                                        " totalAssets() uses balanceOf()"
                                        " without virtual shares offset.\n",
                                        "\tDirect token transfers can"
                                        " inflate share price.\n",
                                    ]
                                    results.append(
                                        self.generate_result(info)
                                    )

        return results

    def _has_virtual_shares(self, contract):
        for func in contract.functions:
            if func.name in ("_convertToShares", "_convertToAssets"):
                source = str(func.source_mapping)
                if "decimalsOffset" in source or "OFFSET" in source:
                    return True
        return False