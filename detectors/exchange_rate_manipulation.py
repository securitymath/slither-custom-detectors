"""
SM-02: Exchange Rate Manipulation Detector

Flags lending protocols where exchange rate calculations
depend on balanceOf(), making them vulnerable to flash loan
manipulation.

Severity: High
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExchangeRateManipulation(AbstractDetector):
    ARGUMENT = "sm-exchange-rate"
    HELP = "Exchange rate calculation uses manipulable balanceOf()"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://securitymath.com/blog/flash-loan-attack-taxonomy"
    WIKI_TITLE = "Exchange Rate Manipulation via balanceOf"
    WIKI_DESCRIPTION = (
        "Detects lending protocols where share/debt exchange rates "
        "are derived from balanceOf(), which can be manipulated "
        "via flash loans or direct transfers."
    )

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            exchange_rate_funcs = [
                f
                for f in contract.functions
                if any(
                    kw in f.name.lower()
                    for kw in [
                        "exchangerate",
                        "exchange_rate",
                        "convertto",
                        "totalassets",
                        "sharevalue",
                    ]
                )
            ]

            for func in exchange_rate_funcs:
                uses_balance = False
                for node in func.nodes:
                    for ir in node.irs:
                        if hasattr(ir, "function") and hasattr(
                            ir.function, "name"
                        ):
                            if ir.function.name == "balanceOf":
                                uses_balance = True

                if uses_balance:
                    info = [
                        func,
                        " uses balanceOf() in exchange rate"
                        " calculation.\n",
                        "\tConsider using internal accounting.\n",
                    ]
                    results.append(self.generate_result(info))

        return results