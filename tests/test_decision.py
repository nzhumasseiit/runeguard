from runeguard.decision import Decision, DecisionType


def test_decision_dataclass_fields():
    decision = Decision(DecisionType.ALLOW, "allowed by policy")
    assert decision.type == DecisionType.ALLOW
    assert decision.reason == "allowed by policy"
