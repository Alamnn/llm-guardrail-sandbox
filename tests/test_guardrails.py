from rag_sandbox import evaluate


def test_guardrails_block_all_attacks_and_allow_benign():
    res = evaluate()
    m = res["metrics"]
    assert m["before_guardrails_successful_exploits"] == 8
    assert m["after_guardrails_successful_exploits"] == 0
    assert m["exploit_reduction_pct"] == 100.0
    assert m["benign_queries_passed"] == "2/2"
