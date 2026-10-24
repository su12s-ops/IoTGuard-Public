from app.services.unified.agent_base import UsageMeter, BudgetExceeded
import pytest


def test_role_budget_visible_without_falsely_exhausting_other_roles():
    meter = UsageMeter(max_tokens=1000, role_token_limits={'runtime_analyst': 50, 'decision_planner': 100})
    meter.register_call({'total_tokens': 60}, role='runtime_analyst')
    summary = meter.as_dict()
    assert summary['role_budgets_exhausted'] == ['runtime_analyst']
    assert summary['budget_exceeded'] is False  # run-level limit remains distinct
    with pytest.raises(BudgetExceeded):
        meter.ensure_budget('runtime_analyst')
    meter.ensure_budget('decision_planner')
    assert summary['usage']['total_tokens'] == 60
