import pytest

from scripts.qa.signup_admin_smoke import extract_api_key


@pytest.mark.parametrize("environment", ["test", "live"])
def test_key_extractor_returns_only_expected_credentials(environment: str) -> None:
    example = f"osak_{environment}_abc_DEF-123"
    assert extract_api_key(f"Your API key: {example}") == example


def test_extractors_do_not_match_unrelated_text() -> None:
    assert extract_api_key("osak_live_") is None
