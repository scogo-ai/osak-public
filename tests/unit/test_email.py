from osak.accounts import email


def test_local_mailpit_wins_over_accidental_resend_key(monkeypatch):
    calls: list[str] = []

    class Response:
        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        calls.append(url)
        return Response()

    monkeypatch.setenv("OSAK_ENV", "development")
    monkeypatch.setenv("MAILPIT_API_URL", "http://mailpit:8025")
    monkeypatch.setenv("RESEND_API_KEY", "accidental-production-key")
    monkeypatch.setattr(email.httpx, "post", fake_post)

    assert email.send_email(to="user@example.test", subject="test", text="hello") is True
    assert calls == ["http://mailpit:8025/api/v1/send"]
