(() => {
  "use strict";

  const root = document.documentElement;
  const themeToggle = document.querySelector("#theme-toggle");
  const themeLabel = document.querySelector(".theme-label");
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  const form = document.querySelector("#signup-form");
  const formStatus = document.querySelector("#form-status");
  const sourceList = document.querySelector("#source-list");
  const coverageStatus = document.querySelector("#coverage-status-label");
  const sourceCount = document.querySelector("#source-count");
  const turnstileSlot = document.querySelector("#turnstile-widget");
  const turnstileToken = document.querySelector("#turnstile-token");
  const turnstileKey = document.querySelector('meta[name="turnstile-site-key"]')?.content?.trim() || "";
  let turnstileWidgetId = null;

  const setTheme = (theme) => {
    const isDark = theme === "dark";
    root.dataset.theme = isDark ? "dark" : "light";
    if (themeToggle) {
      themeToggle.setAttribute("aria-pressed", String(isDark));
      if (themeLabel) themeLabel.textContent = isDark ? "Use light mode" : "Use dark mode";
    }
    if (themeMeta) themeMeta.setAttribute("content", isDark ? "#09131d" : "#f5f1e8");
  };

  let savedTheme = "";
  try { savedTheme = window.localStorage.getItem("osak-theme") || ""; } catch (_) { /* Private browsing can deny storage. */ }
  setTheme(savedTheme === "dark" ? "dark" : "light");
  themeToggle?.addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    setTheme(next);
    try { window.localStorage.setItem("osak-theme", next); } catch (_) { /* Theme still works without persistence. */ }
  });

  const sourceItems = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== "object") return [];
    if (Array.isArray(payload.items)) return payload.items;
    if (Array.isArray(payload.sources)) return payload.sources;
    if (Array.isArray(payload.data)) return payload.data;
    if (payload.data && Array.isArray(payload.data.items)) return payload.data.items;
    return [];
  };

  const textValue = (value, fallback) => {
    if (value === null || value === undefined || value === "") return fallback;
    return String(value);
  };

  const formatSync = (value) => {
    if (!value) return "Not reported";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return textValue(value, "Not reported");
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  };

  const sourceStatus = (item) => {
    const raw = String(item.status || item.health || item.state || "").toLowerCase();
    if (raw === "running") return ["pending", item.last_success_at ? "Syncing" : "Initial sync in progress"];
    if (raw === "idle") return ["pending", item.last_success_at ? "Idle" : "Awaiting first sync"];
    if (["ok", "healthy", "live", "ready", "success", "synced"].includes(raw)) return ["live", "Healthy"];
    if (["error", "failed", "stale", "degraded"].includes(raw)) return ["error", textValue(item.status || item.health, "Needs review")];
    return ["pending", textValue(item.status || item.health, "Pending")];
  };

  const renderSources = (items) => {
    if (!sourceList || !items.length) return;
    sourceList.replaceChildren();
    items.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const row = document.createElement("tr");
      const name = document.createElement("td");
      const role = document.createElement("td");
      const sync = document.createElement("td");
      const statusCell = document.createElement("td");
      const status = document.createElement("span");
      name.dataset.label = "Source";
      role.dataset.label = "Role";
      sync.dataset.label = "Last successful sync";
      statusCell.dataset.label = "Status";
      name.textContent = textValue(item.name || item.id || item.source || item.source_id, "Unnamed source");
      role.textContent = textValue(item.kind || item.role || item.type || item.metadata_json?.kind, "Advisory source");
      sync.textContent = formatSync(item.last_success_at || item.last_synced_at || item.last_sync);
      const [statusClass, statusText] = sourceStatus(item);
      status.className = `table-status table-status-${statusClass}`;
      status.textContent = statusText;
      statusCell.append(status);
      row.append(name, role, sync, statusCell);
      sourceList.append(row);
    });
    if (sourceCount) sourceCount.textContent = String(sourceList.children.length);
  };

  const loadSources = async () => {
    if (!coverageStatus) return;
    try {
      const response = await fetch("/api/v1/sources", { headers: { Accept: "application/json" }, credentials: "omit" });
      if (!response.ok) throw new Error("source request failed");
      const items = sourceItems(await response.json());
      if (!items.length) throw new Error("source response was empty");
      renderSources(items);
      coverageStatus.textContent = `${items.length} sources reporting`;
    } catch (_) {
      coverageStatus.textContent = "Live source health is temporarily unavailable";
    }
  };
  loadSources();

  const getTextForCopy = (target) => {
    if (!target) return "";
    return target.textContent.trim();
  };

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget || "");
      const text = getTextForCopy(target);
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
      } catch (_) {
        const range = document.createRange();
        range.selectNodeContents(target);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
        document.execCommand("copy");
        selection?.removeAllRanges();
      }
      const previous = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = previous; }, 1400);
    });
  });

  const clearTurnstileToken = (state) => {
    if (turnstileToken) turnstileToken.value = "";
    if (turnstileSlot && state) turnstileSlot.dataset.state = state;
  };

  const resetTurnstileWidget = () => {
    clearTurnstileToken("reset");
    if (window.turnstile && turnstileWidgetId !== null) window.turnstile.reset(turnstileWidgetId);
  };

  window.onTurnstileSuccess = (token) => {
    if (turnstileToken) turnstileToken.value = token || "";
    if (turnstileSlot) turnstileSlot.dataset.state = token ? "ready" : "empty";
  };
  window.onTurnstileExpired = () => clearTurnstileToken("expired");
  window.onTurnstileError = () => clearTurnstileToken("error");
  window.onTurnstileReset = () => clearTurnstileToken("reset");

  const initTurnstile = () => {
    if (!turnstileSlot || !turnstileKey) return;
    turnstileSlot.dataset.sitekey = turnstileKey;
    turnstileSlot.replaceChildren();
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.onload = () => {
      if (window.turnstile) {
        turnstileWidgetId = window.turnstile.render(turnstileSlot, {
          sitekey: turnstileKey,
          callback: window.onTurnstileSuccess,
          "expired-callback": window.onTurnstileExpired,
          "error-callback": window.onTurnstileError,
          "timeout-callback": window.onTurnstileExpired,
        });
      }
    };
    document.head.append(script);
  };
  initTurnstile();

  const setFormStatus = (message, state = "") => {
    if (!formStatus) return;
    formStatus.textContent = message;
    if (state) formStatus.dataset.state = state; else delete formStatus.dataset.state;
  };

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      setFormStatus("Complete the required fields, then try again.", "error");
      return;
    }
    const token = turnstileToken?.value?.trim() || "";
    if (!token) {
      setFormStatus("Spam protection is not ready yet. Configure Turnstile before requesting a key.", "error");
      return;
    }
    const button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    setFormStatus("Sending your API key email…");
    const formData = new FormData(form);
    const body = {
      name: String(formData.get("name") || "").trim(),
      organization: String(formData.get("organization") || "").trim(),
      email: String(formData.get("email") || "").trim(),
      turnstile_token: token,
      accept_terms: formData.has("accept_terms"),
      accepted_terms_version: "v1",
    };
    try {
      const response = await fetch("/api/v1/signup", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        credentials: "omit",
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error("signup failed");
      setFormStatus("If eligible, we’ll send one email containing your API key. If this address already has an active key, we won’t revoke it or issue a second one.");
      form.reset();
      resetTurnstileWidget();
    } catch (_) {
      setFormStatus("The request could not be sent. Check your connection and try again.", "error");
    } finally {
      if (button) button.disabled = false;
    }
  });
})();
