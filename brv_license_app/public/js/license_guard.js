// /home/frappe/frappe-bench/apps/brv_license_app/brv_license_app/public/js/license_guard.js
/* global frappe */

(function () {
  const BOOT = () => (frappe && frappe.boot && frappe.boot.brv_license) || null;

  function isoToDate(v) {
    try {
      return v ? new Date(v) : null;
    } catch (_) {
      return null;
    }
  }

  function showExpiredBanner(snap) {
    const until = isoToDate(snap.grace_until);
    const untilStr = until ? until.toLocaleString() : __("unknown");

    const html =
      `<div style="padding:6px 10px">
        <b>${__("License expired")}</b> – ${__(
          "You are in a grace period until"
        )} <b>${untilStr}</b>.
        ${snap.reason ? `<div style="opacity:.8">${frappe.utils.escape_html(snap.reason)}</div>` : ""}
      </div>`;

    // Frappe v14/v15+ için güvenli bir sabit üst bant:
    frappe.msgprint({
      title: __("License Warning"),
      message: html,
      indicator: "orange",
      wide: 1,
      primary_action: undefined,
    });

    // Ek olarak üst kısımda küçük bir notice:
    if (frappe.ui && frappe.ui.toolbar && frappe.ui.toolbar.show_banner) {
      frappe.ui.toolbar.show_banner(
        __("License expired — grace until: {0}", [untilStr]),
        "orange"
      );
    }
  }

  async function forceLogout(reason) {
    try {
      await frappe.call("logout");
    } catch (e) {
      // no-op
    } finally {
      const q = reason ? `?reason=${encodeURIComponent(reason)}` : "";
      window.location.href = `/${q}`;
    }
  }

  function startGraceTimer(snap) {
    const until = isoToDate(snap.grace_until);
    if (!until) return;

    const check = async () => {
      const now = new Date();
      if (now >= until) {
        await forceLogout("license_expired");
      }
    };

    // Başlangıçta bir kez kontrol et, sonra dakikada bir kontrol et
    check();
    setInterval(check, 60 * 1000);
  }

  // Boot olduğunda çalıştır
  frappe.ready(() => {
    const snap = BOOT();
    if (!snap) return;

    const status = (snap.status || "").toUpperCase();
    if (status === "EXPIRED") {
      showExpiredBanner(snap);
      startGraceTimer(snap);
    }
  });
})();
