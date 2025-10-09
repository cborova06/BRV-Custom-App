
(async function () {
  try {
    const r = await frappe.call({ method: 'brv_license_app.api.license.healthz' });
    const msg = r && r.message ? r.message : {};
    // Healthz, site/app/ok döndürüyordu; artık lisans temel alanlarını da isteyelim
    // (license_settings.health_check ile genişletilebilir)
    // Beklenen: {status, grace_until, reason}
    const status = (msg.status || '').toUpperCase();
    const reason = msg.reason || '';
    const grace = msg.grace_until || null;

    // Renk/öncelik belirleme
    let color = 'green';
    let title = 'Lisans Durumu: OK';

    if (status === 'DEACTIVATED') {
      color = 'orange';
      title = 'Lisans Pasif (Sınırlı Erişim)';
    } else if (status === 'EXPIRED') {
      color = 'orange';
      title = 'Lisans Süresi Doldu (Esneklik Süresi)';
    }

    if (['REVOKED','LOCK_HARD'].includes(status)) {
      color = 'red';
      title = 'Lisans Engelli';
    }

    // Sadece problem durumlarında banner gösterelim
    if (color !== 'green') {
      const lines = [];
      if (reason) lines.push(reason);
      if (grace && status === 'EXPIRED') lines.push(`Esneklik bitişi: ${grace}`);

      frappe.ui.toolbar.clear_breadcrumbs && frappe.ui.toolbar.clear_breadcrumbs();
      frappe.ui.banner && frappe.ui.banner.show({
        title: __(title),
        subtitle: lines.join(' — '),
        color: color,
        actions: [
          {
            label: __('Lisans Ayarlarına Git'),
            action: () => {
              frappe.set_route('Form', 'License Settings');
            }
          }
        ]
      });
    }
  } catch (e) {
    // Sessiz geç
    // console.warn('license_banner error', e);
  }
})();