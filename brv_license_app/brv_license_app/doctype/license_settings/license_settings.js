// BRV License App – License Settings Client UI (revised)
// Buttons to drive LMFWC lifecycle via whitelisted server methods.
// Fixes: proper token prompt handling (await), trim, and stricter UI flow (no optimistic banners).

frappe.ui.form.on('License Settings', {
  refresh: function (frm) {
    render_status_banner(frm);

    const hasKey = !!(frm.doc.license_key && String(frm.doc.license_key).trim());

    // --- Activate ---
    frm.add_custom_button(__('Activate'), async () => {
      if (!ensure_key(frm)) return;
      await call_and_refresh(frm, 'activate_license', { license_key: frm.doc.license_key });
    }, __('License'));

    // --- Reactivate (with Token) ---
    frm.add_custom_button(__('Reactivate (with Token)'), async () => {
      if (!ensure_key(frm)) return;
      const token = await get_token_from_user(frm.doc.activation_token);
      if (!token) return;
      await call_and_refresh(frm, 'reactivate_license', { license_key: frm.doc.license_key, token });
    }, __('License'));

    // --- Validate ---
    frm.add_custom_button(__('Validate'), async () => {
      if (!ensure_key(frm)) return;
      await call_and_refresh(frm, 'validate_license', { license_key: frm.doc.license_key });
    }, __('License'));

    // --- Deactivate (This Device Token) ---
    frm.add_custom_button(__('Deactivate (This Device Token)'), async () => {
      if (!ensure_key(frm)) return;
      const token = await get_token_from_user(frm.doc.activation_token);
      if (!token) return;
      await call_and_refresh(frm, 'deactivate_license', { license_key: frm.doc.license_key, token });
    }, __('License'));

    if (!hasKey) {
      frm.dashboard.clear_headline();
      frm.dashboard.set_headline(__('Please enter and save a License Key to enable actions.'));
    }
  },

  license_key: function (frm) {
    render_status_banner(frm);
  }
});

// -------------------------------
// Helpers
// -------------------------------
async function call_and_refresh(frm, method, args) {
  frappe.dom.freeze(__('Processing...'));
  try {
    const r = await frappe.call({
      method: `brv_license_app.brv_license_app.doctype.license_settings.license_settings.${method}`,
      args: args || {},
      freeze: false,
    });

    // Show a compact toast with remaining activations if provided
    const data = (r && r.message) || {};
    const remain = (data.remainingActivations ?? data.remaining ?? undefined);
    if (remain !== undefined) {
      frappe.show_alert({ message: __('Done. Remaining activations: {0}', [remain]), indicator: 'green' });
    } else {
      frappe.show_alert({ message: __('Operation completed.'), indicator: 'green' });
    }
  } catch (e) {
    const msg = (e && e.message) ? e.message : (e && e.exc ? e.exc : __('Operation failed'));
    frappe.msgprint({ title: __('License Operation Failed'), message: frappe.utils.escape_html(String(msg)), indicator: 'red' });
  } finally {
    frappe.dom.unfreeze();
    await frm.reload_doc();
    render_status_banner(frm);
  }
}

function ensure_key(frm) {
  if (!frm.doc.license_key || !String(frm.doc.license_key).trim()) {
    frappe.msgprint({ message: __('Please enter a License Key and save the document first.'), indicator: 'orange' });
    return false;
  }
  return true;
}

async function get_token_from_user(default_token) {
  const t = (default_token || '').trim();
  if (t) return t;

  // Geriye dönük uyumlu wrapper: callback imzasını Promise'a çevir
  const values = await new Promise((resolve) => {
    frappe.prompt(
      [
        {
          fieldname: 'token',
          label: __('Activation Token'),
          fieldtype: 'Data',
          reqd: 1,
          description: __('Enter the activation token for this device.'),
        },
      ],
      // callback -> values
      (vals) => resolve(vals || {}),
      __('Provide Token'),
      __('Submit')
    );
  });

  if (!values || !values.token) return '';
  return String(values.token).trim();
}


async function confirm_action(message) {
  return new Promise((resolve) => {
    frappe.confirm(message, () => resolve(true), () => resolve(false));
  });
}

function render_status_banner(frm) {
  const status = frm.doc.status || 'UNCONFIGURED';
  const msg = frm.doc.reason || '';
  const remain = (frm.doc.remaining === undefined || frm.doc.remaining === null) ? '?' : frm.doc.remaining;
  const cls = (
    status === 'VALIDATED' ? 'green' :
    status === 'ACTIVE' ? 'blue' :
    status === 'GRACE_SOFT' ? 'orange' :
    status === 'LOCK_HARD' ? 'red' :
    status === 'DEACTIVATED' ? 'gray' : 'gray'
  );

  const html = `
    <div class="indicator ${cls}">
      <b>Status:</b> ${frappe.utils.escape_html(status)}&nbsp;&nbsp;
      <b>Remaining:</b> ${frappe.utils.escape_html(String(remain))}&nbsp;&nbsp;
      <span>${frappe.utils.escape_html(msg)}</span>
    </div>`;

  if (frm.fields_dict && frm.fields_dict.status_banner && frm.fields_dict.status_banner.$wrapper) {
    frm.fields_dict.status_banner.$wrapper.html(html);
  }
}