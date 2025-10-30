# FILE: brv_license_app/hooks.py
app_name = "brv_license_app"
app_title = "BRV License App"
app_publisher = "BRV Softare"
app_description = "License client"
app_email = "info@brvsoftware.com.tr"
app_license = "mit"

# Her istek başında lisans kısıtını uygla
auth_hooks = ["brv_license_app.overrides.enforce_request"]

# 6 saatte bir otomatik doğrulama - 48 saat grace period içinde 8 deneme şansı
scheduler_events = {
    "cron": {
        "0 */6 * * *": [
            "brv_license_app.brv_license_app.doctype.license_settings.license_settings.scheduled_auto_validate"
        ]
    }
}

# Desk'e global JS enjekte et
app_include_js = [
    "/assets/brv_license_app/js/license_guard.js",
    "/assets/brv_license_app/js/license_banner.js",
]

# Oturum açılışında istemciye lisans özetini gönder
boot_session = "brv_license_app.overrides.boot_session"

# İzin/allowlist — License Settings'in çalışabilmesi için gerekli standart endpointler
license_allowlist_paths = [
    "/login",
    "/api/method/login",
    "/api/method/logout",
    "/api/method/ping",
    "/assets/",
    "/app/license-settings",  # License Settings sayfası
    "/api/method/brv_license_app.api.license.healthz",

    # Form yükleme/kaydetme
    "/api/method/frappe.desk.form.load.getdoc",
    "/api/method/frappe.desk.form.save.savedocs",

    # Doc method çağrıları (ör. activate/validate/deactivate)
    "/api/method/run_doc_method",
    
    # License Settings API'leri
    "/api/method/brv_license_app.brv_license_app.doctype.license_settings.license_settings",
]