// Bot checks for the forms that post to QS_CONTACT_ENDPOINT (marked data-qs-guard).
// - Reports how long the page was open; the function ignores sends under 3 seconds.
// - Adds a Cloudflare Turnstile widget when QS_TURNSTILE_SITEKEY is set in contact-endpoint.js.
(function ($) {
    var loadedAt = Date.now();
    var forms = $('form[data-qs-guard]');

    if (window.QS_TURNSTILE_SITEKEY && forms.length) {
        window.qsTurnstileReady = function () {
            forms.each(function () {
                var box = $('<div class="mb-3"></div>').insertBefore($(this).find('[type="submit"]'));
                $(this).data('turnstileId', turnstile.render(box[0], { sitekey: window.QS_TURNSTILE_SITEKEY }));
            });
        };
        var s = document.createElement('script');
        s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=qsTurnstileReady';
        s.async = true;
        document.head.appendChild(s);
    }

    // Extra fields to send with a guarded form.
    window.qsGuardFields = function (form) {
        var fields = { form_elapsed_ms: String(Date.now() - loadedAt) };
        var id = $(form).data('turnstileId');
        if (window.turnstile && id !== undefined) fields['cf-turnstile-response'] = turnstile.getResponse(id) || '';
        return fields;
    };

    // Turnstile tokens work once, so get a fresh one after every send.
    window.qsGuardReset = function (form) {
        var id = $(form).data('turnstileId');
        if (window.turnstile && id !== undefined) turnstile.reset(id);
    };

    // The function's own reason (rate limit, missing field, verification) when it gave one.
    window.qsErrorText = function (xhr) {
        var r = xhr && xhr.responseJSON;
        return (r && r[0] === 'error' && r[1]) ? $('<div>').text(r[1]).html() : '';
    };
})(jQuery);
