// Pay page: starts an M-Pesa payment through the payments function (KCB Buni) and waits
// for the result. Prices for fixed plans come from the function, never from this page.
(function ($) {
    var base = (window.QS_PAYMENTS_ENDPOINT || '').replace(/\/$/, '');
    var form = $('#payForm');
    var msg = $('#payMsg');
    var btn = form.find('.btn-tc-submit');
    var btnHtml = btn.html();

    function show(kind, text) {
        msg.html('<div class="alert alert-' + kind + ' mt-2">' + text + '</div>');
    }
    function esc(s) { return $('<div>').text(String(s)).html(); }

    if (!base) {
        form.find(':input').prop('disabled', true);
        show('info', 'Online payments are being set up. To pay now, please contact us at ' +
            '<a href="mailto:info@qsoftwares.org">info@qsoftwares.org</a> or +254 101 609 998.');
        return;
    }

    // Fixed-price plans, listed above the invoice option.
    var plans = {};
    $.getJSON(base + '/plans', function (list) {
        var select = form.find('[name="plan"]');
        $.each(list || [], function (_, p) {
            plans[p.id] = p;
            $('<option>').val(p.id).text(p.name + ' (KES ' + Number(p.amount).toLocaleString('en-KE') + ')')
                .insertBefore(select.find('option[value="invoice"]'));
        });
        if (list && list.length) select.val(list[0].id).trigger('change');
    });
    form.find('[name="plan"]').on('change', function () {
        form.find('.pay-invoice').toggle($(this).val() === 'invoice');
    });

    function poll(orderId, tries) {
        $.getJSON(base + '/status', { id: orderId }, function (r) {
            if (r.status === 'paid') {
                show('success', 'Payment received. Thank you! Your M-Pesa reference is <strong>' + esc(r.receipt) +
                    '</strong>, and we have emailed you a receipt.');
                form[0].reset();
                return done();
            }
            if (r.status === 'failed') {
                show('danger', 'The payment was not completed. You can try again.');
                return done();
            }
            if (r.status === 'review') {
                show('warning', 'We received a payment but need to check it. We will contact you shortly.');
                return done();
            }
            if (tries > 40) {
                show('warning', 'We have not heard back from M-Pesa yet. If you paid, your receipt will arrive by email.');
                return done();
            }
            setTimeout(function () { poll(orderId, tries + 1); }, 3000);
        }).fail(function () { setTimeout(function () { poll(orderId, tries + 1); }, 3000); });
    }
    function done() {
        btn.prop('disabled', false).html(btnHtml);
        qsGuardReset(form[0]);
    }

    form.on('submit', function (e) {
        e.preventDefault();
        var data = {};
        $.each(form.serializeArray(), function (_, f) { data[f.name] = $.trim(f.value); });
        if (!data.name || !data.email || !data.phone || (data.plan === 'invoice' && (!data.invoice || !data.amount))) {
            return show('warning', 'Please fill in all required fields (*).');
        }
        $.extend(data, qsGuardFields(form[0]));
        btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Sending M-Pesa prompt…');

        $.ajax({ url: base + '/pay', method: 'POST', contentType: 'application/json', data: JSON.stringify(data) })
            .done(function (r) {
                show('info', '<i class="fas fa-mobile-alt"></i> ' + esc(r.message) + ' This page updates once you have paid.');
                btn.html('<i class="fas fa-spinner fa-spin"></i> Waiting for your payment…');
                poll(r.orderId, 0);
            })
            .fail(function (xhr) {
                var r = xhr.responseJSON;
                show('danger', esc((r && r.error) || 'Something went wrong. Please try again.'));
                done();
            });
    });
})(jQuery);
