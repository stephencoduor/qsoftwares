<?php
/**
 * QSOFTWARES — Secure Contact / Support Form Handler
 * --------------------------------------------------
 * - Input sanitisation & validation
 * - Rate limiting (per IP, file-based — no DB needed)
 * - Honeypot spam trap
 * - Origin / Referer check
 * - HTML-escaped output to prevent XSS in email body
 * - Proper PHPMailer require paths
 */

// ── CONFIG ──────────────────────────────────────────
define('RECIPIENT_EMAIL', 'info@qsoftwares.org');
define('RECIPIENT_NAME',  'QSOFTWARES Support');
define('RATE_LIMIT_MAX',  5);          // max submissions
define('RATE_LIMIT_WINDOW', 3600);     // per this many seconds (1 hour)
// SMTP login and server paths live outside the web root (see deploy/gcp/set-smtp.sh).
define('SMTP_CONFIG_FILE', '/etc/qsoftwares/smtp.ini');
$smtp = is_readable(SMTP_CONFIG_FILE) ? (parse_ini_file(SMTP_CONFIG_FILE, false, INI_SCANNER_RAW) ?: []) : [];
define('RATE_LIMIT_DIR',  $smtp['rate_limit_dir'] ?? (__DIR__ . '/../tmp/rate_limits'));

// ── HEADERS ─────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ── HELPER: JSON response & exit ────────────────────
function respond(string $status, string $msg, int $http = 200): void {
    http_response_code($http);
    echo json_encode([$status, $msg]);
    exit;
}

// ── ONLY accept POST ────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond('error', 'Invalid request method.', 405);
}

// ── ORIGIN / REFERER check ──────────────────────────
$allowed_hosts = ['qsoftwares.org', 'www.qsoftwares.org', 'localhost', '127.0.0.1'];
$referer  = $_SERVER['HTTP_REFERER'] ?? '';
$ref_host = parse_url($referer, PHP_URL_HOST) ?: '';
if ($referer && !in_array($ref_host, $allowed_hosts, true)) {
    respond('error', 'Unauthorized origin.', 403);
}

// ── HONEYPOT — hidden field bots will fill ──────────
if (!empty($_POST['website_url'])) {
    // Silently reject — looks like success to the bot
    respond('success', 'Thank you. Your message has been sent.');
}

// ── RATE LIMITING (file-based, per IP) ──────────────
function check_rate_limit(): bool {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $hash = md5($ip);
    $dir  = RATE_LIMIT_DIR;

    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
        // Protect directory with .htaccess
        @file_put_contents($dir . '/.htaccess', "Deny from all\n");
    }

    $file = $dir . '/' . $hash . '.json';

    $data = [];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        $data = $raw ? json_decode($raw, true) : [];
        if (!is_array($data)) $data = [];
    }

    // Purge timestamps outside the window
    $now  = time();
    $data = array_values(array_filter($data, function ($ts) use ($now) {
        return ($now - $ts) < RATE_LIMIT_WINDOW;
    }));

    if (count($data) >= RATE_LIMIT_MAX) {
        return false; // limit exceeded
    }

    $data[] = $now;
    @file_put_contents($file, json_encode($data), LOCK_EX);
    return true;
}

if (!check_rate_limit()) {
    respond('error', 'Too many requests. Please try again later.', 429);
}

// ── VALIDATE & SANITISE inputs ──────────────────────
$name    = trim(strip_tags($_POST['contactName']    ?? ''));
$email   = trim(strip_tags($_POST['contactEmail']   ?? ''));
$message = trim(strip_tags($_POST['contactMessage'] ?? ''));

if ($name === '' || $email === '' || $message === '') {
    respond('error', 'Please fill in all required fields.', 422);
}

// Strict name validation — letters, spaces, hyphens, apostrophes only
if (!preg_match('/^[\p{L}\s\'\-\.]{2,100}$/u', $name)) {
    respond('error', 'Please enter a valid name.', 422);
}

// Email validation
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    respond('error', 'Please enter a valid email address.', 422);
}

// Message length cap (prevent abuse)
if (mb_strlen($message) > 5000) {
    respond('error', 'Message is too long (max 5 000 characters).', 422);
}

// ── BUILD HTML email body (escaped) ─────────────────
$esc = function (string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
};

$body  = '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;margin:0 auto;">';
$body .= '<div style="background:#015055;padding:20px 24px;border-radius:8px 8px 0 0;">';
$body .= '<h2 style="color:#fff;margin:0;">New Support Request</h2></div>';
$body .= '<div style="background:#f9f9f9;padding:24px;border:1px solid #e0e0e0;border-radius:0 0 8px 8px;">';
$body .= '<table style="width:100%;border-collapse:collapse;">';
$body .= '<tr><td style="padding:8px 12px;font-weight:bold;color:#015055;width:160px;">Name</td>';
$body .= '<td style="padding:8px 12px;">' . $esc($name) . '</td></tr>';
$body .= '<tr style="background:#fff;"><td style="padding:8px 12px;font-weight:bold;color:#015055;">Email</td>';
$body .= '<td style="padding:8px 12px;"><a href="mailto:' . $esc($email) . '">' . $esc($email) . '</a></td></tr>';
$body .= '</table>';
$body .= '<hr style="border:none;border-top:1px solid #e0e0e0;margin:16px 0;">';
$body .= '<div style="white-space:pre-wrap;line-height:1.6;">' . nl2br($esc($message)) . '</div>';
$body .= '</div></div>';

// Plain-text fallback
$plain  = "New Support Request\n";
$plain .= "===================\n\n";
$plain .= "Name:  {$name}\n";
$plain .= "Email: {$email}\n\n";
$plain .= "Message:\n{$message}\n";

// ── DETERMINE subject line from message content ─────
$subject = 'New Contact Form Submission';
if (stripos($message, '[KoboToolbox Support Request]') !== false) {
    $subject = 'KoboToolbox Support Request from ' . $name;
} elseif (stripos($message, '[Training Enquiry]') !== false) {
    $subject = 'Training Enquiry from ' . $name;
}

// ── SEND via PHPMailer ──────────────────────────────
require __DIR__ . '/Exception.php';
require __DIR__ . '/PHPMailer.php';
require __DIR__ . '/SMTP.php';

use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

$mail = new PHPMailer(true);

try {
    // SMTP when /etc/qsoftwares/smtp.ini has a login, otherwise PHP mail().
    // Zoho only accepts a From address that matches the mailbox you log in with.
    $from = 'noreply@qsoftwares.org';
    if (!empty($smtp['username']) && !empty($smtp['password'])) {
        $mail->isSMTP();
        $mail->Host       = $smtp['host'] ?? 'smtp.zoho.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = $smtp['username'];
        $mail->Password   = $smtp['password'];
        $mail->SMTPSecure = ($smtp['secure'] ?? 'ssl') === 'tls' ? 'tls' : 'ssl';
        $mail->Port       = (int) ($smtp['port'] ?? 465);
        $from = $smtp['from'] ?? $smtp['username'];
    }

    // Sender & recipient
    $mail->setFrom($from, $smtp['from_name'] ?? 'QSOFTWARES Website');
    $mail->addReplyTo($email, $name);
    $mail->addAddress(RECIPIENT_EMAIL, RECIPIENT_NAME);

    // Content
    $mail->isHTML(true);
    $mail->CharSet = 'UTF-8';
    $mail->Subject = $subject;
    $mail->Body    = $body;
    $mail->AltBody = $plain;

    $mail->send();

    respond('success', 'Thank you. Your message has been sent.');

} catch (Exception $e) {
    // Log error server-side (never expose details to client)
    error_log('PHPMailer error: ' . $mail->ErrorInfo);
    respond('error', 'Message could not be sent. Please try again later.', 500);
}
