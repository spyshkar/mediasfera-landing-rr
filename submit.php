<?php
// ─── Config (из .env.php рядом со скриптом) ──────────────────────────────────
$cfg = __DIR__ . '/.env.php';
if (file_exists($cfg)) include $cfg;

$MAIL_USER    = getenv('MAIL_USER')        ?: (defined('MAIL_USER')        ? MAIL_USER        : '');
$MAIL_PASS    = getenv('MAIL_PASS')        ?: (defined('MAIL_PASS')        ? MAIL_PASS        : '');
$MAIL_TO      = getenv('MAIL_TO')          ?: (defined('MAIL_TO')          ? MAIL_TO          : '');
$TG_TOKEN     = getenv('TG_BOT_TOKEN')     ?: (defined('TG_BOT_TOKEN')     ? TG_BOT_TOKEN     : '');
$TG_CHAT      = getenv('TG_CHAT_ID')       ?: (defined('TG_CHAT_ID')       ? TG_CHAT_ID       : '');
$AMO_DOMAIN   = getenv('AMO_DOMAIN')       ?: (defined('AMO_DOMAIN')       ? AMO_DOMAIN       : '');
$AMO_TOKEN    = getenv('AMO_TOKEN')        ?: (defined('AMO_TOKEN')        ? AMO_TOKEN        : '');
$AMO_PIPELINE = getenv('AMO_PIPELINE_ID')  ?: (defined('AMO_PIPELINE_ID')  ? AMO_PIPELINE_ID  : '');
$AMO_STATUS   = getenv('AMO_STATUS_ID')    ?: (defined('AMO_STATUS_ID')    ? AMO_STATUS_ID    : '');
$SITE_ORIGIN  = getenv('SITE_ORIGIN')      ?: (defined('SITE_ORIGIN')      ? SITE_ORIGIN      : '');

// ─── CORS ─────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = array_filter(array_map('trim', explode(',', $SITE_ORIGIN)));
if ($allowed && in_array($origin, $allowed, true)) {
    header("Access-Control-Allow-Origin: {$origin}");
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { http_response_code(405); echo json_encode(['error' => 'Method not allowed']); exit; }

// ─── Rate limit (session) ─────────────────────────────────────────────────────
session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict']);
$ip  = trim($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$key = 'rl_' . md5($ip);
$now = time();
if (!isset($_SESSION[$key]) || $now > $_SESSION[$key]['reset']) {
    $_SESSION[$key] = ['count' => 0, 'reset' => $now + 600];
}
if ($_SESSION[$key]['count'] >= 5) {
    http_response_code(429); echo json_encode(['error' => 'Too many requests']); exit;
}
$_SESSION[$key]['count']++;

// ─── Parse & validate ─────────────────────────────────────────────────────────
$raw  = file_get_contents('php://input');
$body = json_decode($raw, true);
if (!$body) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit; }

$name         = trim((string)($body['name']         ?? ''));
$email        = trim((string)($body['email']        ?? ''));
$company      = trim((string)($body['company']      ?? ''));
$site         = trim((string)($body['site']         ?? ''));
$task         = trim((string)($body['task']         ?? ''));
$contactType  = trim((string)($body['contactType']  ?? ''));
$contactValue = trim((string)($body['contactValue'] ?? ''));
$consent      = (bool)($body['consent'] ?? false);
$raw_utms     = is_array($body['utms'] ?? null) ? $body['utms'] : [];
$utms         = array_slice(
    array_filter($raw_utms, fn($v) => is_string($v) && strlen($v) < 300, ARRAY_FILTER_USE_BOTH),
    0, 10, true
);

if (!$name || !$email || !$consent) {
    http_response_code(400); echo json_encode(['error' => 'Missing required fields']); exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400); echo json_encode(['error' => 'Invalid email']); exit;
}

$max = ['name' => 200, 'email' => 200, 'company' => 300, 'site' => 300, 'task' => 3000, 'contactValue' => 200];
foreach ($max as $field => $limit) {
    if (strlen($$field) > $limit) { http_response_code(400); echo json_encode(['error' => "Field {$field} too long"]); exit; }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function esc(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function tg_esc(string $s): string {
    return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $s);
}

function is_test_email(string $email): bool {
    $e = strtolower($email);
    foreach (['@test.', '@example.', '@yopmail.', '@mailinator.'] as $d) {
        if (str_contains($e, $d)) return true;
    }
    foreach (['+test', '.test@', 'test@test'] as $m) {
        if (str_contains($e, $m)) return true;
    }
    return false;
}

function curl_post(string $url, array $data, array $headers = []): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_HTTPHEADER     => array_merge(['Content-Type: application/json'], $headers),
    ]);
    $resp   = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['status' => $status, 'body' => $resp];
}

// ─── SMTP send (mail.ru SSL:465) ──────────────────────────────────────────────
function smtp_send(string $user, string $pass, string $to_list, string $subject, string $html): bool {
    $ctx  = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $sock = @stream_socket_client('ssl://smtp.mail.ru:465', $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$sock) return false;

    $r = fn() => fgets($sock, 512);
    $w = fn(string $s) => fwrite($sock, $s . "\r\n");

    $r();
    $w('EHLO localhost');
    while ($line = $r()) { if ($line[3] === ' ') break; }
    $w('AUTH LOGIN');   $r();
    $w(base64_encode($user));  $r();
    $w(base64_encode($pass));  $r();
    $w("MAIL FROM:<{$user}>"); $r();

    foreach (array_map('trim', explode(',', $to_list)) as $rcpt) {
        $w("RCPT TO:<{$rcpt}>"); $r();
    }

    $w('DATA'); $r();
    $subj_encoded = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $msg  = "Date: " . date('r') . "\r\n";
    $msg .= "From: =?UTF-8?B?" . base64_encode('Медиасфера') . "?= <{$user}>\r\n";
    $msg .= "To: {$to_list}\r\n";
    $msg .= "Subject: {$subj_encoded}\r\n";
    $msg .= "MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n";
    $msg .= $html . "\r\n.";
    $w($msg); $r();
    $w('QUIT');
    fclose($sock);
    return true;
}

// ─── Email ────────────────────────────────────────────────────────────────────
function send_email(array $d, string $user, string $pass, string $to): void {
    if (!$user || !$pass || !$to) return;

    $contact_str = $d['contactType'] ? esc(ucfirst($d['contactType'])) . ': ' . esc($d['contactValue'] ?: '—') : '—';

    $utm_str = '';
    if (!empty($d['utms'])) {
        $parts = [];
        foreach ($d['utms'] as $k => $v) $parts[] = esc($k) . '=' . esc($v);
        $utm_str = '<hr/><p><b>UTM:</b> ' . implode(', ', $parts) . '</p>';
    }

    $html = "
        <h2>Новая заявка — Рейтинг Рунета</h2>
        <p><b>Имя:</b> "      . esc($d['name'])                     . "</p>
        <p><b>Email:</b> "     . esc($d['email'])                    . "</p>
        <p><b>Связь:</b> "     . $contact_str                        . "</p>
        <p><b>Компания:</b> "  . esc($d['company'] ?: '—')           . "</p>
        <p><b>Сайт:</b> "      . esc($d['site']    ?: '—')           . "</p>
        <hr/>
        <p><b>Задача:</b></p>
        <p>" . nl2br(esc($d['task'] ?: '—'))                         . "</p>
        {$utm_str}
    ";

    $subject = 'Заявка с РР-лендинга от ' . preg_replace('/[\r\n]/', '', $d['name']);
    smtp_send($user, $pass, $to, $subject, $html);
}

// ─── Telegram ─────────────────────────────────────────────────────────────────
function send_telegram(array $d, string $token, string $chat_id): void {
    if (!$token || !$chat_id) return;

    $contact = $d['contactType'] ? ucfirst($d['contactType']) . ': ' . tg_esc($d['contactValue'] ?: '—') : '—';

    $utm_lines = [];
    if (!empty($d['utms'])) {
        $utm_lines[] = '';
        $utm_lines[] = 'Метки:';
        foreach ($d['utms'] as $k => $v) $utm_lines[] = tg_esc($k) . '=' . tg_esc($v);
    }

    $task_str = $d['task'] ? "\n\n<b>Задача:</b>\n" . tg_esc($d['task']) : '';

    $lines = array_merge([
        '🎯 <b>Новая заявка — Рейтинг Рунета</b>',
        '',
        'Имя: '      . tg_esc($d['name']),
        'Email: '    . tg_esc($d['email']),
        'Связь: '    . $contact,
        'Компания: ' . tg_esc($d['company'] ?: '—'),
        'Сайт: '     . tg_esc($d['site']    ?: '—'),
    ], $utm_lines);

    $text = implode("\n", $lines) . $task_str;

    curl_post(
        "https://api.telegram.org/bot{$token}/sendMessage",
        ['chat_id' => $chat_id, 'text' => $text, 'parse_mode' => 'HTML']
    );
}

// ─── AmoCRM ───────────────────────────────────────────────────────────────────
function send_to_amo(array $d, string $domain, string $token, string $pipeline, string $status): void {
    if (!$domain || !$token) return;
    if (is_test_email($d['email'])) return;

    $headers = ["Authorization: Bearer {$token}"];

    $contact_fields = [
        ['field_code' => 'EMAIL', 'values' => [['value' => $d['email'], 'enum_code' => 'WORK']]],
    ];
    // Если контакт — телефон, добавляем в контакт
    if ($d['contactType'] === 'phone' && $d['contactValue']) {
        $contact_fields[] = ['field_code' => 'PHONE', 'values' => [['value' => $d['contactValue'], 'enum_code' => 'MOB']]];
    }

    $lead_name = "РР — {$d['name']}";
    if ($d['company']) $lead_name .= " / {$d['company']}";

    $lead_data = [
        'name'     => $lead_name,
        'tags_to_add' => [['name' => 'Рейтинг Рунета 2026']],
        '_embedded' => ['contacts' => [[
            'name'                 => $d['name'],
            'custom_fields_values' => $contact_fields,
        ]]],
    ];

    // Добавляем pipeline/status если заданы
    if ($pipeline) $lead_data['pipeline_id'] = (int)$pipeline;
    if ($status)   $lead_data['status_id']   = (int)$status;

    $lead_res = curl_post("https://{$domain}/api/v4/leads/complex", [$lead_data], $headers);

    if ($lead_res['status'] < 200 || $lead_res['status'] >= 300) {
        error_log('[AMO Error] lead: ' . $lead_res['status'] . ' ' . $lead_res['body']);
        return;
    }

    $lead_json = json_decode($lead_res['body'], true);
    $lead_id   = $lead_json[0]['id'] ?? null;
    if (!$lead_id) { error_log('[AMO Error] no lead id: ' . $lead_res['body']); return; }

    // Примечание к лиду
    $note_parts = [
        '🎯 Заявка с лендинга Рейтинг Рунета',
        '',
        "Имя: {$d['name']}",
        "Email: {$d['email']}",
    ];
    if ($d['contactType'] && $d['contactValue']) {
        $note_parts[] = ucfirst($d['contactType']) . ': ' . $d['contactValue'];
    }
    if ($d['company']) $note_parts[] = "Компания: {$d['company']}";
    if ($d['site'])    $note_parts[] = "Сайт: {$d['site']}";
    if ($d['task'])  { $note_parts[] = ''; $note_parts[] = "Задача:"; $note_parts[] = $d['task']; }
    if (!empty($d['utms'])) {
        $note_parts[] = '';
        $note_parts[] = 'UTM:';
        foreach ($d['utms'] as $k => $v) $note_parts[] = '  ' . preg_replace('/[^\w_-]/', '', $k) . '=' . substr(strip_tags((string)$v), 0, 200);
    }

    curl_post(
        "https://{$domain}/api/v4/leads/{$lead_id}/notes",
        [['note_type' => 'common', 'params' => ['text' => implode("\n", $note_parts)]]],
        $headers
    );
}

// ─── Execute ──────────────────────────────────────────────────────────────────
$d = compact('name', 'email', 'company', 'site', 'task', 'contactType', 'contactValue', 'consent', 'utms');

send_email($d, $MAIL_USER, $MAIL_PASS, $MAIL_TO);
send_telegram($d, $TG_TOKEN, $TG_CHAT);
send_to_amo($d, $AMO_DOMAIN, $AMO_TOKEN, $AMO_PIPELINE, $AMO_STATUS);

echo json_encode(['ok' => true]);
