<?php
// Contact form handler for leine.info
//
// GET  -> issues a single-use spam challenge (a small arithmetic question)
// POST -> validates the submission and forwards it as an email
//
// Spam protection without third-party services or secrets:
//   - a hidden honeypot field that automated bots fill in
//   - a single-use challenge token stored server-side, so the form cannot be
//     submitted within a few seconds of loading and cannot be replayed
//   - a per-IP rate limit
//
// Challenges live in the system temp directory, never inside the web root.

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$RECIPIENT   = 'kontakt@leine.info';
$SENDER      = 'kontakt@leine.info';
$MIN_AGE     = 3;    // seconds: reject submissions that are too fast
$MAX_AGE     = 1800; // seconds: challenge validity
$RATE_MAX    = 5;    // submissions allowed per IP per window
$RATE_WINDOW = 600;  // rate-limit window in seconds

function store_dir()
{
    $dir = sys_get_temp_dir() . '/leine-contact';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir;
}

function out($code, $data)
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

function str_len($s)
{
    return function_exists('mb_strlen') ? mb_strlen($s) : strlen($s);
}

function client_ip()
{
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function issue_challenge()
{
    $a = random_int(2, 9);
    $b = random_int(2, 9);
    $token = bin2hex(random_bytes(16));
    $rec = array('a' => $a + $b, 't' => time());
    @file_put_contents(store_dir() . '/c_' . $token . '.json', json_encode($rec), LOCK_EX);
    return array('token' => $token, 'q' => $a . ' + ' . $b);
}

function take_challenge($token)
{
    if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
        return null;
    }
    $file = store_dir() . '/c_' . $token . '.json';
    if (!is_file($file)) {
        return null;
    }
    $rec = json_decode(file_get_contents($file), true);
    @unlink($file);
    return is_array($rec) ? $rec : null;
}

function rate_limited($ip)
{
    global $RATE_MAX, $RATE_WINDOW;
    $file = store_dir() . '/rl_' . substr(hash('sha256', $ip), 0, 32) . '.json';
    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return false;
    }
    flock($fp, LOCK_EX);
    $list = json_decode(stream_get_contents($fp), true);
    if (!is_array($list)) {
        $list = array();
    }
    $now = time();
    $kept = array();
    foreach ($list as $t) {
        if ($t > $now - $RATE_WINDOW) {
            $kept[] = $t;
        }
    }
    $limited = count($kept) >= $RATE_MAX;
    if (!$limited) {
        $kept[] = $now;
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($kept));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $limited;
}

function cleanup()
{
    global $MAX_AGE;
    if (random_int(1, 20) !== 1) {
        return;
    }
    foreach (glob(store_dir() . '/c_*.json') as $f) {
        if (filemtime($f) < time() - $MAX_AGE) {
            @unlink($f);
        }
    }
}

$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

if ($method === 'GET') {
    cleanup();
    out(200, issue_challenge());
}
if ($method !== 'POST') {
    out(405, array('error' => 'Method not allowed.'));
}

if (rate_limited(client_ip())) {
    out(429, array('error' => 'Too many messages. Please try again later.'));
}

$name    = isset($_POST['name']) ? trim($_POST['name']) : '';
$email   = isset($_POST['email']) ? trim($_POST['email']) : '';
$message = isset($_POST['message']) ? trim($_POST['message']) : '';
$answer  = isset($_POST['answer']) ? trim($_POST['answer']) : '';
$token   = isset($_POST['token']) ? trim($_POST['token']) : '';
$trap    = isset($_POST['website']) ? trim($_POST['website']) : '';

// Honeypot: real users never see or fill this field.
if ($trap !== '') {
    out(400, array('error' => 'Your message was flagged as spam.'));
}

$challenge = take_challenge($token);
if ($challenge === null) {
    out(400, array('error' => 'The spam check expired. Please try again.'));
}
$age = time() - (int) $challenge['t'];
if ($age < $MIN_AGE) {
    out(400, array('error' => 'That was too fast. Please try again.'));
}
if ($age > $MAX_AGE) {
    out(400, array('error' => 'The spam check expired. Please try again.'));
}
if (!preg_match('/^\d{1,3}$/', $answer) || (int) $answer !== (int) $challenge['a']) {
    out(400, array('error' => 'The spam check answer was wrong.'));
}

if ($name === '' || str_len($name) > 100) {
    out(400, array('error' => 'Please enter your name.'));
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || str_len($email) > 200) {
    out(400, array('error' => 'Please enter a valid email address.'));
}
if ($message === '' || str_len($message) > 5000) {
    out(400, array('error' => 'Please enter a message.'));
}

// Guard against header injection via the name or email fields.
$name  = str_replace(array("\r", "\n"), ' ', $name);
$email = str_replace(array("\r", "\n"), ' ', $email);

$subject = 'Website contact from ' . $name;
if (function_exists('mb_encode_mimeheader')) {
    $subject = mb_encode_mimeheader($subject, 'UTF-8', 'B', "\r\n");
} else {
    $subject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
}

$body = "Name: " . $name . "\n"
      . "Email: " . $email . "\n\n"
      . $message . "\n";

$headers = array(
    'From: ' . $SENDER,
    'Reply-To: ' . $email,
    'Content-Type: text/plain; charset=UTF-8',
    'X-Mailer: leine.info contact form',
);

$ok = @mail($RECIPIENT, $subject, $body, implode("\r\n", $headers), '-f' . $SENDER);
if (!$ok) {
    out(500, array('error' => 'The message could not be sent. Please try again later.'));
}
out(200, array('ok' => true));
