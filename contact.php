<?php
// Contact form handler for leine.info
//
// GET  -> issues a single-use spam challenge (a small arithmetic question)
// POST -> validates the submission and forwards it as an email
//
// Spam protection without third-party services or secrets:
//   - a hidden honeypot field that automated bots fill in
//   - a single-use challenge kept in the PHP session, so the form cannot be
//     submitted within a few seconds of loading and cannot be replayed
//   - a session-based rate limit
//
// All state lives in the PHP session; nothing is written to disk by this script.

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$RECIPIENT   = 'contact@leine.info';
$SENDER      = 'contact@leine.info';
$MIN_AGE     = 3;    // seconds: reject submissions that are too fast
$MAX_AGE     = 1800; // seconds: challenge validity
$RATE_MAX    = 5;    // submissions allowed per session per window
$RATE_WINDOW = 600;  // rate-limit window in seconds

session_set_cookie_params(array(
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']),
));
ini_set('session.gc_maxlifetime', (string) $MAX_AGE);
session_name('leine_cf');
session_start();

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

function rate_limited()
{
    global $RATE_MAX, $RATE_WINDOW;
    $now = time();
    $hits = isset($_SESSION['hits']) && is_array($_SESSION['hits']) ? $_SESSION['hits'] : array();
    $kept = array();
    foreach ($hits as $t) {
        if ($t > $now - $RATE_WINDOW) {
            $kept[] = $t;
        }
    }
    $limited = count($kept) >= $RATE_MAX;
    if (!$limited) {
        $kept[] = $now;
    }
    $_SESSION['hits'] = $kept;
    return $limited;
}

$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

if ($method === 'GET') {
    $a = random_int(2, 9);
    $b = random_int(2, 9);
    $_SESSION['challenge'] = array('sum' => $a + $b, 't' => time());
    out(200, array('q' => $a . ' + ' . $b));
}
if ($method !== 'POST') {
    out(405, array('error' => 'Method not allowed.'));
}

if (rate_limited()) {
    out(429, array('error' => 'Too many messages. Please try again later.'));
}

$name    = isset($_POST['name']) ? trim($_POST['name']) : '';
$email   = isset($_POST['email']) ? trim($_POST['email']) : '';
$message = isset($_POST['message']) ? trim($_POST['message']) : '';
$answer  = isset($_POST['answer']) ? trim($_POST['answer']) : '';
$trap    = isset($_POST['website']) ? trim($_POST['website']) : '';

// Honeypot: real users never see or fill this field.
if ($trap !== '') {
    out(400, array('error' => 'Your message was flagged as spam.'));
}

$challenge = isset($_SESSION['challenge']) && is_array($_SESSION['challenge']) ? $_SESSION['challenge'] : null;
unset($_SESSION['challenge']);
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
if (!preg_match('/^\d{1,3}$/', $answer) || (int) $answer !== (int) $challenge['sum']) {
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
