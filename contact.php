<?php

declare(strict_types=1);

// Contact form handler for leine.info  (requires PHP 8.1+)
//
// GET  -> issues a single-use proof-of-work challenge (hashcash style)
// POST -> validates the submission and forwards it as an email
//
// Spam protection without third-party services or secrets:
//   - a hidden honeypot field that automated bots fill in
//   - a single-use challenge kept in the PHP session: the browser must find
//     a nonce whose sha256(challenge . ':' . nonce) starts with POW_BITS
//     zero bits. One hash verifies it on the server, but a bot has to burn
//     about 2^POW_BITS hashes per submission and still cannot submit within
//     a few seconds of loading or replay a solved challenge
//   - a session-based rate limit
//
// All state lives in the PHP session; nothing is written to disk by this script.

const RECIPIENT   = 'contact@leine.info';
const SENDER      = 'contact@leine.info';
const MIN_AGE     = 3;    // seconds: reject submissions that are too fast
const MAX_AGE     = 1800; // seconds: challenge validity
const RATE_MAX    = 5;    // submissions allowed per session per window
const RATE_WINDOW = 600;  // rate-limit window in seconds
const POW_BITS    = 18;   // leading zero bits required in sha256(challenge . ':' . nonce)

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

session_start([
    'name'             => 'leine_cf',
    'cookie_lifetime'  => 0,
    'cookie_path'      => '/',
    'cookie_httponly'  => true,
    'cookie_samesite'  => 'Lax',
    'cookie_secure'    => !empty($_SERVER['HTTPS']),
    'use_strict_mode'  => true,
    'use_only_cookies' => true,
    'gc_maxlifetime'   => MAX_AGE,
]);

function out(int $code, array $data): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_THROW_ON_ERROR);
    exit;
}

function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? trim($value) : '';
}

function str_len(string $s): int
{
    return function_exists('mb_strlen') ? mb_strlen($s) : strlen($s);
}

function rate_limited(): bool
{
    $now = time();
    $hits = array_values(array_filter(
        is_array($_SESSION['hits'] ?? null) ? $_SESSION['hits'] : [],
        static fn (mixed $t): bool => is_int($t) && $t > $now - RATE_WINDOW,
    ));
    if (count($hits) >= RATE_MAX) {
        $_SESSION['hits'] = $hits;
        return true;
    }
    $hits[] = $now;
    $_SESSION['hits'] = $hits;
    return false;
}

function encode_subject(string $subject): string
{
    return function_exists('mb_encode_mimeheader')
        ? mb_encode_mimeheader($subject, 'UTF-8', 'B', "\r\n")
        : '=?UTF-8?B?' . base64_encode($subject) . '?=';
}

function issue_challenge(): never
{
    $challenge = bin2hex(random_bytes(16));
    $_SESSION['challenge'] = ['c' => $challenge, 'bits' => POW_BITS, 't' => time()];
    out(200, ['challenge' => $challenge, 'difficulty' => POW_BITS]);
}

function handle_post(): never
{
    if (rate_limited()) {
        out(429, ['error' => 'Too many messages. Please try again later.']);
    }

    $name    = post_string('name');
    $email   = post_string('email');
    $message = post_string('message');
    $nonce   = post_string('nonce');
    $trap    = post_string('website');

    // Honeypot: real users never see or fill this field.
    if ($trap !== '') {
        out(400, ['error' => 'Your message was flagged as spam.']);
    }

    $challenge = is_array($_SESSION['challenge'] ?? null) ? $_SESSION['challenge'] : null;
    unset($_SESSION['challenge']);
    if ($challenge === null) {
        out(400, ['error' => 'The spam check expired. Please try again.']);
    }

    $age = time() - (int) ($challenge['t'] ?? 0);
    if ($age < MIN_AGE) {
        out(400, ['error' => 'That was too fast. Please try again.']);
    }
    if ($age > MAX_AGE) {
        out(400, ['error' => 'The spam check expired. Please try again.']);
    }
    $bits = (int) ($challenge['bits'] ?? 0);
    $c    = is_string($challenge['c'] ?? null) ? $challenge['c'] : '';
    if ($bits < 1 || $bits > 32 || $c === '') {
        out(400, ['error' => 'The spam check expired. Please try again.']);
    }
    if (!preg_match('/^\d{1,15}$/', $nonce)
        || (int) hexdec(substr(hash('sha256', $c . ':' . $nonce), 0, 8)) >= 2 ** (32 - $bits)
    ) {
        out(400, ['error' => 'The spam check could not be verified. Please try again.']);
    }

    if ($name === '' || str_len($name) > 100) {
        out(400, ['error' => 'Please enter your name.']);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || str_len($email) > 200) {
        out(400, ['error' => 'Please enter a valid email address.']);
    }
    if ($message === '' || str_len($message) > 5000) {
        out(400, ['error' => 'Please enter a message.']);
    }

    // Guard against header injection via the name or email fields.
    $name  = str_replace(["\r", "\n"], ' ', $name);
    $email = str_replace(["\r", "\n"], ' ', $email);

    $subject = encode_subject('Website contact from ' . $name);
    $body    = "Name: $name\nEmail: $email\n\n$message\n";
    $headers = implode("\r\n", [
        'From: ' . SENDER,
        'Reply-To: ' . $email,
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: leine.info contact form',
    ]);

    if (!mail(RECIPIENT, $subject, $body, $headers, '-f' . SENDER)) {
        out(500, ['error' => 'The message could not be sent. Please try again later.']);
    }
    out(200, ['ok' => true]);
}

match ($_SERVER['REQUEST_METHOD'] ?? 'GET') {
    'GET'   => issue_challenge(),
    'POST'  => handle_post(),
    default => out(405, ['error' => 'Method not allowed.']),
};
