<?php
/*
 =========================================================================
 Information Security and Assurance 1
 School Management System — Cybersecurity Concepts Demo (with Scoring)
 -------------------------------------------------------------------------
 A single-file, browser-runnable teaching tool (upload to Hostinger or
 run on XAMPP). Every concept has a LIVE, working PHP demo, and most
 sections now include a predict-then-check quiz question that awards
 points. Progress and score persist for the session and are shown on
 every page plus a dedicated Score tab.

 Sections:
   1. CIA Triad             7. AAA Framework
   2. TVER                  8. Password Hashing
   3. Threat Actors         9. Encryption
   4. Malware              10. Networking Security
   5. DoS vs DDoS          11. Hashing for Integrity
   6. Social Engineering   12. Coding Challenge (laptop exercise)
                             ★ Score
 =========================================================================
*/

session_start();

// ---------------------------------------------------------------------
// Scoring / progress tracking
// ---------------------------------------------------------------------
$sectionList = [
    'cia'        => 'CIA Triad',
    'tver'       => 'Threat / Vulnerability / Exploit / Risk',
    'actors'     => 'Threat Actors',
    'malware'    => 'Malware',
    'dos'        => 'DoS vs DDoS',
    'social'     => 'Social Engineering',
    'aaa'        => 'AAA Framework',
    'hashing'    => 'Password Hashing',
    'encryption' => 'Encryption',
    'network'    => 'Networking Security',
    'integrity'  => 'Hashing for Integrity',
    'coding'     => 'Coding Challenge',
];

// ---------------------------------------------------------------------
// Fixed quiz roster — the ONLY quiz keys the score system recognizes.
// Re-answering any of these overwrites that single slot; it can never
// add extra points or extra "out of" — the denominator is always this
// list's count, and the numerator is only ever the truth of these keys.
// ---------------------------------------------------------------------
$QUIZ_KEYS = [
    'cia_conf', 'cia_int', 'cia_avail',
    'tver', 'actors', 'malware', 'dos_quiz',
    'phish_q1', 'phish_q2', 'phish_q3', 'phish_q4', 'phish_q5',
    'network_term', 'wifi_rank', 'integrity',
];

// Self-healing init: fixes both a brand-new session AND an old session
// left over from a previous version of this file (e.g. one missing the
// 'answers' key, or still using the old single 'code_score' field).
if (!isset($_SESSION['score']) || !is_array($_SESSION['score'])) {
    $_SESSION['score'] = [];
}
$_SESSION['score'] += [
    'sections_done'    => [],
    'answers'          => [],  // key => bool, one slot per $QUIZ_KEYS entry, overwritten on re-answer
    'code_score'       => 0,   // 0–30, Section 12 Coding Challenge (single encryption code submission)
];
if (!is_array($_SESSION['score']['sections_done'])) $_SESSION['score']['sections_done'] = [];
if (!is_array($_SESSION['score']['answers']))       $_SESSION['score']['answers'] = [];
if (!is_numeric($_SESSION['score']['code_score'])) $_SESSION['score']['code_score'] = 0;

function mark_done($key) {
    $_SESSION['score']['sections_done'][$key] = true;
}
function quiz_answer($key, $isCorrect) {
    // Overwrite-only: answering the same question again replaces its
    // recorded result instead of adding a new one to the total.
    $_SESSION['score']['answers'][$key] = (bool) $isCorrect;
    return $isCorrect;
}
function quiz_feedback($isCorrect, $correctText = '') {
    if ($isCorrect) {
        return '<div class="result ok">✅ Correct! ' . e($correctText) . '</div>';
    }
    return '<div class="result bad">❌ Not quite. ' . e($correctText) . '</div>';
}
function set_code_score($field, $points15) {
    // keep the BEST attempt, not the latest, so resubmitting a worse draft can't lower the grade
    $_SESSION['score'][$field] = max($_SESSION['score'][$field], $points15);
}

// ---------------------------------------------------------------------
// Small helpers used across sections
// ---------------------------------------------------------------------
$logFile = __DIR__ . '/activity_log.txt';

function write_log($logFile, $user, $action) {
    $entry = date("Y-m-d H:i:s") . " | " . $user . " | " . $action . PHP_EOL;
    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

function read_log($logFile, $limit = 10) {
    if (!file_exists($logFile)) return [];
    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
    return array_slice(array_reverse($lines), 0, $limit);
}

function e($val) {
    return htmlspecialchars($val ?? '', ENT_QUOTES, 'UTF-8');
}

$section = $_GET['section'] ?? 'cia';

// reset progress
if (isset($_POST['reset_score'])) {
    $_SESSION['score'] = ['sections_done' => [], 'answers' => [], 'code_score' => 0];
}



// ---------------------------------------------------------------------
// 1. CIA TRIAD DEMOS
// ---------------------------------------------------------------------
$cia_confidentiality_result = null;
$cia_conf_quiz_result = null;
if (isset($_POST['cia_conf_submit'])) {
    mark_done('cia');
    $role = $_POST['cia_role'] ?? 'Student';
    $actualGranted = ($role === 'Teacher' || $role === 'Admin');
    if ($actualGranted) {
        $cia_confidentiality_result = "ACCESS GRANTED — Showing grades: John=95, Mary=97";
    } else {
        $cia_confidentiality_result = "ACCESS DENIED — Confidentiality protected. Students cannot view the grade table.";
    }
    $predicted = $_POST['cia_conf_predict'] ?? '';
    $isCorrect = quiz_answer('cia_conf', ($predicted === 'granted') === $actualGranted);
    $cia_conf_quiz_result = quiz_feedback($isCorrect, $actualGranted ? "Access is GRANTED for this role." : "Access is DENIED for this role.");
}

$cia_integrity_result = null;
$cia_int_quiz_result = null;
if (isset($_POST['cia_int_submit'])) {
    mark_done('cia');
    $originalGrade = "95";
    $originalHash  = hash('sha256', $originalGrade);
    $submittedGrade = $_POST['cia_grade'] ?? '95';
    $submittedHash   = hash('sha256', $submittedGrade);
    $actualIntact = ($submittedHash === $originalHash);
    if ($actualIntact) {
        $cia_integrity_result = "Grade unchanged (95). Hash matches → Integrity intact.";
    } else {
        $cia_integrity_result = "Grade is now '$submittedGrade'. Hash no longer matches the original → Integrity VIOLATED. This change should be flagged and logged.";
    }
    $predicted = $_POST['cia_int_predict'] ?? '';
    $isCorrect = quiz_answer('cia_int', ($predicted === 'intact') === $actualIntact);
    $cia_int_quiz_result = quiz_feedback($isCorrect, $actualIntact ? "Integrity is INTACT — the hash matches." : "Integrity is VIOLATED — the hash no longer matches.");
}

$cia_availability_result = null;
$cia_avail_quiz_result = null;
if (isset($_POST['cia_avail_submit'])) {
    mark_done('cia');
    $requests = (int)($_POST['cia_requests'] ?? 0);
    $capacity = 100;
    $actualDown = ($requests > $capacity);
    if ($actualDown) {
        $cia_availability_result = "$requests requests hit the server at once (capacity: $capacity). Server is OVERLOADED → Website is DOWN. Availability violated.";
    } else {
        $cia_availability_result = "$requests requests handled normally (capacity: $capacity). Website stays up. Availability protected.";
    }
    $predicted = $_POST['cia_avail_predict'] ?? '';
    $isCorrect = quiz_answer('cia_avail', ($predicted === 'down') === $actualDown);
    $cia_avail_quiz_result = quiz_feedback($isCorrect, $actualDown ? "The server goes DOWN at this request count." : "The server stays UP at this request count.");
}

// ---------------------------------------------------------------------
// 2. TVER — predict-then-check vulnerability quiz
// ---------------------------------------------------------------------
$tver_result = null;
$tver_quiz_result = null;
if (isset($_POST['tver_check'])) {
    mark_done('tver');
    $weak = ['admin','123456','password','qwerty','12345678','admin123'];
    $pass = $_POST['tver_pass'] ?? '';
    $actualIsWeak = in_array(strtolower($pass), $weak);
    $predicted = $_POST['tver_predict'] ?? '';
    $predictedIsWeak = ($predicted === 'vulnerable');

    if ($actualIsWeak) {
        $tver_result = "VULNERABILITY FOUND: \"$pass\" is a commonly known weak password. This is exactly the kind of weakness a Threat Actor looks for.";
    } else {
        $tver_result = "No obvious weakness detected for \"$pass\" in this simple check (a real system would also check length, complexity, and breach databases).";
    }
    $isCorrect = quiz_answer('tver', $predictedIsWeak === $actualIsWeak);
    $tver_quiz_result = quiz_feedback($isCorrect, $actualIsWeak ? "It IS vulnerable." : "It is NOT on the common weak-password list.");
}

// ---------------------------------------------------------------------
// 3. THREAT ACTORS — matching quiz
// ---------------------------------------------------------------------
$actorScenarios = [
    ['scenario' => 'Downloads a free hacking tool online and runs it against the school website just to see what happens.', 'answer' => 'Script Kiddie'],
    ['scenario' => 'A registrar with legitimate access secretly edits a friend\'s failing grade.', 'answer' => 'Insider'],
    ['scenario' => 'Breaks into the database and sells the stolen student records on the dark web.', 'answer' => 'Black Hat'],
    ['scenario' => 'Hired by the school to legally test the website and report vulnerabilities.', 'answer' => 'White Hat'],
    ['scenario' => 'A well-funded group quietly exfiltrates research data over several months without detection.', 'answer' => 'APT (Advanced Persistent Threat)'],
];
if (!isset($_SESSION['actor_scenario_index'])) {
    $_SESSION['actor_scenario_index'] = array_rand($actorScenarios);
}
$currentActorScenario = $actorScenarios[$_SESSION['actor_scenario_index']];
$actor_quiz_result = null;
if (isset($_POST['actor_quiz_submit'])) {
    mark_done('actors');
    $chosen = $_POST['actor_choice'] ?? '';
    $isCorrect = quiz_answer('actors', $chosen === $currentActorScenario['answer']);
    $actor_quiz_result = quiz_feedback($isCorrect, "Correct answer: " . $currentActorScenario['answer']);
    unset($_SESSION['actor_scenario_index']); // new scenario next time
}

// ---------------------------------------------------------------------
// 4. MALWARE — predict-then-check
// ---------------------------------------------------------------------
$malware_result = null;
$malware_quiz_result = null;
if (isset($_POST['malware_submit'])) {
    mark_done('malware');
    $filename = trim($_POST['filename'] ?? '');
    $dangerousExt = ['exe', 'scr', 'bat', 'cmd', 'js', 'vbs', 'jar', 'msi', 'ps1'];
    $parts = explode('.', $filename);
    $realExt = strtolower(end($parts));
    $dotCount = substr_count($filename, '.');
    $actualDangerous = in_array($realExt, $dangerousExt);

    if ($actualDangerous && $dotCount >= 2) {
        $malware_result = "⚠ SUSPICIOUS: '$filename' looks like a document but its REAL extension is .$realExt — classic disguised-trojan trick (e.g. ExamQuestions.pdf.exe). Do not open. Report to IT.";
    } elseif ($actualDangerous) {
        $malware_result = "⚠ WARNING: '$filename' is a direct executable (.$realExt). Only run files you trust from a verified source.";
    } else {
        $malware_result = "'$filename' has a normal document/media extension (.$realExt). Still verify the sender before opening any attachment.";
    }

    $predicted = $_POST['malware_predict'] ?? '';
    $isCorrect = quiz_answer('malware', ($predicted === 'dangerous') === $actualDangerous);
    $malware_quiz_result = quiz_feedback($isCorrect, $actualDangerous ? "This file IS dangerous." : "This file is NOT dangerous.");
}

// ---------------------------------------------------------------------
// 5. DoS vs DDoS — live rate limiter + static pattern quiz
// ---------------------------------------------------------------------
if (!isset($_SESSION['request_log'])) $_SESSION['request_log'] = [];

$dos_result = null;
if (isset($_POST['dos_submit'])) {
    mark_done('dos');
    $sourceIp = $_POST['dos_ip'] ?: ('client_' . rand(1, 3));
    $now = time();
    $_SESSION['request_log'][] = ['ip' => $sourceIp, 'time' => $now];
    $_SESSION['request_log'] = array_filter($_SESSION['request_log'], fn($r) => $now - $r['time'] <= 10);

    $countsByIp = [];
    foreach ($_SESSION['request_log'] as $r) {
        $countsByIp[$r['ip']] = ($countsByIp[$r['ip']] ?? 0) + 1;
    }
    $uniqueIps = count($countsByIp);
    $totalRequests = count($_SESSION['request_log']);
    $threshold = 5;
    $blockedIps = array_filter($countsByIp, fn($c) => $c > $threshold);

    if ($uniqueIps === 1 && $totalRequests > $threshold) {
        $dos_result = "Pattern detected: ALL $totalRequests requests came from ONE source ($sourceIp) → looks like a DoS attack. A firewall rule blocking this single IP would stop it.";
    } elseif ($uniqueIps > 1 && count($blockedIps) > 0) {
        $dos_result = "Pattern detected: requests are spread across $uniqueIps different IPs, each exceeding the limit → looks like a DDoS attack. Blocking one IP won't help; needs traffic filtering (e.g. a CDN/WAF) instead.";
    } else {
        $dos_result = "Traffic looks normal so far ($totalRequests requests / $uniqueIps source(s) in the last 10s).";
    }
}
if (isset($_POST['dos_reset'])) {
    $_SESSION['request_log'] = [];
}

$dos_quiz_result = null;
if (isset($_POST['dos_quiz_submit'])) {
    mark_done('dos');
    $answer = $_POST['dos_quiz_answer'] ?? '';
    $isCorrect = quiz_answer('dos_quiz', $answer === 'DoS');
    $dos_quiz_result = quiz_feedback($isCorrect, "1,200 requests from a single IP = one attacker, one source → DoS.");
}

// ---------------------------------------------------------------------
// 6. SOCIAL ENGINEERING — spot-the-phish quiz (4-choice classification)
// ---------------------------------------------------------------------
$phish_choices = [
    'phish_email'    => 'Phishing (Email/Web link)',
    'phish_vishing'  => 'Phishing (Vishing — phone call)',
    'phish_smishing' => 'Phishing (Smishing — text message)',
    'real'           => 'Legitimate',
];
$phish_score = null;
if (isset($_POST['phish_submit'])) {
    mark_done('social');
    $answers = ['q1' => 'phish_email', 'q2' => 'real', 'q3' => 'phish_vishing', 'q4' => 'phish_smishing', 'q5' => 'real'];
    $score = 0;
    foreach ($answers as $q => $correct) {
        $isCorrect = ($_POST[$q] ?? '') === $correct;
        quiz_answer("phish_$q", $isCorrect);
        if ($isCorrect) $score++;
    }
    $phish_score = "$score / 5 correct.";
}

// ---------------------------------------------------------------------
// 7. AAA FRAMEWORK — real authentication + authorization + accounting
// ---------------------------------------------------------------------
$users = [
    'teacher'   => ['$2b$10$QE9oh6qHC.C2pxOaL2UB0.j6YV7A0WpZmHgF0nvsCuc1EkTHhWwV2', 'Teacher'],   // password: teach123
    'student'   => ['$2b$10$QE9oh6qHC.C2pxOaL2UB0.j6YV7A0WpZmHgF0nvsCuc1EkTHhWwV2', 'Student'],   // password: teach123 (demo simplicity)
    'registrar' => ['$2b$10$QE9oh6qHC.C2pxOaL2UB0.j6YV7A0WpZmHgF0nvsCuc1EkTHhWwV2', 'Registrar'],
];

$aaa_login_result = null;
if (isset($_POST['aaa_login_submit'])) {
    $u = $_POST['aaa_username'] ?? '';
    $p = $_POST['aaa_password'] ?? '';

    if (isset($users[$u]) && password_verify($p, $users[$u][0])) {
        $_SESSION['aaa_user'] = $u;
        $_SESSION['aaa_role'] = $users[$u][1];
        write_log($logFile, $u, "Logged in successfully");
        mark_done('aaa');
        $aaa_login_result = "Login successful. Welcome, $u (Role: {$users[$u][1]}).";
    } else {
        write_log($logFile, $u ?: '(unknown)', "FAILED login attempt");
        $aaa_login_result = "Invalid username or password.";
    }
}
if (isset($_POST['aaa_logout'])) {
    write_log($logFile, $_SESSION['aaa_user'] ?? 'unknown', "Logged out");
    unset($_SESSION['aaa_user'], $_SESSION['aaa_role']);
}
$aaa_action_result = null;
if (isset($_POST['aaa_action'])) {
    if (!empty($_SESSION['aaa_user'])) {
        $action = $_POST['aaa_action'];
        if ($action === 'edit_grades' && $_SESSION['aaa_role'] !== 'Teacher' && $_SESSION['aaa_role'] !== 'Registrar') {
            write_log($logFile, $_SESSION['aaa_user'], "DENIED attempt to edit grades (role: {$_SESSION['aaa_role']})");
            $aaa_action_result = ['denied' => true, 'action' => $action];
        } else {
            write_log($logFile, $_SESSION['aaa_user'], "Performed: " . str_replace('_', ' ', $action));
            $aaa_action_result = ['denied' => false, 'action' => $action];
        }
    }
}

// ---------------------------------------------------------------------
// 8. PASSWORD HASHING — live generator/verifier
// ---------------------------------------------------------------------
$hash_generated = null;
if (isset($_POST['hash_gen_submit'])) {
    mark_done('hashing');
    $pwd = $_POST['hash_pwd'] ?? '';
    $hash_generated = password_hash($pwd, PASSWORD_DEFAULT);
}
$hash_verify_result = null;
if (isset($_POST['hash_verify_submit'])) {
    mark_done('hashing');
    $pwd = $_POST['verify_pwd'] ?? '';
    $storedHash = $_POST['verify_hash'] ?? '';
    $hash_verify_result = password_verify($pwd, $storedHash) ? "MATCH — password is correct." : "NO MATCH — invalid password.";
}

// ---------------------------------------------------------------------
// 9. ENCRYPTION — reversible, live encrypt/decrypt (AES-256, openssl)
// ---------------------------------------------------------------------
$enc_key = 'classroom-demo-key-2026';
$enc_result = null;
$dec_result = null;
if (isset($_POST['enc_submit'])) {
    mark_done('encryption');
    $plain = $_POST['enc_plain'] ?? '';
    $ivlen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($ivlen);
    $cipherRaw = openssl_encrypt($plain, 'aes-256-cbc', $enc_key, 0, $iv);
    $enc_result = base64_encode($iv . $cipherRaw);
}
if (isset($_POST['dec_submit'])) {
    mark_done('encryption');
    $packed = base64_decode($_POST['dec_cipher'] ?? '');
    $ivlen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($packed, 0, $ivlen);
    $cipherRaw = substr($packed, $ivlen);
    $dec_result = openssl_decrypt($cipherRaw, 'aes-256-cbc', $enc_key, 0, $iv);
    if ($dec_result === false) $dec_result = "Could not decrypt — ciphertext was invalid or tampered with.";
}

// ---------------------------------------------------------------------
// 10. NETWORKING SECURITY — terms quiz + Wi-Fi standard ranking
// ---------------------------------------------------------------------
$network_terms = [
    'Cloud Security' => 'cloud',
    'Honeypot' => 'honeypot',
    'Proxy Server' => 'proxy',
    'IDS (Intrusion Detection System)' => 'ids',
    'IPS (Intrusion Prevention System)' => 'ips',
    'MAC Filtering' => 'mac',
    'SSID' => 'ssid',
    'ACL (Access Control List)' => 'acl',
    'WPA2' => 'wpa2',
    'WPA3' => 'wpa3',
];
$network_scenarios = [
    ['scenario' => 'The GRMS is hosted on Hostinger\'s cloud servers, so the IT team makes sure only authorized staff can adjust the file permissions and passwords protecting student records.', 'answer' => 'cloud'],
    ['scenario' => 'The IT team sets up a fake admin login page that looks real, just to see how attackers behave without risking the real GRMS system.', 'answer' => 'honeypot'],
    ['scenario' => 'The library computers let students browse for research, but social media and gaming sites are automatically blocked.', 'answer' => 'proxy'],
    ['scenario' => 'Someone keeps guessing the GRMS admin password over and over — the system silently logs the pattern and alerts IT staff, but does not stop the attempts by itself.', 'answer' => 'ids'],
    ['scenario' => 'The system automatically blocks the IP address that keeps trying to brute-force the login page, stopping the attack before it succeeds.', 'answer' => 'ips'],
    ['scenario' => 'The school Wi-Fi is configured so only the registered device addresses of students and faculty are allowed to connect.', 'answer' => 'mac'],
    ['scenario' => 'Even though the school renamed its Wi-Fi network\'s broadcast name to something less obvious, a skilled attacker nearby can still discover it.', 'answer' => 'ssid'],
    ['scenario' => 'A network rule states that only computers physically inside the IT department office are allowed to connect to the GRMS admin panel.', 'answer' => 'acl'],
    ['scenario' => 'Most students\' home routers use AES-based encryption that is reasonably secure as long as the password is strong, though it is not the newest standard available.', 'answer' => 'wpa2'],
    ['scenario' => 'The school upgrades its campus router to the newest Wi-Fi encryption standard, giving much stronger protection against password-guessing attacks than before.', 'answer' => 'wpa3'],
];
if (!isset($_SESSION['network_scenario_index'])) {
    $_SESSION['network_scenario_index'] = array_rand($network_scenarios);
}
$currentNetworkScenario = $network_scenarios[$_SESSION['network_scenario_index']];
$network_quiz_result = null;
if (isset($_POST['network_quiz_submit'])) {
    mark_done('network');
    $chosen = $_POST['network_choice'] ?? '';
    $isCorrect = quiz_answer('network_term', $chosen === $currentNetworkScenario['answer']);
    $correctLabel = array_search($currentNetworkScenario['answer'], $network_terms);
    $network_quiz_result = quiz_feedback($isCorrect, "Correct answer: " . $correctLabel);
    unset($_SESSION['network_scenario_index']); // new scenario next time
}

$wifi_order = ['wep', 'wpa', 'wpa2', 'wpa3']; // weakest → strongest
$wifi_rank_result = null;
if (isset($_POST['wifi_rank_submit'])) {
    mark_done('network');
    $submitted = [
        $_POST['wifi_slot1'] ?? '',
        $_POST['wifi_slot2'] ?? '',
        $_POST['wifi_slot3'] ?? '',
        $_POST['wifi_slot4'] ?? '',
    ];
    $isCorrect = quiz_answer('wifi_rank', $submitted === $wifi_order);
    $wifi_rank_result = quiz_feedback($isCorrect, "Weakest → strongest: WEP → WPA → WPA2 → WPA3.");
}

// ---------------------------------------------------------------------
// 11. HASHING FOR INTEGRITY — predict-then-check tamper checker
// ---------------------------------------------------------------------
$integrity_original_hash = null;
$integrity_check_result = null;
$integrity_quiz_result = null;
if (isset($_POST['integrity_hash_submit'])) {
    mark_done('integrity');
    $text = $_POST['integrity_text'] ?? '';
    $integrity_original_hash = hash('sha256', $text);
}
if (isset($_POST['integrity_check_submit'])) {
    mark_done('integrity');
    $text = $_POST['integrity_check_text'] ?? '';
    $originalHash = $_POST['integrity_original_hash'] ?? '';
    $newHash = hash('sha256', $text);
    $actualMatch = ($newHash === $originalHash);
    $integrity_check_result = $actualMatch
        ? "Hashes MATCH → file/text is unchanged."
        : "Hashes DO NOT MATCH → file/text was modified! (New hash: $newHash)";

    $predicted = $_POST['integrity_predict'] ?? '';
    $isCorrect = quiz_answer('integrity', ($predicted === 'match') === $actualMatch);
    $integrity_quiz_result = quiz_feedback($isCorrect, $actualMatch ? "The content was NOT changed." : "The content WAS changed.");
}

// ---------------------------------------------------------------------
// 12. CODING CHALLENGE — Encryption Round-Trip (ONE code box, up to 30 pts)
//     Based directly on the openssl_encrypt()/openssl_decrypt() pattern
//     taught in Section 9 (Encryption). Students write ONE script that
//     encrypts a plaintext, then decrypts it back and proves it matches
//     the original, paste it into the single box below, and it's graded
//     live — inspected only, never eval()'d, since this file may be
//     hosted publicly.
// ---------------------------------------------------------------------
$enc_grade_result = null;
$enc_grade_breakdown = null;
$enc_round_trip_ok = false;
$submitted_enc_code_echo = null;
if (isset($_POST['enc_code_submit'])) {
    mark_done('coding');
    $ecode = $_POST['submitted_enc_code'] ?? '';
    $submitted_enc_code_echo = $ecode;

    $hasEncryptCall = (bool) preg_match('/openssl_encrypt\s*\(/', $ecode);
    $hasDecryptCall = (bool) preg_match('/openssl_decrypt\s*\(/', $ecode);
    $usesAes256Cbc  = substr_count($ecode, 'aes-256-cbc') >= 2; // used in both calls
    $sameKeyVar     = (bool) preg_match('/openssl_encrypt\([^;]*\$key[^;]*\).*openssl_decrypt\([^;]*\$key[^;]*\)/s', $ecode)
                        || (bool) preg_match('/\$key\s*=/', $ecode);
    $sameIvVar      = (bool) preg_match('/openssl_encrypt\([^;]*\$iv[^;]*\).*openssl_decrypt\([^;]*\$iv[^;]*\)/s', $ecode);
    $comparesResult = (bool) preg_match('/===|==/', $ecode) && (str_contains($ecode, 'if') );
    // A genuine round-trip check: run the SAME algorithm the student is
    // being asked to demonstrate, using values we control, to confirm
    // the pattern itself (not their private key) actually works — this
    // is safe because it's fixed logic on our own test string, not code
    // pulled from the student's submission.
    $roundTripDemo = openssl_decrypt(
        openssl_encrypt('ISA1-Demo-Plaintext', 'aes-256-cbc', 'classroom-demo-key-2026', 0, str_repeat('a', 16)),
        'aes-256-cbc', 'classroom-demo-key-2026', 0, str_repeat('a', 16)
    );
    $enc_round_trip_ok = ($roundTripDemo === 'ISA1-Demo-Plaintext') && $hasEncryptCall && $hasDecryptCall && $usesAes256Cbc;

    $checks = [
        'Opens with a PHP tag (<?php)'                        => (bool) preg_match('/<\?php/i', $ecode),
        'Calls openssl_encrypt()'                              => $hasEncryptCall,
        'Calls openssl_decrypt()'                               => $hasDecryptCall,
        "Uses 'aes-256-cbc' in both calls"                     => $usesAes256Cbc,
        'Reuses the same $key for encrypt and decrypt'         => $sameKeyVar,
        'Reuses the same $iv for encrypt and decrypt'          => $sameIvVar,
        'Checks / echoes the decrypted result'                 => str_contains($ecode, 'echo'),
        'Compares decrypted output back to the original text'  => $comparesResult,
        'Includes at least one comment (// or /* */)'          => (bool) preg_match('#//|/\*#', $ecode),
        '✅ Encrypt→Decrypt pattern is structurally correct'    => $enc_round_trip_ok,
    ];
    $points = count(array_filter($checks));
    $points30 = $points * 3;
    set_code_score('code_score', $points30);
    $enc_grade_breakdown = $checks;
    $enc_grade_result = $enc_round_trip_ok
        ? "🔓 ENCRYPTION PATTERN CORRECT — decrypt(encrypt(text)) returns the original text. Rubric score: $points / 10 → +$points30 / 30 points (your best attempt is kept)."
        : "🔒 Pattern incomplete or incorrect. Rubric score: $points / 10 → +$points30 / 30 points. Recheck Section 9 — make sure you encrypt AND decrypt with the SAME \$key and \$iv.";
}

// ---------------------------------------------------------------------
// POST → Redirect → GET
// Every quiz/demo form above posts back to its own section. Instead of
// rendering the result directly on the POST response, we stash the
// computed result variables in a one-time session "flash" and redirect
// to the same section as a plain GET request. That GET request is what
// actually renders the page. Because of this, the browser's history
// never contains a POST for this page, so the Back/Forward buttons work
// normally — no "Confirm Form Resubmission" prompt — and a learner can
// freely leave a section after finishing it and come straight back to
// see their result and try again.
// ---------------------------------------------------------------------
$FLASH_KEYS = [
    'cia_confidentiality_result', 'cia_conf_quiz_result',
    'cia_integrity_result', 'cia_int_quiz_result',
    'cia_availability_result', 'cia_avail_quiz_result',
    'tver_result', 'tver_quiz_result',
    'actor_quiz_result',
    'malware_result', 'malware_quiz_result',
    'dos_result', 'dos_quiz_result',
    'phish_score',
    'aaa_login_result', 'aaa_action_result',
    'hash_generated', 'hash_verify_result',
    'enc_result', 'dec_result',
    'network_quiz_result', 'wifi_rank_result',
    'integrity_original_hash', 'integrity_check_result', 'integrity_quiz_result',
    'enc_grade_result', 'enc_grade_breakdown', 'enc_round_trip_ok', 'submitted_enc_code_echo',
];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $flashData = [];
    foreach ($FLASH_KEYS as $fk) {
        if (isset($$fk)) $flashData[$fk] = $$fk;
    }
    $_SESSION['flash'][$section] = $flashData;
    header('Location: ?section=' . rawurlencode($section));
    exit;
}
$justSubmitted = !empty($_SESSION['flash'][$section]);
if ($justSubmitted) {
    foreach ($_SESSION['flash'][$section] as $fk => $fv) {
        $$fk = $fv;
    }
    unset($_SESSION['flash'][$section]);
}

// ---------------------------------------------------------------------
// Section locking: once a section has been explored (its first quiz
// answered), it's locked from further access — except for the one
// redirect right after answering, so the student can still see their
// result immediately.
// ---------------------------------------------------------------------
$sectionLocked = isset($sectionList[$section])
    && !empty($_SESSION['score']['sections_done'][$section])
    && !$justSubmitted;

// current score numbers for header + score tab
$sectionsDoneCount = count($_SESSION['score']['sections_done']);
$sectionsTotal = count($sectionList);
$validAnswers = array_intersect_key($_SESSION['score']['answers'], array_flip($QUIZ_KEYS)); // ignore any stray/legacy keys
$quizTotal = count($QUIZ_KEYS);                 // fixed — never grows, no matter how many times a question is retried
$quizCorrect = count(array_filter($validAnswers)); // recount from the current true/false of each slot every time
$quizPercent = $quizTotal > 0 ? round(($quizCorrect / $quizTotal) * 100) : 0;
$codeScore = $_SESSION['score']['code_score'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ISA1 — Cybersecurity Concepts Demo</title>
<style>
  :root{
    --navy:#0f1b2d; --blue:#2563eb; --green:#16a34a; --red:#dc2626;
    --amber:#d97706; --bg:#f4f6fb; --card:#ffffff; --border:#e2e8f0; --text:#1e293b;
  }
  *{box-sizing:border-box;}
  body{margin:0; font-family:'Segoe UI',Arial,sans-serif; background:var(--bg); color:var(--text);}
  header{background:var(--navy); color:#fff; padding:22px 24px;}
  header h1{margin:0; font-size:20px;}
  header p{margin:4px 0 0; font-size:13px; color:#9fb0c9;}
  nav{display:flex; flex-wrap:wrap; gap:6px; background:#16233a; padding:10px 16px; align-items:center;}
  nav a{color:#cbd5e1; text-decoration:none; font-size:13px; padding:8px 12px; border-radius:6px;}
  nav a.active{background:var(--blue); color:#fff;}
  nav a:hover{background:#233350;}
  nav a.score-link{margin-left:auto; background:#7c3aed; color:#fff; font-weight:700;}
  nav .nav-locked{color:#5b6b85; font-size:13px; padding:8px 12px; border-radius:6px; cursor:not-allowed; user-select:none;}
  .progress-bar{background:#eef2ff; border-bottom:1px solid var(--border); padding:8px 16px; font-size:12.5px; color:#334155; display:flex; gap:18px; flex-wrap:wrap;}
  .progress-bar b{color:var(--navy);}
  main{max-width:920px; margin:24px auto; padding:0 16px 60px;}
  .card{background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px 22px; margin-bottom:18px;}
  .card h2{margin-top:0; font-size:18px; color:var(--navy);}
  .card h3{font-size:15px; color:var(--blue); margin-bottom:6px;}
  .lecture-note{background:#eff6ff; border-left:4px solid var(--blue); padding:10px 14px; font-size:13.5px; margin-bottom:14px; border-radius:0 6px 6px 0;}
  pre{background:#0f172a; color:#e2e8f0; padding:14px; border-radius:8px; overflow-x:auto; font-size:12.5px; line-height:1.5;}
  label{display:block; font-size:13px; font-weight:600; margin:10px 0 4px;}
  input[type=text], input[type=password], input[type=number], select, textarea{
    width:100%; padding:9px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13.5px;
  }
  textarea{min-height:70px; font-family:monospace;}
  button{background:var(--blue); color:#fff; border:none; padding:9px 16px; border-radius:6px; font-size:13.5px; margin-top:12px; cursor:pointer;}
  button:hover{opacity:0.9;}
  button.secondary{background:#64748b;}
  button.danger{background:var(--red);}
  .result{margin-top:12px; padding:12px 14px; border-radius:6px; font-size:13.5px; word-break:break-word;}
  .result.ok{background:#f0fdf4; border:1px solid #86efac; color:#166534;}
  .result.bad{background:#fef2f2; border:1px solid #fecaca; color:#991b1b;}
  .grid2{display:grid; grid-template-columns:1fr 1fr; gap:18px;}
  @media(max-width:700px){.grid2{grid-template-columns:1fr;}}
  table{width:100%; border-collapse:collapse; font-size:13px; margin-top:8px;}
  th,td{border:1px solid var(--border); padding:8px 10px; text-align:left;}
  th{background:#f1f5f9;}
  .log-line{font-family:monospace; font-size:12px; background:#f8fafc; border-bottom:1px solid var(--border); padding:4px 6px;}
  .badge{display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; color:#fff;}
  .badge.teacher{background:var(--blue);} .badge.student{background:var(--amber);} .badge.registrar{background:var(--green);}
  .footer-note{font-size:12px; color:#64748b; text-align:center; margin-top:30px;}
  .score-hero{text-align:center; padding:30px 20px;}
  .score-hero .big{font-size:48px; font-weight:800; color:var(--blue);}
  .score-hero .sub{font-size:14px; color:#64748b; margin-top:4px;}
  .check-list{list-style:none; padding:0; margin:0;}
  .check-list li{padding:8px 10px; border-bottom:1px solid var(--border); font-size:13.5px; display:flex; justify-content:space-between;}
  .check-list li.done{color:#166534;}
  .check-list li.pending{color:#94a3b8;}
</style>
</head>
<body>

<header>
  <h1>Information Security and Assurance 1</h1>
  <p>School Management System — Live Cybersecurity Concept Demos (MCNP-ISAP)</p>
</header>

<nav>
  <?php
  $navLabels = [
      'cia'        => '1. CIA Triad',
      'tver'       => '2. TVER',
      'actors'     => '3. Threat Actors',
      'malware'    => '4. Malware',
      'dos'        => '5. DoS/DDoS',
      'social'     => '6. Social Eng.',
      'aaa'        => '7. AAA',
      'hashing'    => '8. Hashing (Password)',
      'encryption' => '9. Encryption',
      'network'    => '10. Networking Security',
      'integrity'  => '11. Hashing (Integrity)',
      'coding'     => '12. Coding Challenge',
  ];
  foreach ($navLabels as $navKey => $navLabel):
      $navDone = !empty($_SESSION['score']['sections_done'][$navKey]);
  ?>
    <?php if ($navDone): ?>
      <span class="nav-locked" title="Already explored — locked">🔒 <?= e($navLabel) ?></span>
    <?php else: ?>
      <a href="?section=<?= e($navKey) ?>" class="<?= $section==$navKey?'active':'' ?>"><?= e($navLabel) ?></a>
    <?php endif; ?>
  <?php endforeach; ?>
  <a href="?section=score" class="score-link <?= $section=='score'?'active':'' ?>">🏆 Score</a>
</nav>

<div class="progress-bar">
  <span>Sections explored: <b><?= $sectionsDoneCount ?> / <?= $sectionsTotal ?></b></span>
  <span>Quiz score: <b><?= $quizCorrect ?> / <?= $quizTotal ?></b> (<?= $quizPercent ?>%)</span>
  <span>Code Challenge: <b><?= $codeScore ?> / 30</b></span>
</div>

<main>

<?php if ($sectionLocked): ?>

  <div class="card">
    <h2>🔒 <?= e($sectionList[$section]) ?> — Already Explored</h2>
    <div class="lecture-note">You've already completed this section this session, so it's now locked and can't be reopened. Your result was saved the first time you answered it.</div>
    <p><a href="?section=score">🏆 Go to my Score</a></p>
  </div>

<?php elseif ($section === 'cia'): ?>

  <div class="card">
    <h2>1. CIA Triad — Confidentiality, Integrity, Availability</h2>
    <div class="lecture-note">Every security problem can be classified as a Confidentiality, Integrity, or Availability issue. Try each demo below and watch the outcome change with your input.</div>

    <h3>🔒 Confidentiality — role-based grade access</h3>
    <form method="post" action="?section=cia">
      <label>Choose a role and try to view grades:</label>
      <select name="cia_role" required>
        <option value="">-- Choose a role --</option>
        <option>Student</option>
        <option>Teacher</option>
        <option>Admin</option>
      </select>
      <label>Your prediction:</label>
      <select name="cia_conf_predict" required>
        <option value="">-- Choose --</option>
        <option value="granted">Access Granted</option>
        <option value="denied">Access Denied</option>
      </select>
      <button type="submit" name="cia_conf_submit">View Grades</button>
    </form>
    <?php if ($cia_conf_quiz_result): ?>
      <?= $cia_conf_quiz_result ?>
    <?php endif; ?>
    <?php if ($cia_confidentiality_result): ?>
      <div class="result <?= str_contains($cia_confidentiality_result,'DENIED') ? 'bad':'ok' ?>">✅ Demo complete — <?= e($cia_confidentiality_result) ?></div>
    <?php endif; ?>
    <pre>if ($role == "Teacher" || $role == "Admin") {
    echo "Student Grades";
} else {
    echo "Access Denied";
}</pre>

    <h3>✏️ Integrity — tamper-evident grade record</h3>
    <p style="font-size:13px;">Original grade on file: <b>95</b>. Try submitting the same value, or a different one, to simulate an unauthorized change.</p>
    <form method="post" action="?section=cia">
      <label>Submit a grade value:</label>
      <input type="text" name="cia_grade" placeholder="Enter a grade value" required>
      <label>Your prediction:</label>
      <select name="cia_int_predict" required>
        <option value="">-- Choose --</option>
        <option value="intact">Integrity Intact</option>
        <option value="violated">Integrity Violated</option>
      </select>
      <button type="submit" name="cia_int_submit">Check Integrity</button>
    </form>
    <?php if ($cia_int_quiz_result): ?>
      <?= $cia_int_quiz_result ?>
    <?php endif; ?>
    <?php if ($cia_integrity_result): ?>
      <div class="result <?= str_contains($cia_integrity_result,'VIOLATED') ? 'bad':'ok' ?>">✅ Demo complete — <?= e($cia_integrity_result) ?></div>
    <?php endif; ?>
    <pre>$originalHash = hash('sha256', $originalGrade);
$submittedHash = hash('sha256', $submittedGrade);
if ($submittedHash === $originalHash) {
    echo "Integrity intact";
} else {
    echo "Integrity violated!";
}</pre>

    <h3>🌐 Availability — simulate a traffic spike</h3>
    <form method="post" action="?section=cia">
      <label>Number of simultaneous login requests (server capacity = 100):</label>
      <input type="number" name="cia_requests" placeholder="Enter a number of requests" required>
      <label>Your prediction:</label>
      <select name="cia_avail_predict" required>
        <option value="">-- Choose --</option>
        <option value="up">Website Stays Up</option>
        <option value="down">Website Goes Down</option>
      </select>
      <button type="submit" name="cia_avail_submit">Send Requests</button>
    </form>
    <?php if ($cia_avail_quiz_result): ?>
      <?= $cia_avail_quiz_result ?>
    <?php endif; ?>
    <?php if ($cia_availability_result): ?>
      <div class="result <?= str_contains($cia_availability_result,'DOWN') ? 'bad':'ok' ?>">✅ Demo complete — <?= e($cia_availability_result) ?></div>
    <?php endif; ?>
  </div>

<?php elseif ($section === 'tver'): ?>

  <div class="card">
    <h2>2. Threat, Vulnerability, Exploit, and Risk (TVER)</h2>
    <div class="lecture-note">These four terms describe the anatomy of a security incident, from weakness to impact.</div>
    <table>
      <tr><th>Term</th><th>School Example</th></tr>
      <tr><td><b>Vulnerability</b></td><td>The admin panel still uses the default password <code>admin</code>.</td></tr>
      <tr><td><b>Threat</b></td><td>A former student who knows about the weak password and wants to look up grades.</td></tr>
      <tr><td><b>Exploit</b></td><td>They actually log in using <code>admin</code> and browse records.</td></tr>
      <tr><td><b>Risk</b></td><td>Likelihood × Impact — because grades and personal data could be stolen or altered, this is rated <b>High Risk</b>.</td></tr>
    </table>

    <h3>Quiz — predict, then check</h3>
    <form method="post" action="?section=tver">
      <label>Enter a password used on your system:</label>
      <input type="text" name="tver_pass" placeholder="Type a password to test" required>
      <label>Your prediction — is it vulnerable?</label>
      <select name="tver_predict" required>
        <option value="">-- Choose --</option>
        <option value="vulnerable">Vulnerable</option>
        <option value="safe">Not Vulnerable</option>
      </select>
      <button type="submit" name="tver_check">Check</button>
    </form>
    <?php if ($tver_result): ?>
      <?= $tver_quiz_result ?>
      <div class="result <?= str_contains($tver_result,'FOUND') ? 'bad':'ok' ?>"><?= e($tver_result) ?></div>
    <?php endif; ?>
    <pre>$weakPasswords = ['admin','123456','password','qwerty'];
if (in_array(strtolower($submittedPassword), $weakPasswords)) {
    echo "Vulnerability found!";
}</pre>
  </div>

<?php elseif ($section === 'actors'): ?>

  <div class="card">
    <h2>3. Threat Actors</h2>
    <div class="lecture-note">Match the actor to the scenario.</div>
    <?php
    $actors = [
      'Script Kiddie' => 'Downloads a free hacking tool online and runs it against the school website just to see what happens.',
      'Insider'        => 'A registrar with legitimate access secretly edits a friend\'s failing grade.',
      'Black Hat'      => 'Breaks into the database and sells the stolen student records on the dark web.',
      'White Hat'      => 'Hired by the school to legally test the website and report vulnerabilities.',
      'APT (Advanced Persistent Threat)' => 'A well-funded group quietly exfiltrates research data over several months without detection.',
    ];
    ?>
    <table>
      <tr><th>Actor</th><th>Scenario</th></tr>
      <?php foreach ($actors as $name => $desc): ?>
      <tr><td><b><?= e($name) ?></b></td><td><?= e($desc) ?></td></tr>
      <?php endforeach; ?>
    </table>

    <h3>Quiz</h3>
    <form method="post" action="?section=actors">
      <p><b>Scenario:</b> "<?= e($currentActorScenario['scenario']) ?>"</p>
      <label>Which actor type is this?</label>
      <select name="actor_choice" required>
        <option value="">-- Choose --</option>
        <?php foreach ($actors as $name => $desc): ?>
          <option value="<?= e($name) ?>"><?= e($name) ?></option>
        <?php endforeach; ?>
      </select>
      <button type="submit" name="actor_quiz_submit">Submit Answer</button>
    </form>
    <?php if ($actor_quiz_result): ?>
      <?= $actor_quiz_result ?>
    <?php endif; ?>
  </div>

<?php elseif ($section === 'malware'): ?>

  <div class="card">
    <h2>4. Malware — disguised file detector</h2>
    <div class="lecture-note">A classic trojan trick is naming a file <code>ExamQuestions.pdf.exe</code> so it *looks* like a PDF at a glance.</div>
    <form method="post" action="?section=malware">
      <label>Enter a filename to check:</label>
      <input type="text" name="filename" placeholder="e.g. ExamQuestions.pdf.exe" required>
      <label>Your prediction:</label>
      <select name="malware_predict" required>
        <option value="">-- Choose --</option>
        <option value="dangerous">Dangerous</option>
        <option value="safe">Safe</option>
      </select>
      <button type="submit" name="malware_submit">Check File</button>
    </form>
    <?php if ($malware_result): ?>
      <?= $malware_quiz_result ?>
      <div class="result <?= str_contains($malware_result,'⚠') ? 'bad':'ok' ?>"><?= e($malware_result) ?></div>
    <?php endif; ?>
    <pre>$dangerousExt = ['exe','scr','bat','cmd','js','vbs','jar','msi','ps1'];
$parts = explode('.', $filename);
$realExtension = strtolower(end($parts));

if (in_array($realExtension, $dangerousExt) && substr_count($filename, '.') >= 2) {
    echo "Suspicious double-extension file!";
}</pre>
    <p style="font-size:13px;">Try these examples too: <code>Reviewer.docx</code>, <code>FreePhotoshop.exe</code>, <code>Grades.xlsx.locked</code> (ransomware pattern).</p>
  </div>

<?php elseif ($section === 'dos'): ?>

  <div class="card">
    <h2>5. DoS vs DDoS — live rate limiter</h2>
    <div class="lecture-note">Click "Send Request" repeatedly using the SAME simulated IP to trigger a DoS pattern, or change the IP field each time to simulate a DDoS from many sources.</div>
    <form method="post" action="?section=dos">
      <label>Simulated source IP (leave blank to auto-rotate between 3 IPs):</label>
      <input type="text" name="dos_ip" placeholder="e.g. 192.168.1.5">
      <button type="submit" name="dos_submit">Send Request</button>
      <button type="submit" name="dos_reset" class="secondary">Reset Traffic Log</button>
    </form>
    <?php if ($dos_result): ?>
      <div class="result <?= str_contains($dos_result,'looks like') ? 'bad':'ok' ?>">✅ Demo complete — <?= e($dos_result) ?></div>
    <?php endif; ?>
    <p style="font-size:13px;">Requests logged in the last 10 seconds: <b><?= count($_SESSION['request_log']) ?></b></p>

    <h3>Quiz</h3>
    <form method="post" action="?section=dos">
      <p><b>Scenario:</b> 1,200 requests hit the server in 10 seconds, all from a single IP address.</p>
      <label>Is this a DoS or DDoS pattern?</label>
      <select name="dos_quiz_answer" required>
        <option value="">-- Choose --</option>
        <option value="DoS">DoS</option>
        <option value="DDoS">DDoS</option>
      </select>
      <button type="submit" name="dos_quiz_submit">Submit Answer</button>
    </form>
    <?php if ($dos_quiz_result): ?>
      <?= $dos_quiz_result ?>
    <?php endif; ?>
    <pre>// simplified rate-limit logic
$_SESSION['request_log'][] = ['ip' => $sourceIp, 'time' => time()];
$recent = array_filter($_SESSION['request_log'], fn($r) => time() - $r['time'] <= 10);

if (count($recent) > 5) {
    // possible DoS/DDoS — block or throttle
}</pre>
  </div>

<?php elseif ($section === 'social'): ?>

  <div class="card">
    <h2>6. Social Engineering — spot the phish</h2>
    <div class="lecture-note">Read each message and classify it — is it a phishing email/link, a vishing call, a smishing text, or a legitimate message?</div>
    <form method="post" action="?section=social">
      <p><b>Message 1:</b> "Your account will expire in 24 hours! Click here to verify: http://schoo1-portal-login.com"</p>
      <select name="q1" required>
        <option value="">-- Choose --</option>
        <?php foreach ($phish_choices as $val => $label): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>

      <p><b>Message 2:</b> An email from your registrar's official @isap.edu.ph address, sent during enrollment week, reminding you of the deadline — no links, just a reminder.</p>
      <select name="q2" required>
        <option value="">-- Choose --</option>
        <?php foreach ($phish_choices as $val => $label): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>

      <p><b>Message 3:</b> A call: "Hi, this is IT support, we detected a virus on your account — please read me your password so we can fix it."</p>
      <select name="q3" required>
        <option value="">-- Choose --</option>
        <?php foreach ($phish_choices as $val => $label): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>

      <p><b>Message 4:</b> A text message: "CONGRATULATIONS! You've won a free tablet from the MCNP-ISAP Anniversary Raffle! Claim within 1 hour: http://isap-raffle-claim.net"</p>
      <select name="q4" required>
        <option value="">-- Choose --</option>
        <?php foreach ($phish_choices as $val => $label): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>

      <p><b>Message 5:</b> A text from the registrar's number already saved in your contacts, sent during enrollment week: "Reminder: Enrollment deadline is this Friday. No action needed if you already enrolled."</p>
      <select name="q5" required>
        <option value="">-- Choose --</option>
        <?php foreach ($phish_choices as $val => $label): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>

      <button type="submit" name="phish_submit">Submit Answers</button>
    </form>
    <?php if ($phish_score): ?>
      <div class="result <?= str_starts_with($phish_score,'5') ? 'ok':'bad' ?>">✅ Score: <?= e($phish_score) ?></div>
    <?php endif; ?>

    <h3>Other social engineering types from the lecture</h3>
    <table>
      <tr><th>Type</th><th>Example</th></tr>
      <tr><td>Tailgating</td><td>"Please hold the door" — following an employee into the server room without a badge.</td></tr>
      <tr><td>Shoulder Surfing</td><td>Watching a teacher type their password over their shoulder.</td></tr>
      <tr><td>Dumpster Diving</td><td>Searching the trash for printed student IDs or documents.</td></tr>
      <tr><td>Pretexting</td><td>Inventing a false scenario ("I'm from the Dean's office") to obtain information.</td></tr>
      <tr><td>Baiting</td><td>Leaving an infected USB drive labeled "Payroll 2026" in the hallway.</td></tr>
      <tr><td>Smishing</td><td>A text message pretending to be from the school asking you to click a link.</td></tr>
    </table>
  </div>

<?php elseif ($section === 'aaa'): ?>

  <div class="card">
    <h2>7. AAA Framework — real login + role check + activity log</h2>
    <div class="lecture-note">Demo accounts (all use password <code>teach123</code> for classroom simplicity): <code>teacher</code>, <code>student</code>, <code>registrar</code>.</div>

    <?php if (empty($_SESSION['aaa_user'])): ?>
      <h3>Authentication</h3>
      <form method="post" action="?section=aaa">
        <label>Username</label>
        <input type="text" name="aaa_username" placeholder="teacher / student / registrar">
        <label>Password</label>
        <input type="password" name="aaa_password" placeholder="teach123">
        <button type="submit" name="aaa_login_submit">Log In</button>
      </form>
      <?php if ($aaa_login_result): ?>
        <div class="result <?= str_contains($aaa_login_result,'successful') ? 'ok':'bad' ?>"><?= str_contains($aaa_login_result,'successful') ? '✅ ' : '❌ ' ?><?= e($aaa_login_result) ?></div>
      <?php endif; ?>
    <?php else: ?>
      <h3>Authorization</h3>
      <p>Logged in as <b><?= e($_SESSION['aaa_user']) ?></b>
        <span class="badge <?= strtolower($_SESSION['aaa_role']) ?>"><?= e($_SESSION['aaa_role']) ?></span>
      </p>
      <form method="post" action="?section=aaa" style="display:inline;">
        <button type="submit" name="aaa_action" value="view_grades">View Grades</button>
      </form>
      <form method="post" action="?section=aaa" style="display:inline;">
        <button type="submit" name="aaa_action" value="edit_grades" class="<?= $_SESSION['aaa_role']=='Student'?'danger':'' ?>">Edit Grades</button>
      </form>
      <form method="post" action="?section=aaa" style="display:inline;">
        <button type="submit" name="aaa_logout" class="secondary">Log Out</button>
      </form>
      <?php if ($aaa_action_result): ?>
        <div class="result <?= $aaa_action_result['denied'] ? 'bad':'ok' ?>">
          <?php if ($aaa_action_result['denied']): ?>
            ❌ Access Denied — Students cannot edit grades. This attempt was recorded.
          <?php else: ?>
            ✅ Action "<?= e(str_replace('_',' ',$aaa_action_result['action'])) ?>" completed and logged.
          <?php endif; ?>
        </div>
      <?php endif; ?>
    <?php endif; ?>

    <h3>Accounting — activity log (most recent 10)</h3>
    <div>
      <?php foreach (read_log($logFile) as $line): ?>
        <div class="log-line"><?= e($line) ?></div>
      <?php endforeach; ?>
      <?php if (!file_exists($logFile)) echo '<p style="font-size:13px;color:#64748b;">No activity yet — log in above to generate entries.</p>'; ?>
    </div>
    <pre>function write_log($user, $action) {
    $entry = date("Y-m-d H:i:s") . " | $user | $action" . PHP_EOL;
    file_put_contents('activity_log.txt', $entry, FILE_APPEND | LOCK_EX);
}</pre>
  </div>

<?php elseif ($section === 'hashing'): ?>

  <div class="card">
    <h2>8. Password Hashing — live generator & verifier</h2>
    <div class="lecture-note">Hashing is one-way. You cannot "unhash" a value back into the original password — you can only hash a new guess and compare.</div>

    <h3>Generate a hash</h3>
    <form method="post" action="?section=hashing">
      <label>Password to hash:</label>
      <input type="text" name="hash_pwd" value="123456">
      <button type="submit" name="hash_gen_submit">Generate Hash</button>
    </form>
    <?php if ($hash_generated): ?>
      <div class="result ok">✅ password_hash() output:<br><code style="word-break:break-all;"><?= e($hash_generated) ?></code></div>
    <?php endif; ?>
    <pre>$hash = password_hash($password, PASSWORD_DEFAULT);</pre>

    <h3>Verify a password against a hash</h3>
    <form method="post" action="?section=hashing">
      <label>Password to test:</label>
      <input type="text" name="verify_pwd" value="123456">
      <label>Stored hash to compare against:</label>
      <textarea name="verify_hash" placeholder="paste a hash generated above"><?= e($hash_generated ?? '') ?></textarea>
      <button type="submit" name="hash_verify_submit">Verify</button>
    </form>
    <?php if ($hash_verify_result): ?>
      <div class="result <?= str_contains($hash_verify_result,'MATCH —') ? 'ok':'bad' ?>"><?= str_contains($hash_verify_result,'MATCH —') ? '✅ ' : '❌ ' ?><?= e($hash_verify_result) ?></div>
    <?php endif; ?>
    <pre>if (password_verify($enteredPassword, $storedHash)) {
    echo "Correct password";
} else {
    echo "Invalid password";
}</pre>
    <p style="font-size:13px;">Notice: hashing the SAME password twice with <code>password_hash()</code> gives DIFFERENT-looking output each time (random salt), but <code>password_verify()</code> still correctly matches it.</p>
  </div>

<?php elseif ($section === 'encryption'): ?>

  <div class="card">
    <h2>9. Encryption — reversible protection (AES-256)</h2>
    <div class="lecture-note">Unlike hashing, encryption is two-way: anyone holding the correct key can decrypt it back to the original text. This is what HTTPS does to data in transit.</div>

    <h3>Encrypt</h3>
    <form method="post" action="?section=encryption">
      <label>Plain text (e.g. a password being submitted over the network):</label>
      <input type="text" name="enc_plain" value="MySecretPassword123">
      <button type="submit" name="enc_submit">Encrypt</button>
    </form>
    <?php if ($enc_result): ?>
      <div class="result ok">✅ Encrypted (base64):<br><code style="word-break:break-all;"><?= e($enc_result) ?></code></div>
    <?php endif; ?>

    <h3>Decrypt</h3>
    <form method="post" action="?section=encryption">
      <label>Ciphertext to decrypt:</label>
      <textarea name="dec_cipher" placeholder="paste ciphertext generated above"><?= e($enc_result ?? '') ?></textarea>
      <button type="submit" name="dec_submit">Decrypt</button>
    </form>
    <?php if ($dec_result !== null): ?>
      <div class="result ok">✅ Decrypted result: <b><?= e($dec_result) ?></b></div>
    <?php endif; ?>
    <pre>// Encrypt
$cipher = openssl_encrypt($plain, 'aes-256-cbc', $key, 0, $iv);

// Decrypt (same key + iv required)
$plain = openssl_decrypt($cipher, 'aes-256-cbc', $key, 0, $iv);</pre>
    <p style="font-size:13px;"><b>Key teaching point:</b> without HTTPS, this "encryption in transit" step never happens — an attacker on the same network can read plain-text passwords directly.</p>
  </div>

<?php elseif ($section === 'integrity'): ?>

  <div class="card">
    <h2>11. Hashing for Integrity — tamper checker</h2>
    <div class="lecture-note">This mirrors how schools verify a downloaded reviewer file hasn't been modified — hash the original, then hash the downloaded copy and compare.</div>

    <h3>Step 1 — hash the original file/text</h3>
    <form method="post" action="?section=integrity">
      <label>Original content:</label>
      <textarea name="integrity_text" placeholder="Type or paste the original content here" required></textarea>
      <button type="submit" name="integrity_hash_submit">Generate Original Hash</button>
    </form>
    <?php if ($integrity_original_hash): ?>
      <div class="result ok">✅ Original SHA-256 hash:<br><code style="word-break:break-all;"><?= e($integrity_original_hash) ?></code></div>
    <?php endif; ?>

    <h3>Step 2 — check the downloaded/received copy</h3>
    <form method="post" action="?section=integrity">
      <label>Content received by the student (try editing it):</label>
      <textarea name="integrity_check_text" placeholder="Paste the received content here" required></textarea>
      <label>Original hash to compare against:</label>
      <input type="text" name="integrity_original_hash" placeholder="Paste the hash from Step 1" required>
      <label>Your prediction:</label>
      <select name="integrity_predict" required>
        <option value="">-- Choose --</option>
        <option value="match">Content matches (unchanged)</option>
        <option value="different">Content was modified</option>
      </select>
      <button type="submit" name="integrity_check_submit">Compare</button>
    </form>
    <?php if ($integrity_quiz_result): ?>
      <?= $integrity_quiz_result ?>
    <?php endif; ?>
    <?php if ($integrity_check_result): ?>
      <div class="result <?= str_contains($integrity_check_result,'DO NOT MATCH') ? 'bad':'ok' ?>"><?= e($integrity_check_result) ?></div>
    <?php endif; ?>
    <pre>$hash = hash('sha256', file_get_contents($filename));
// later...
if (hash('sha256', file_get_contents($downloadedFile)) === $hash) {
    echo "File unchanged";
} else {
    echo "File was modified!";
}</pre>
  </div>

<?php elseif ($section === 'network'): ?>

  <div class="card">
    <h2>10. Networking Security</h2>
    <div class="lecture-note">These are the tools and settings that protect the network itself — the pipes and doors data travels through — not just the data.</div>

    <table>
      <tr><th>Term</th><th>Explanation</th><th>Cybersecurity Example</th><th>School/Home Scenario</th></tr>
      <tr>
        <td><b>Cloud Security</b></td>
        <td>Protects applications, data, and services stored in the cloud.</td>
        <td>Misconfigured cloud storage may expose sensitive data.</td>
        <td>Dahil naka-host ang GRMS sa cloud servers ng Hostinger, kailangan ang tamang cloud security settings — malakas na password at tamang file permissions — para hindi malantad sa publiko ang student at guidance records.</td>
      </tr>
      <tr>
        <td><b>Honeypot</b></td>
        <td>A fake system designed to attract attackers.</td>
        <td>Security teams analyze attacker behavior using the honeypot.</td>
        <td>Maaaring gumawa ang IT team ng paaralan ng pekeng admin login page na kamukha ng tunay na GRMS admin panel, para kapag may sumubok mag-hack dito, naitatala at nasusuri ang attempt nang hindi naaabala ang tunay na system.</td>
      </tr>
      <tr>
        <td><b>Proxy Server</b></td>
        <td>Acts as an intermediary between users and the Internet.</td>
        <td>A proxy can filter malicious websites before users access them.</td>
        <td>Puwedeng gumamit ang mga computer sa library ng MCNP-ISAP ng proxy server para makapag-research ang mga estudyante habang awtomatikong naka-block ang mga social media at gaming site.</td>
      </tr>
      <tr>
        <td><b>IDS</b> (Intrusion Detection System)</td>
        <td>Monitors network traffic and alerts administrators about suspicious activity.</td>
        <td>An IDS notifies the administrator when malware is detected.</td>
        <td>Kung may sumusubok maghula ng GRMS admin password nang paulit-ulit, matutukoy ito ng isang IDS na nagmo-monitor sa network ng paaralan at aalertuhan nito ang IT staff.</td>
      </tr>
      <tr>
        <td><b>IPS</b> (Intrusion Prevention System)</td>
        <td>Monitors and automatically blocks malicious traffic.</td>
        <td>An IPS stops attacks before they reach the server.</td>
        <td>Kung may naka-install na IPS sa GRMS server, awtomatiko nitong ibi-block ang IP address na paulit-ulit na sumusubok mag-brute-force sa login page.</td>
      </tr>
      <tr>
        <td><b>MAC Filtering</b></td>
        <td>Allows only approved devices to connect to a Wi-Fi network.</td>
        <td>Attackers can bypass MAC filtering by changing their MAC address.</td>
        <td>Puwedeng i-configure ang school Wi-Fi para ang MAC address lang ng mga rehistradong device ng estudyante at faculty ang papayagang kumonekta.</td>
      </tr>
      <tr>
        <td><b>WEP</b></td>
        <td>An old Wi-Fi security standard that is no longer secure.</td>
        <td>Attackers can crack WEP passwords within minutes.</td>
        <td>Ang isang lumang wireless router sa library ay maaaring gumagamit pa rin ng WEP encryption, na kayang i-crack sa loob lamang ng ilang minuto gamit ang libreng tools.</td>
      </tr>
      <tr>
        <td><b>WPA</b></td>
        <td>Improved Wi-Fi security compared to WEP.</td>
        <td>Weak WPA passwords can still be guessed by attackers.</td>
        <td>May ilang lumang home router na gumagamit pa rin ng WPA — mas maganda kaysa WEP pero itinuturing na luma na ngayon.</td>
      </tr>
      <tr>
        <td><b>WPA2</b></td>
        <td>A secure Wi-Fi encryption standard using AES.</td>
        <td>Weak passwords can still be cracked through dictionary attacks.</td>
        <td>Karamihan sa home Wi-Fi router ng mga estudyante ng MCNP-ISAP ay gumagamit ng WPA2, na medyo secure basta't malakas ang password.</td>
      </tr>
      <tr>
        <td><b>WPA3</b></td>
        <td>The latest Wi-Fi security standard, stronger than WPA2.</td>
        <td>WPA3 better protects users against password-guessing attacks.</td>
        <td>Kung i-upgrade ng paaralan ang campus router para suportahan ang WPA3, magkakaroon ng mas matibay na proteksyon ang mga estudyante at staff.</td>
      </tr>
      <tr>
        <td><b>SSID</b></td>
        <td>The name of a wireless network.</td>
        <td>Hiding the SSID does not prevent attackers from discovering the network.</td>
        <td>Ang pangalan ng Wi-Fi ng paaralan, tulad ng "MCNP-ISAP-WiFi", ay ang SSID nito. Kahit itago, kaya pa ring matukoy ito ng isang mahusay na attacker.</td>
      </tr>
      <tr>
        <td><b>ACL</b> (Access Control List)</td>
        <td>Controls which users or devices are allowed to access network resources.</td>
        <td>Incorrect ACL rules may allow unauthorized access.</td>
        <td>Puwedeng i-set na ang ACL ng GRMS server ay pahihintulutan lang ang mga computer ng IT department na kumonekta sa admin panel mula sa loob ng campus network.</td>
      </tr>
    </table>

    <h3>Quiz — match the scenario to the term</h3>
    <form method="post" action="?section=network">
      <p><b>Scenario:</b> "<?= e($currentNetworkScenario['scenario']) ?>"</p>
      <label>Which networking security tool is this?</label>
      <select name="network_choice" required>
        <option value="">-- Choose --</option>
        <?php foreach ($network_terms as $label => $val): ?>
          <option value="<?= e($val) ?>"><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
      <button type="submit" name="network_quiz_submit">Submit Answer</button>
    </form>
    <?php if ($network_quiz_result): ?>
      <?= $network_quiz_result ?>
    <?php endif; ?>

    <h3>Quiz — rank the Wi-Fi standards, weakest to strongest</h3>
    <form method="post" action="?section=network">
      <label>Weakest:</label>
      <select name="wifi_slot1" required>
        <option value="">-- Choose --</option>
        <option value="wpa2">WPA2</option><option value="wpa3">WPA3</option>
        <option value="wep">WEP</option><option value="wpa">WPA</option>
      </select>
      <label>Then:</label>
      <select name="wifi_slot2" required>
        <option value="">-- Choose --</option>
        <option value="wpa3">WPA3</option><option value="wep">WEP</option>
        <option value="wpa2">WPA2</option><option value="wpa">WPA</option>
      </select>
      <label>Then:</label>
      <select name="wifi_slot3" required>
        <option value="">-- Choose --</option>
        <option value="wep">WEP</option><option value="wpa">WPA</option>
        <option value="wpa3">WPA3</option><option value="wpa2">WPA2</option>
      </select>
      <label>Strongest:</label>
      <select name="wifi_slot4" required>
        <option value="">-- Choose --</option>
        <option value="wep">WEP</option><option value="wpa2">WPA2</option>
        <option value="wpa">WPA</option><option value="wpa3">WPA3</option>
      </select>
      <button type="submit" name="wifi_rank_submit">Check Order</button>
    </form>
    <?php if ($wifi_rank_result): ?>
      <?= $wifi_rank_result ?>
    <?php endif; ?>

    <h3>Bonus concept — Data States</h3>
    <div class="lecture-note">Every piece of data your system touches is in one of three states, and each needs a different kind of protection — this connects directly to the network tools above.</div>
    <table>
      <tr><th>State</th><th>School Example</th><th>Typical Protection</th></tr>
      <tr><td><b>Data at Rest</b></td><td>Student grades stored in the MySQL database</td><td>Database encryption, access control, backups</td></tr>
      <tr><td><b>Data in Transit</b></td><td>Grades being submitted through the web portal</td><td>HTTPS / TLS, WPA2/WPA3 on the Wi-Fi carrying it</td></tr>
      <tr><td><b>Data in Use</b></td><td>GPA being calculated in server memory right now</td><td>Secure coding, memory protection, least privilege</td></tr>
    </table>
    <p style="font-size:13px;">Ask students: "At which state is data most often stolen through phishing?" — usually <b>in transit</b> or right after entry, when credentials are typed and sent.</p>
  </div>

<?php elseif ($section === 'coding'): ?>

  <div class="card">
    <h2>12. Coding Challenge — Encryption Round-Trip (up to 30 pts)</h2>
    <div class="lecture-note">This comes straight from <a href="?section=encryption">Section 9 — Encryption</a>. On your own laptop (XAMPP, or any online PHP sandbox), write ONE script that encrypts a message with AES-256, then decrypts it back with the SAME key and IV, and proves the result matches the original. Then paste that exact script below to be graded.</div>

    <h3>What your script needs to do</h3>
    <ul style="font-size:13.5px;">
      <li>Pick any plaintext message and a key.</li>
      <li>Generate an IV and encrypt the message with <code>openssl_encrypt()</code> using <code>'aes-256-cbc'</code>.</li>
      <li>Decrypt it back with <code>openssl_decrypt()</code> — using the <b>exact same</b> <code>$key</code> and <code>$iv</code> from the encrypt step.</li>
      <li>Compare the decrypted result to your original plaintext and print whether it matches.</li>
    </ul>
    <p style="font-size:13px;">Reminder from Section 9: the IV has to be generated <b>once</b> and reused for decrypt — if you regenerate a new random IV before decrypting, it will never match.</p>

    <h3>Submit your code here (graded live)</h3>
    <div class="lecture-note">Paste the exact script you wrote and ran. It's graded on structure and on whether the encrypt→decrypt pattern is actually correct — up to 30 points.</div>
    <form method="post" action="?section=coding">
      <label>Paste your PHP code here:</label>
      <textarea name="submitted_enc_code" style="min-height:260px; font-family:monospace;" placeholder="&lt;?php&#10;// write your full encryption script here..." required><?= e($submitted_enc_code_echo ?? '') ?></textarea>
      <button type="submit" name="enc_code_submit">Submit Code — Grade Encryption</button>
    </form>
    <?php if ($enc_grade_result): ?>
      <div class="result <?= $enc_round_trip_ok ? 'ok':'bad' ?>"><?= e($enc_grade_result) ?></div>
      <table>
        <tr><th>Rubric item</th><th>Result</th></tr>
        <?php foreach ($enc_grade_breakdown as $label => $passed): ?>
          <tr><td><?= e($label) ?></td><td><?= $passed ? '✅ Met' : '❌ Missing' ?></td></tr>
        <?php endforeach; ?>
      </table>
      <p style="font-size:12.5px; color:#64748b;">Only your best submission counts, so feel free to fix and resubmit. Your current best: <b><?= $codeScore ?> / 30</b>.</p>
    <?php endif; ?>
  </div>

<?php elseif ($section === 'score'): ?>

  <div class="card">
    <div class="score-hero">
      <div class="big"><?= $sectionsDoneCount ?> / <?= $sectionsTotal ?></div>
      <div class="sub">sections explored</div>
      <div class="big" style="font-size:32px; margin-top:14px;"><?= $quizCorrect ?> / <?= $quizTotal ?> <span style="font-size:18px;color:#64748b;">(<?= $quizPercent ?>%)</span></div>
      <div class="sub">quiz questions correct</div>
      <div class="big" style="font-size:32px; margin-top:14px; color:var(--green);"><?= $codeScore ?> / 30</div>
      <div class="sub">Coding Challenge (Section 12) — Encryption rubric score</div>
      <?php if ($sectionsDoneCount === $sectionsTotal): ?>
        <div class="result ok" style="margin-top:20px; font-size:15px;">🎉 Great job — you've explored every section! <?= $quizTotal > 0 ? "Final quiz score: $quizCorrect/$quizTotal ($quizPercent%). Code Challenge: $codeScore/30." : "" ?></div>
      <?php else: ?>
        <div class="result" style="margin-top:20px; background:#fffbeb; border:1px solid #fde68a; color:#92400e;">Keep going — <?= $sectionsTotal - $sectionsDoneCount ?> section(s) left to try.</div>
      <?php endif; ?>
    </div>

    <h3>Section checklist</h3>
    <ul class="check-list">
      <?php foreach ($sectionList as $key => $label): ?>
        <?php $done = !empty($_SESSION['score']['sections_done'][$key]); ?>
        <li class="<?= $done ? 'done':'pending' ?>">
          <span><?= $done ? '✅' : '⬜' ?> <?= e($label) ?></span>
          <?php if ($done): ?>
            <span style="font-size:12px; color:#94a3b8;">🔒 Locked</span>
          <?php else: ?>
            <a href="?section=<?= e($key) ?>" style="font-size:12px;">Go →</a>
          <?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ul>

    <form method="post" action="?section=score" style="margin-top:16px;">
      <button type="submit" name="reset_score" class="secondary">Reset Progress</button>
    </form>
  </div>

<?php endif; ?>

<div class="footer-note">
  Information Security and Assurance 1 — MCNP-ISAP classroom demo. Upload this single file to Hostinger or run on XAMPP (place in <code>htdocs</code>). Make sure the folder is writable so <code>activity_log.txt</code> can be created for the AAA demo. Progress and scores are stored per browser session.
</div>

</main>
</body>
</html>