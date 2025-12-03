<?php
/**
 * KINKNTEASE API - Complete Backend
 * Version: 2.1 - FIXED
 * 
 * Upload to: /api/index.php
 */

// ============================================
// CONFIGURATION
// ============================================

// Database credentials
define('DB_HOST', 'localhost');
define('DB_NAME', 'db9hmsktz1ntus');
define('DB_USER', 'udyfazsjumhnm');
define('DB_PASS', 'Whiteman1!');

// API Key for basic security
define('API_KEY', 'kinkntease_secret_key_2024');

// Upload paths
define('UPLOAD_PATH', __DIR__ . '/../uploads/');
define('UPLOAD_URL', '/uploads/');

// Session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Lax');

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// ============================================
// CORS & HEADERS
// ============================================

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: https://kinkntease.com');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Start session
session_start();

// ============================================
// DATABASE CONNECTION
// ============================================

class Database {
    private static $instance = null;
    private $pdo;
    
    private function __construct() {
        try {
            $this->pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function getConnection() {
        return $this->pdo;
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function jsonResponse($success, $data = null, $error = null, $code = 200) {
    http_response_code($code);
    echo json_encode([
        'success' => $success,
        'data' => $data,
        'error' => $error,
        'timestamp' => date('c')
    ]);
    exit;
}

function validateApiKey() {
    $key = $_SERVER['HTTP_X_API_KEY'] ?? '';
    if ($key !== API_KEY) {
        jsonResponse(false, null, 'Invalid API key', 401);
    }
}

function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        jsonResponse(false, null, 'Authentication required', 401);
    }
    return $_SESSION['user_id'];
}

function getInput() {
    $input = json_decode(file_get_contents('php://input'), true);
    return $input ?: $_POST;
}

function sanitize($str) {
    return htmlspecialchars(strip_tags(trim($str)), ENT_QUOTES, 'UTF-8');
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function calculateAge($dob) {
    $birthDate = new DateTime($dob);
    $today = new DateTime();
    return $birthDate->diff($today)->y;
}

function uploadFile($file, $subdir = 'general', $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']) {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'error' => 'No file uploaded'];
    }
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    error_log("UPLOAD: Detected MIME type: {$mimeType}");
    error_log("UPLOAD: Allowed types: " . implode(', ', $allowedTypes));
    
    if (!in_array($mimeType, $allowedTypes)) {
        error_log("UPLOAD ERROR: MIME type '{$mimeType}' not in allowed types");
        return ['success' => false, 'error' => "Invalid file type (detected: {$mimeType}). Allowed: " . implode(', ', $allowedTypes)];
    }
    
    $maxSize = 10 * 1024 * 1024; // 10MB
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'error' => 'File too large'];
    }
    
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    $filename = generateToken(16) . '.' . $ext;
    $uploadDir = UPLOAD_PATH . $subdir . '/';
    
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    
    $filepath = $uploadDir . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $filepath)) {
        error_log("UPLOAD SUCCESS: {$filepath}");
        return [
            'success' => true,
            'filename' => $filename,
            'url' => UPLOAD_URL . $subdir . '/' . $filename
        ];
    }
    
    return ['success' => false, 'error' => 'Upload failed'];
}

// ============================================
// API ROUTER
// ============================================

validateApiKey();

// DEBUG - Version check
error_log("API VERSION: 2.1.1 - FIXED");
error_log("Endpoint: " . ($_GET['endpoint'] ?? 'none'));
error_log("Action: " . ($_GET['action'] ?? 'none'));
error_log("Session User ID: " . ($_SESSION['user_id'] ?? 'not set'));

// Match frontend parameter names
$endpoint = $_GET['endpoint'] ?? '';
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

try {
    $db = Database::getInstance()->getConnection();
    
    switch ($endpoint) {
        
        // ==========================================
        // AUTH ENDPOINTS
        // ==========================================
        case 'auth':
            switch ($action) {
                case 'register':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $username = sanitize($input['username'] ?? '');
                    $email = sanitize($input['email'] ?? '');
                    $password = $input['password'] ?? '';
                    $dob = $input['date_of_birth'] ?? '';
                    $gender = sanitize($input['gender'] ?? '');
                    
                    // Validation
                    if (strlen($username) < 3) jsonResponse(false, null, 'Username must be at least 3 characters');
                    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(false, null, 'Invalid email address');
                    if (strlen($password) < 6) jsonResponse(false, null, 'Password must be at least 6 characters');
                    if ($dob && calculateAge($dob) < 18) jsonResponse(false, null, 'You must be 18 or older');
                    
                    // Check if exists
                    $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
                    $stmt->execute([$username, $email]);
                    if ($stmt->fetch()) jsonResponse(false, null, 'Username or email already exists');
                    
                    // Generate verification token
                    $verificationToken = bin2hex(random_bytes(32));
                    
                    // Create user with verification token
                    $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, date_of_birth, gender, coins, email_verified, verification_token, created_at) VALUES (?, ?, ?, ?, ?, 100, 0, ?, NOW())");
                    $stmt->execute([$username, $email, hashPassword($password), $dob ?: null, $gender ?: null, $verificationToken]);
                    
                    $userId = $db->lastInsertId();
                    
                    // Create profile
                    $db->prepare("INSERT INTO profiles (user_id) VALUES (?)")->execute([$userId]);
                    
                    // Send verification email
                    $verifyLink = "https://kinkntease.com/verify.html?token=" . $verificationToken;
                    $subject = "Verify your Kink N Tease account";
                    $message = "
                        <html>
                        <body style='font-family: Arial, sans-serif;'>
                            <h2>Welcome to Kink N Tease!</h2>
                            <p>Hi <strong>{$username}</strong>,</p>
                            <p>Thank you for registering! Please verify your email address by clicking the link below:</p>
                            <p><a href='{$verifyLink}' style='background:#4ECCA3;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;display:inline-block'>Verify Email Address</a></p>
                            <p>Or copy and paste this link into your browser:</p>
                            <p>{$verifyLink}</p>
                            <p>This link will expire in 24 hours.</p>
                            <p><strong>Important:</strong> You must verify your email before you can login.</p>
                            <hr>
                            <p style='color:#666;font-size:12px'>If you didn't create this account, please ignore this email.</p>
                        </body>
                        </html>
                    ";
                    
                    // Send email (using mail() function - replace with your SMTP if configured)
                    $headers = "MIME-Version: 1.0" . "\r\n";
                    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
                    $headers .= "From: noreply@kinkntease.com" . "\r\n";
                    
                    @mail($email, $subject, $message, $headers);
                    
                    jsonResponse(true, [
                        'user_id' => $userId, 
                        'message' => 'Registration successful! Please check your email to verify your account.'
                    ]);
                    break;
                    
                case 'login':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $username = sanitize($input['username'] ?? '');
                    $password = $input['password'] ?? '';
                    
                    $stmt = $db->prepare("SELECT u.*, p.display_name, p.avatar_url FROM users u LEFT JOIN profiles p ON u.id = p.user_id WHERE u.username = ? OR u.email = ?");
                    $stmt->execute([$username, $username]);
                    $user = $stmt->fetch();
                    
                    if (!$user || !verifyPassword($password, $user['password_hash'])) {
                        jsonResponse(false, null, 'Invalid credentials');
                    }
                    
                    if ($user['is_banned']) {
                        jsonResponse(false, null, 'Account suspended');
                    }
                    
                    // Check email verification (skip for admin)
                    if ($user['email_verified'] == 0 && $user['is_admin'] != 1) {
                        jsonResponse(false, null, 'Please verify your email before logging in. Check your inbox for the verification link.');
                    }
                    
                    // Update last login and online status
                    $db->prepare("UPDATE users SET last_login = NOW(), is_online = 1 WHERE id = ?")->execute([$user['id']]);
                    
                    // Set session
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    
                    unset($user['password_hash']);
                    jsonResponse(true, ['user' => $user]);
                    break;
                    
                case 'logout':
                    if (isset($_SESSION['user_id'])) {
                        $db->prepare("UPDATE users SET is_online = 0 WHERE id = ?")->execute([$_SESSION['user_id']]);
                    }
                    session_destroy();
                    jsonResponse(true, ['message' => 'Logged out']);
                    break;
                    
                case 'verify-email':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $token = sanitize($input['token'] ?? '');
                    
                    if (empty($token)) jsonResponse(false, null, 'Verification token required');
                    
                    $stmt = $db->prepare("SELECT id, username, email FROM users WHERE verification_token = ? AND email_verified = 0");
                    $stmt->execute([$token]);
                    $user = $stmt->fetch();
                    
                    if (!$user) jsonResponse(false, null, 'Invalid or expired verification token');
                    
                    // Mark as verified
                    $db->prepare("UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?")->execute([$user['id']]);
                    
                    jsonResponse(true, ['message' => 'Email verified successfully! You can now login.', 'username' => $user['username']]);
                    break;
                    
                case 'resend-verification':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $email = sanitize($input['email'] ?? '');
                    
                    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(false, null, 'Invalid email address');
                    
                    $stmt = $db->prepare("SELECT id, username, email_verified FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    $user = $stmt->fetch();
                    
                    if (!$user) jsonResponse(false, null, 'Email not found');
                    if ($user['email_verified'] == 1) jsonResponse(false, null, 'Email already verified');
                    
                    // Generate new token
                    $verificationToken = bin2hex(random_bytes(32));
                    $db->prepare("UPDATE users SET verification_token = ? WHERE id = ?")->execute([$verificationToken, $user['id']]);
                    
                    // Send email
                    $verifyLink = "https://kinkntease.com/verify.html?token=" . $verificationToken;
                    $subject = "Verify your Kink N Tease account";
                    $message = "
                        <html>
                        <body style='font-family: Arial, sans-serif;'>
                            <h2>Verify your email</h2>
                            <p>Hi <strong>{$user['username']}</strong>,</p>
                            <p>Click the link below to verify your email address:</p>
                            <p><a href='{$verifyLink}' style='background:#4ECCA3;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;display:inline-block'>Verify Email Address</a></p>
                            <p>Or copy and paste this link:</p>
                            <p>{$verifyLink}</p>
                        </body>
                        </html>
                    ";
                    
                    $headers = "MIME-Version: 1.0" . "\r\n";
                    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
                    $headers .= "From: noreply@kinkntease.com" . "\r\n";
                    
                    @mail($email, $subject, $message, $headers);
                    
                    jsonResponse(true, ['message' => 'Verification email sent! Please check your inbox.']);
                    break;
                    
                case 'check':
                    if (isset($_SESSION['user_id'])) {
                        $stmt = $db->prepare("SELECT u.id, u.username, u.email, u.coins, u.subscription_type, u.is_verified, u.is_admin, p.display_name, p.avatar_url FROM users u LEFT JOIN profiles p ON u.id = p.user_id WHERE u.id = ?");
                        $stmt->execute([$_SESSION['user_id']]);
                        $user = $stmt->fetch();
                        jsonResponse(true, ['user' => $user]);
                    }
                    jsonResponse(false, null, 'Not authenticated');
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown auth action', 404);
            }
            break;
            
        // ==========================================
        // USERS ENDPOINTS
        // ==========================================
        case 'users':
            switch ($action) {
                case 'list':
                    $page = max(1, intval($_GET['page'] ?? 1));
                    $limit = min(50, max(10, intval($_GET['limit'] ?? 20)));
                    $offset = ($page - 1) * $limit;
                    
                    $where = ["u.is_banned = 0"];
                    $params = [];
                    
                    if (!empty($_GET['gender'])) {
                        $where[] = "u.gender = ?";
                        $params[] = $_GET['gender'];
                    }
                    if (!empty($_GET['min_age'])) {
                        $where[] = "TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) >= ?";
                        $params[] = intval($_GET['min_age']);
                    }
                    if (!empty($_GET['max_age'])) {
                        $where[] = "TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) <= ?";
                        $params[] = intval($_GET['max_age']);
                    }
                    if (!empty($_GET['online'])) {
                        $where[] = "u.is_online = 1";
                    }
                    
                    $whereClause = implode(' AND ', $where);
                    
                    $sql = "SELECT u.id, u.username, u.gender, u.is_online, u.is_verified, u.subscription_type,
                                   TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                                   p.display_name, p.avatar_url, p.about_me, p.tagline, p.city, p.country,
                                   p.interests, p.kinks, p.occupation, p.body_type, p.hair_color, p.eye_color, p.relationship_status,
                                   (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                            FROM users u
                            LEFT JOIN profiles p ON u.id = p.user_id
                            WHERE {$whereClause}
                            ORDER BY u.is_online DESC, u.last_login DESC
                            LIMIT {$limit} OFFSET {$offset}";
                    
                    $stmt = $db->prepare($sql);
                    $stmt->execute($params);
                    $users = $stmt->fetchAll();
                    
                    // Get total count
                    $countSql = "SELECT COUNT(*) FROM users u WHERE {$whereClause}";
                    $countStmt = $db->prepare($countSql);
                    $countStmt->execute($params);
                    $total = $countStmt->fetchColumn();
                    
                    jsonResponse(true, [
                        'users' => $users,
                        'pagination' => [
                            'page' => $page,
                            'limit' => $limit,
                            'total' => $total,
                            'pages' => ceil($total / $limit)
                        ]
                    ]);
                    break;
                    
                case 'search':
                    $query = sanitize($_GET['q'] ?? '');
                    if (strlen($query) < 2) jsonResponse(false, null, 'Search query too short');
                    
                    $stmt = $db->prepare("
                        SELECT u.id, u.username, u.is_online, u.is_verified,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               p.display_name, p.avatar_url, p.city
                        FROM users u
                        LEFT JOIN profiles p ON u.id = p.user_id
                        WHERE u.is_banned = 0 AND (u.username LIKE ? OR p.display_name LIKE ?)
                        LIMIT 20
                    ");
                    $searchTerm = "%{$query}%";
                    $stmt->execute([$searchTerm, $searchTerm]);
                    jsonResponse(true, ['users' => $stmt->fetchAll()]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown users action', 404);
            }
            break;
            
        // ==========================================
        // PROFILE ENDPOINTS
        // ==========================================
        case 'profile':
            switch ($action) {
                case 'get':
                    $userId = intval($_GET['user_id'] ?? 0);
                    $currentUser = $_SESSION['user_id'] ?? 0;
                    
                    if (!$userId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("
                        SELECT u.id, u.username, u.gender, u.is_online, u.is_verified, u.subscription_type, u.last_login, u.created_at,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               p.*
                        FROM users u
                        LEFT JOIN profiles p ON u.id = p.user_id
                        WHERE u.id = ? AND u.is_banned = 0
                    ");
                    $stmt->execute([$userId]);
                    $profile = $stmt->fetch();
                    
                    if (!$profile) jsonResponse(false, null, 'User not found', 404);
                    
                    // Get photos (with error handling for missing table)
                    $photos = [];
                    try {
                        $stmt = $db->prepare("SELECT * FROM user_photos WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC");
                        $stmt->execute([$userId]);
                        $allPhotos = $stmt->fetchAll();
                        
                        // Check if current user is premium
                        $viewerIsPremium = false;
                        $isOwner = ($currentUser == $userId);
                        
                        if ($currentUser) {
                            $premiumStmt = $db->prepare("SELECT subscription_type FROM users WHERE id = ?");
                            $premiumStmt->execute([$currentUser]);
                            $viewer = $premiumStmt->fetch();
                            $viewerIsPremium = ($viewer && in_array($viewer['subscription_type'], ['premium', 'vip']));
                        }
                        
                        // Filter locked photos for non-premium viewers
                        foreach ($allPhotos as $photo) {
                            if ($photo['is_locked'] && !$isOwner && !$viewerIsPremium) {
                                // Show locked placeholder
                                $photo['photo_url'] = '/uploads/locked-placeholder.jpg';
                                $photo['is_locked_for_viewer'] = true;
                            } else {
                                $photo['is_locked_for_viewer'] = false;
                            }
                            $photos[] = $photo;
                        }
                    } catch (PDOException $e) {
                        error_log("PROFILE GET: user_photos table error: " . $e->getMessage());
                        // Table doesn't exist yet - return empty array
                    }
                    
                    // Get voice recordings (with error handling for missing table)
                    $voiceRecordings = [];
                    try {
                        $stmt = $db->prepare("SELECT * FROM profile_voice_recordings WHERE user_id = ? ORDER BY created_at DESC");
                        $stmt->execute([$userId]);
                        $voiceRecordings = $stmt->fetchAll();
                    } catch (PDOException $e) {
                        error_log("PROFILE GET: profile_voice_recordings table error: " . $e->getMessage());
                        // Table doesn't exist yet - return empty array
                    }
                    
                    // Log profile view (if viewing someone else's profile)
                    if ($currentUser && $currentUser != $userId) {
                        try {
                            $db->prepare("INSERT INTO profile_views (viewer_id, viewed_user_id, viewed_at) VALUES (?, ?, NOW())")->execute([$currentUser, $userId]);
                            
                            // Create notification for profile view
                            $db->prepare("INSERT INTO notifications (user_id, from_user_id, type, created_at) VALUES (?, ?, 'view', NOW())")->execute([$userId, $currentUser]);
                        } catch (PDOException $e) {
                            // Ignore if table doesn't exist
                        }
                    }
                    
                    jsonResponse(true, ['profile' => $profile, 'photos' => $photos, 'voice_recordings' => $voiceRecordings]);
                    break;
                    
                case 'update':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $allowed = ['display_name', 'about_me', 'looking_for', 'orientation', 'relationship_status', 
                                'body_type', 'height', 'hair_color', 'eye_color',
                                'city', 'country', 'occupation', 'tagline', 'interests', 'kinks'];
                    
                    $updates = [];
                    $params = [];
                    
                    foreach ($allowed as $field) {
                        if (isset($input[$field])) {
                            $updates[] = "{$field} = ?";
                            $params[] = sanitize($input[$field]);
                        }
                    }
                    
                    if (empty($updates)) jsonResponse(false, null, 'No fields to update');
                    
                    $params[] = $userId;
                    $sql = "UPDATE profiles SET " . implode(', ', $updates) . ", updated_at = NOW() WHERE user_id = ?";
                    $db->prepare($sql)->execute($params);
                    
                    jsonResponse(true, ['message' => 'Profile updated']);
                    break;
                    
                case 'upload-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    // Debug logging
                    error_log("PHOTO UPLOAD: User ID: $userId");
                    error_log("PHOTO UPLOAD: FILES: " . print_r($_FILES, true));
                    error_log("PHOTO UPLOAD: POST: " . print_r($_POST, true));
                    
                    if (!isset($_FILES['photo'])) {
                        error_log("PHOTO UPLOAD ERROR: No photo in FILES array");
                        jsonResponse(false, null, 'No photo uploaded. Please select an image.');
                    }
                    
                    $result = uploadFile($_FILES['photo'], 'profiles');
                    
                    error_log("PHOTO UPLOAD: Upload result: " . print_r($result, true));
                    
                    if (!$result['success']) {
                        error_log("PHOTO UPLOAD ERROR: " . $result['error']);
                        jsonResponse(false, null, $result['error']);
                    }
                    
                    $isPrimary = !empty($_POST['is_primary']) && $_POST['is_primary'] === 'true' ? 1 : 0;
                    
                    error_log("PHOTO UPLOAD: Is primary: $isPrimary, URL: " . $result['url']);
                    
                    // If setting as primary, unset other primaries
                    if ($isPrimary) {
                        $db->prepare("UPDATE user_photos SET is_primary = 0 WHERE user_id = ?")->execute([$userId]);
                    }
                    
                    try {
                        $stmt = $db->prepare("INSERT INTO user_photos (user_id, photo_url, is_primary, created_at) VALUES (?, ?, ?, NOW())");
                        $stmt->execute([$userId, $result['url'], $isPrimary]);
                        $photoId = $db->lastInsertId();
                        
                        error_log("PHOTO UPLOAD: Inserted into user_photos. ID: $photoId");
                        
                        // Update avatar if primary
                        if ($isPrimary) {
                            $stmt = $db->prepare("UPDATE profiles SET avatar_url = ? WHERE user_id = ?");
                            $stmt->execute([$result['url'], $userId]);
                            error_log("PHOTO UPLOAD: Updated profile avatar_url");
                        }
                        
                        error_log("PHOTO UPLOAD: SUCCESS! Photo ID: $photoId, URL: " . $result['url']);
                        jsonResponse(true, ['photo_id' => $photoId, 'url' => $result['url'], 'is_primary' => $isPrimary]);
                        
                    } catch (PDOException $e) {
                        error_log("PHOTO UPLOAD DATABASE ERROR: " . $e->getMessage());
                        
                        // Check if table exists
                        try {
                            $db->query("DESCRIBE user_photos");
                        } catch (PDOException $e2) {
                            error_log("PHOTO UPLOAD: user_photos table does NOT exist!");
                            jsonResponse(false, null, 'Database error: user_photos table not found. Please run the database setup SQL.');
                        }
                        
                        jsonResponse(false, null, 'Database error: ' . $e->getMessage());
                    }
                    break;
                    
                case 'set-primary-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $photoId = intval($input['photo_id'] ?? 0);
                    
                    if (!$photoId) jsonResponse(false, null, 'Photo ID required');
                    
                    // Verify photo belongs to user
                    $stmt = $db->prepare("SELECT photo_url FROM user_photos WHERE id = ? AND user_id = ?");
                    $stmt->execute([$photoId, $userId]);
                    $photo = $stmt->fetch();
                    
                    if (!$photo) jsonResponse(false, null, 'Photo not found');
                    
                    // Unset all primaries for this user
                    $db->prepare("UPDATE user_photos SET is_primary = 0 WHERE user_id = ?")->execute([$userId]);
                    
                    // Set new primary
                    $db->prepare("UPDATE user_photos SET is_primary = 1 WHERE id = ?")->execute([$photoId]);
                    
                    // Update avatar
                    $db->prepare("UPDATE profiles SET avatar_url = ? WHERE user_id = ?")->execute([$photo['photo_url'], $userId]);
                    
                    jsonResponse(true, ['message' => 'Primary photo updated']);
                    break;
                    
                case 'delete-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $photoId = intval($input['photo_id'] ?? 0);
                    
                    $stmt = $db->prepare("DELETE FROM user_photos WHERE id = ? AND user_id = ?");
                    $stmt->execute([$photoId, $userId]);
                    
                    jsonResponse(true, ['message' => 'Photo deleted']);
                    break;
                    
                case 'upload-voice':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['voice'])) jsonResponse(false, null, 'No voice recording uploaded');
                    
                    $title = sanitize($_POST['title'] ?? 'Voice Intro');
                    
                    // Check max recordings (5)
                    $stmt = $db->prepare("SELECT COUNT(*) as count FROM profile_voice_recordings WHERE user_id = ?");
                    $stmt->execute([$userId]);
                    $count = $stmt->fetch()['count'];
                    
                    if ($count >= 5) jsonResponse(false, null, 'Maximum 5 voice recordings allowed');
                    
                    // Upload voice file
                    $file = $_FILES['voice'];
                    $uploadDir = __DIR__ . '/../uploads/voice/';
                    
                    if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
                    
                    $ext = 'webm';
                    $filename = uniqid('profile_voice_') . '.' . $ext;
                    $filepath = $uploadDir . $filename;
                    
                    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
                        jsonResponse(false, null, 'Failed to save voice recording');
                    }
                    
                    $url = '/uploads/voice/' . $filename;
                    
                    // Calculate duration (placeholder - would need ffmpeg to get actual duration)
                    $duration = '0:00';
                    
                    $stmt = $db->prepare("INSERT INTO profile_voice_recordings (user_id, title, audio_url, duration, created_at) VALUES (?, ?, ?, ?, NOW())");
                    $stmt->execute([$userId, $title, $url, $duration]);
                    
                    jsonResponse(true, ['voice_id' => $db->lastInsertId(), 'url' => $url]);
                    break;
                    
                case 'delete-voice':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $voiceId = intval($input['voice_id'] ?? 0);
                    
                    $stmt = $db->prepare("DELETE FROM profile_voice_recordings WHERE id = ? AND user_id = ?");
                    $stmt->execute([$voiceId, $userId]);
                    
                    jsonResponse(true, ['message' => 'Voice recording deleted']);
                    break;
                    
                case 'rate-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $photoId = intval($input['photo_id'] ?? 0);
                    $rating = intval($input['rating'] ?? 0);
                    
                    if (!$photoId) jsonResponse(false, null, 'Photo ID required');
                    if ($rating < 1 || $rating > 5) jsonResponse(false, null, 'Rating must be between 1 and 5');
                    
                    // Get photo owner
                    $stmt = $db->prepare("SELECT user_id FROM user_photos WHERE id = ?");
                    $stmt->execute([$photoId]);
                    $photo = $stmt->fetch();
                    
                    if (!$photo) jsonResponse(false, null, 'Photo not found');
                    if ($photo['user_id'] == $userId) jsonResponse(false, null, 'Cannot rate your own photos');
                    
                    // Check if user already rated this photo
                    $stmt = $db->prepare("SELECT id FROM photo_ratings WHERE photo_id = ? AND user_id = ?");
                    $stmt->execute([$photoId, $userId]);
                    
                    if ($stmt->fetch()) {
                        // Update existing rating
                        $db->prepare("UPDATE photo_ratings SET rating = ?, rated_at = NOW() WHERE photo_id = ? AND user_id = ?")
                           ->execute([$rating, $photoId, $userId]);
                    } else {
                        // Insert new rating
                        $db->prepare("INSERT INTO photo_ratings (photo_id, user_id, rating, rated_at) VALUES (?, ?, ?, NOW())")
                           ->execute([$photoId, $userId, $rating]);
                    }
                    
                    // Calculate average rating for this photo
                    $stmt = $db->prepare("SELECT AVG(rating) as avg_rating, COUNT(*) as total_ratings FROM photo_ratings WHERE photo_id = ?");
                    $stmt->execute([$photoId]);
                    $stats = $stmt->fetch();
                    
                    // Update photo with new average
                    $db->prepare("UPDATE user_photos SET rating = ?, rating_count = ? WHERE id = ?")
                       ->execute([round($stats['avg_rating'], 1), $stats['total_ratings'], $photoId]);
                    
                    jsonResponse(true, [
                        'message' => 'Rating saved!',
                        'avg_rating' => round($stats['avg_rating'], 1),
                        'total_ratings' => intval($stats['total_ratings'])
                    ]);
                    break;
                    
                case 'toggle-photo-lock':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $photoId = intval($input['photo_id'] ?? 0);
                    
                    if (!$photoId) jsonResponse(false, null, 'Photo ID required');
                    
                    // Verify photo belongs to user
                    $stmt = $db->prepare("SELECT is_locked FROM user_photos WHERE id = ? AND user_id = ?");
                    $stmt->execute([$photoId, $userId]);
                    $photo = $stmt->fetch();
                    
                    if (!$photo) jsonResponse(false, null, 'Photo not found or not yours');
                    
                    // Toggle lock status
                    $newLockStatus = $photo['is_locked'] ? 0 : 1;
                    $db->prepare("UPDATE user_photos SET is_locked = ? WHERE id = ?")
                       ->execute([$newLockStatus, $photoId]);
                    
                    jsonResponse(true, [
                        'is_locked' => $newLockStatus,
                        'message' => $newLockStatus ? 'Photo locked 🔒' : 'Photo unlocked 🔓'
                    ]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown profile action', 404);
            }
            break;
            
        // ==========================================
        // MESSAGES ENDPOINTS
        // ==========================================
        case 'messages':
            switch ($action) {
                case 'conversations':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT 
                            CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END as user_id,
                            u.username,
                            p.display_name,
                            p.avatar_url,
                            u.is_online,
                            m.message_text as last_message,
                            m.created_at as last_message_time,
                            m.is_read,
                            m.sender_id as last_sender_id,
                            (SELECT COUNT(*) FROM messages WHERE sender_id = user_id AND receiver_id = ? AND is_read = 0) as unread_count,
                            (SELECT COUNT(*) FROM blocked_users WHERE (blocker_id = ? AND blocked_id = user_id) OR (blocker_id = user_id AND blocked_id = ?)) as is_blocked
                        FROM messages m
                        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE (m.sender_id = ? OR m.receiver_id = ?)
                        AND m.id IN (
                            SELECT MAX(id) FROM messages 
                            WHERE sender_id = ? OR receiver_id = ?
                            GROUP BY LEAST(sender_id, receiver_id), GREATEST(sender_id, receiver_id)
                        )
                        ORDER BY m.created_at DESC
                    ");
                    $stmt->execute([$userId, $userId, $userId, $userId, $userId, $userId, $userId, $userId, $userId]);
                    
                    jsonResponse(true, ['conversations' => $stmt->fetchAll()]);
                    break;
                    
                case 'get':
                    $userId = requireAuth();
                    $withUserId = intval($_GET['with_user_id'] ?? 0);
                    
                    if (!$withUserId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("
                        SELECT m.*, 
                               s.username as sender_username, sp.display_name as sender_display_name,
                               r.username as receiver_username, rp.display_name as receiver_display_name
                        FROM messages m
                        JOIN users s ON m.sender_id = s.id
                        JOIN users r ON m.receiver_id = r.id
                        LEFT JOIN profiles sp ON sp.user_id = s.id
                        LEFT JOIN profiles rp ON rp.user_id = r.id
                        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
                        ORDER BY m.created_at ASC
                        LIMIT 100
                    ");
                    $stmt->execute([$userId, $withUserId, $withUserId, $userId]);
                    
                    jsonResponse(true, ['messages' => $stmt->fetchAll()]);
                    break;
                    
                case 'send':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $toUserId = intval($input['to_user_id'] ?? 0);
                    $messageText = sanitize($input['message_text'] ?? '');
                    $messageType = $input['message_type'] ?? 'text';
                    
                    if (!$toUserId) jsonResponse(false, null, 'Recipient required');
                    if (empty($messageText) && $messageType === 'text') jsonResponse(false, null, 'Message cannot be empty');
                    
                    // Check if either user has blocked the other
                    $blockCheck = $db->prepare("SELECT id FROM blocked_users WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)");
                    $blockCheck->execute([$toUserId, $userId, $userId, $toUserId]);
                    if ($blockCheck->fetch()) {
                        jsonResponse(false, null, 'Cannot send message - user blocked');
                    }
                    
                    $mediaUrl = null;
                    if (isset($_FILES['media'])) {
                        $result = uploadFile($_FILES['media'], 'messages');
                        if ($result['success']) $mediaUrl = $result['url'];
                    }
                    
                    $stmt = $db->prepare("INSERT INTO messages (sender_id, receiver_id, message_text, message_type, created_at) VALUES (?, ?, ?, ?, NOW())");
                    $stmt->execute([$userId, $toUserId, $messageText, $messageType]);
                    
                    // Create notification for new message
                    $db->prepare("INSERT INTO notifications (user_id, from_user_id, type, message, created_at) VALUES (?, ?, 'message', ?, NOW())")->execute([$toUserId, $userId, substr($messageText, 0, 100)]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId()]);
                    break;
                    
                case 'read':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $withUserId = intval($input['with_user_id'] ?? 0);
                    
                    $db->prepare("UPDATE messages SET is_read = 1, read_at = NOW() WHERE sender_id = ? AND receiver_id = ? AND is_read = 0")->execute([$withUserId, $userId]);
                    
                    jsonResponse(true, ['message' => 'Messages marked as read']);
                    break;
                    
                case 'delete':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    
                    // Verify user owns the message
                    $stmt = $db->prepare("SELECT id FROM messages WHERE id = ? AND sender_id = ?");
                    $stmt->execute([$messageId, $userId]);
                    
                    if (!$stmt->fetch()) jsonResponse(false, null, 'Message not found or you do not have permission', 403);
                    
                    // Delete the message
                    $db->prepare("DELETE FROM messages WHERE id = ?")->execute([$messageId]);
                    
                    jsonResponse(true, ['message' => 'Message deleted']);
                    break;
                    
                case 'send-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['photo'])) jsonResponse(false, null, 'No photo uploaded');
                    
                    $toUserId = intval($_POST['to_user_id'] ?? 0);
                    if (!$toUserId) jsonResponse(false, null, 'Recipient required');
                    
                    $result = uploadFile($_FILES['photo'], 'messages');
                    if (!$result['success']) jsonResponse(false, null, $result['error']);
                    
                    $stmt = $db->prepare("INSERT INTO messages (sender_id, receiver_id, message_text, message_type, created_at) VALUES (?, ?, ?, 'photo', NOW())");
                    $stmt->execute([$userId, $toUserId, $result['url']]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId(), 'url' => $result['url']]);
                    break;
                    
                case 'send-voice':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['voice'])) jsonResponse(false, null, 'No voice message uploaded');
                    
                    $toUserId = intval($_POST['to_user_id'] ?? 0);
                    if (!$toUserId) jsonResponse(false, null, 'Recipient required');
                    
                    // Upload voice file
                    $file = $_FILES['voice'];
                    $uploadDir = __DIR__ . '/../uploads/voice/';
                    
                    if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
                    
                    $ext = 'webm';
                    $filename = uniqid('voice_') . '.' . $ext;
                    $filepath = $uploadDir . $filename;
                    
                    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
                        jsonResponse(false, null, 'Failed to save voice message');
                    }
                    
                    $url = '/uploads/voice/' . $filename;
                    
                    $stmt = $db->prepare("INSERT INTO messages (sender_id, receiver_id, message_text, message_type, created_at) VALUES (?, ?, ?, 'voice', NOW())");
                    $stmt->execute([$userId, $toUserId, $url]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId(), 'url' => $url]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown messages action', 404);
            }
            break;
            
        // ==========================================
        // SOCIAL ENDPOINTS (Winks, Favorites, Views)
        // ==========================================
        case 'social':
            switch ($action) {
                case 'send-wink':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $toUserId = intval($input['to_user_id'] ?? 0);
                    
                    if (!$toUserId) jsonResponse(false, null, 'User ID required');
                    if ($toUserId === $userId) jsonResponse(false, null, 'Cannot wink at yourself');
                    
                    // Check if wink already sent
                    $stmt = $db->prepare("SELECT id FROM winks WHERE from_user_id = ? AND to_user_id = ?");
                    $stmt->execute([$userId, $toUserId]);
                    if ($stmt->fetch()) {
                        jsonResponse(true, ['message' => 'Wink already sent!']);
                    }
                    
                    $db->prepare("INSERT INTO winks (from_user_id, to_user_id, created_at) VALUES (?, ?, NOW())")->execute([$userId, $toUserId]);
                    
                    // Create notification
                    $db->prepare("INSERT INTO notifications (user_id, from_user_id, type, created_at) VALUES (?, ?, 'wink', NOW())")->execute([$toUserId, $userId]);
                    
                    jsonResponse(true, ['message' => 'Wink sent!']);
                    break;
                    
                case 'get-winks':
                    // Check if user is authenticated
                    if (!isset($_SESSION['user_id'])) {
                        jsonResponse(false, null, 'Not authenticated - please login', 401);
                    }
                    
                    $userId = $_SESSION['user_id'];
                    
                    $stmt = $db->prepare("
                        SELECT w.*, u.username, p.display_name, p.avatar_url, u.is_online,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                        FROM winks w
                        JOIN users u ON w.from_user_id = u.id
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE w.to_user_id = ?
                        ORDER BY w.created_at DESC
                        LIMIT 50
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['winks' => $stmt->fetchAll()]);
                    break;
                    
                case 'toggle-favorite':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $favUserId = intval($input['user_id'] ?? 0);
                    
                    if (!$favUserId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("SELECT id FROM favorites WHERE user_id = ? AND favorited_user_id = ?");
                    $stmt->execute([$userId, $favUserId]);
                    
                    if ($stmt->fetch()) {
                        $db->prepare("DELETE FROM favorites WHERE user_id = ? AND favorited_user_id = ?")->execute([$userId, $favUserId]);
                        jsonResponse(true, ['is_favorited' => false]);
                    } else {
                        $db->prepare("INSERT INTO favorites (user_id, favorited_user_id, created_at) VALUES (?, ?, NOW())")->execute([$userId, $favUserId]);
                        
                        // Create notification for being favorited
                        $db->prepare("INSERT INTO notifications (user_id, from_user_id, type, created_at) VALUES (?, ?, 'favorite', NOW())")->execute([$favUserId, $userId]);
                        
                        jsonResponse(true, ['is_favorited' => true]);
                    }
                    break;
                    
                case 'get-favorites':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT f.*, u.username, p.display_name, p.avatar_url, u.is_online,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                        FROM favorites f
                        JOIN users u ON f.favorited_user_id = u.id
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE f.user_id = ?
                        ORDER BY f.created_at DESC
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['favorites' => $stmt->fetchAll()]);
                    break;
                    
                case 'get-profile-views':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT pv.*, u.username, p.display_name, p.avatar_url, u.is_online,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                        FROM profile_views pv
                        JOIN users u ON pv.viewer_id = u.id
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE pv.viewed_user_id = ?
                        ORDER BY pv.viewed_at DESC
                        LIMIT 50
                    ");
                    $stmt->execute([$userId]);
                    $views = $stmt->fetchAll();
                    
                    // Get stats
                    $statsStmt = $db->prepare("
                        SELECT 
                            COUNT(CASE WHEN viewed_at > DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as today,
                            COUNT(CASE WHEN viewed_at > DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as week,
                            COUNT(*) as total
                        FROM profile_views WHERE viewed_user_id = ?
                    ");
                    $statsStmt->execute([$userId]);
                    $stats = $statsStmt->fetch();
                    
                    jsonResponse(true, ['profile_views' => $views, 'stats' => $stats]);
                    break;
                    
                case 'get-unread-counts':
                    $userId = requireAuth();
                    
                    $msgStmt = $db->prepare("SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0");
                    $msgStmt->execute([$userId]);
                    $msgCount = $msgStmt->fetchColumn();
                    
                    $notifStmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
                    $notifStmt->execute([$userId]);
                    $notifCount = $notifStmt->fetchColumn();
                    
                    $winkStmt = $db->prepare("SELECT COUNT(*) FROM winks WHERE to_user_id = ? AND is_read = 0");
                    $winkStmt->execute([$userId]);
                    $winkCount = $winkStmt->fetchColumn();
                    
                    jsonResponse(true, [
                        'messages' => intval($msgCount),
                        'notifications' => intval($notifCount),
                        'winks' => intval($winkCount)
                    ]);
                    break;
                    
                case 'block-user':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $blockedId = intval($input['blocked_id'] ?? 0);
                    $reason = sanitize($input['reason'] ?? '');
                    
                    if (!$blockedId) jsonResponse(false, null, 'User ID required');
                    if ($blockedId === $userId) jsonResponse(false, null, 'Cannot block yourself');
                    
                    try {
                        $stmt = $db->prepare("INSERT INTO blocked_users (blocker_id, blocked_id, reason, created_at) VALUES (?, ?, ?, NOW())");
                        $stmt->execute([$userId, $blockedId, $reason]);
                        jsonResponse(true, ['message' => 'User blocked']);
                    } catch (PDOException $e) {
                        if ($e->getCode() == 23000) {
                            jsonResponse(false, null, 'User already blocked');
                        } else {
                            throw $e;
                        }
                    }
                    break;
                    
                case 'unblock-user':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $blockedId = intval($input['blocked_id'] ?? 0);
                    
                    if (!$blockedId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?");
                    $stmt->execute([$userId, $blockedId]);
                    
                    jsonResponse(true, ['message' => 'User unblocked']);
                    break;
                    
                case 'get-blocked-users':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT bu.*, u.username
                        FROM blocked_users bu
                        JOIN users u ON bu.blocked_id = u.id
                        WHERE bu.blocker_id = ?
                        ORDER BY bu.created_at DESC
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['blocked' => $stmt->fetchAll()]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown social action', 404);
            }
            break;
            
        // ==========================================
        // NOTIFICATIONS ENDPOINTS
        // ==========================================
        case 'notifications':
            switch ($action) {
                case 'list':
                    $userId = requireAuth();
                    $filter = sanitize($_GET['filter'] ?? 'all');
                    
                    // Build WHERE clause based on filter
                    $whereClause = "n.user_id = ?";
                    if ($filter === 'messages') {
                        $whereClause .= " AND n.type = 'message'";
                    } elseif ($filter === 'views') {
                        $whereClause .= " AND n.type = 'view'";
                    } elseif ($filter === 'social') {
                        $whereClause .= " AND n.type IN ('wink', 'favorite', 'vm_like', 'gift')";
                    }
                    
                    $stmt = $db->prepare("
                        SELECT n.*, u.username as from_username
                        FROM notifications n
                        LEFT JOIN users u ON n.from_user_id = u.id
                        WHERE $whereClause
                        ORDER BY n.created_at DESC
                        LIMIT 50
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['notifications' => $stmt->fetchAll()]);
                    break;
                    
                case 'count':
                    $userId = requireAuth();
                    
                    // Get unread notification count
                    $notifStmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
                    $notifStmt->execute([$userId]);
                    $notifCount = $notifStmt->fetchColumn();
                    
                    // Get unread message count
                    $msgStmt = $db->prepare("SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0");
                    $msgStmt->execute([$userId]);
                    $msgCount = $msgStmt->fetchColumn();
                    
                    jsonResponse(true, [
                        'unread_count' => intval($notifCount),
                        'unread_messages' => intval($msgCount)
                    ]);
                    break;
                    
                case 'mark-read':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $db->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0")->execute([$userId]);
                    
                    jsonResponse(true, ['message' => 'Notifications marked as read']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown notifications action', 404);
            }
            break;
            
        // ==========================================
        // CHAT ROOMS ENDPOINTS
        // ==========================================
        case 'chat-rooms':
            switch ($action) {
                case 'list':
                    $stmt = $db->query("
                        SELECT cr.*, 
                               (SELECT COUNT(DISTINCT user_id) FROM chat_room_members WHERE room_id = cr.id AND last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)) as active_users
                        FROM chat_rooms cr
                        WHERE cr.is_active = 1
                        ORDER BY cr.id ASC
                    ");
                    jsonResponse(true, ['rooms' => $stmt->fetchAll()]);
                    break;
                    
                case 'join':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $roomId = intval($input['room_id'] ?? 0);
                    
                    $db->prepare("INSERT INTO chat_room_members (room_id, user_id, last_seen) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW()")->execute([$roomId, $userId]);
                    
                    jsonResponse(true, ['message' => 'Joined room']);
                    break;
                    
                case 'messages':
                    $userId = requireAuth();
                    $roomId = intval($_GET['room_id'] ?? 0);
                    $since = intval($_GET['since_id'] ?? 0);
                    
                    if ($since > 0) {
                        $stmt = $db->prepare("
                            SELECT crm.*, u.username, p.display_name, p.avatar_url,
                                   (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                            FROM chat_room_messages crm
                            JOIN users u ON crm.user_id = u.id
                            LEFT JOIN profiles p ON p.user_id = u.id
                            WHERE crm.room_id = ? AND crm.id > ?
                            ORDER BY crm.created_at ASC
                            LIMIT 50
                        ");
                        $stmt->execute([$roomId, $since]);
                    } else {
                        $stmt = $db->prepare("
                            SELECT crm.*, u.username, p.display_name, p.avatar_url,
                                   (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                            FROM chat_room_messages crm
                            JOIN users u ON crm.user_id = u.id
                            LEFT JOIN profiles p ON p.user_id = u.id
                            WHERE crm.room_id = ?
                            ORDER BY crm.created_at DESC
                            LIMIT 50
                        ");
                        $stmt->execute([$roomId]);
                    }
                    
                    $messages = $stmt->fetchAll();
                    if ($since == 0) {
                        $messages = array_reverse($messages);
                    }
                    
                    jsonResponse(true, ['messages' => $messages]);
                    break;
                    
                case 'send':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $roomId = intval($input['room_id'] ?? 0);
                    $message = sanitize($input['message'] ?? '');
                    
                    if (empty($message)) jsonResponse(false, null, 'Message required');
                    
                    $stmt = $db->prepare("INSERT INTO chat_room_messages (room_id, user_id, message_text, created_at) VALUES (?, ?, ?, NOW())");
                    $stmt->execute([$roomId, $userId, $message]);
                    
                    // Update member last_seen
                    $db->prepare("UPDATE chat_room_members SET last_seen = NOW() WHERE room_id = ? AND user_id = ?")->execute([$roomId, $userId]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId()]);
                    break;
                    
                case 'send-photo':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['photo'])) jsonResponse(false, null, 'No photo uploaded');
                    
                    $roomId = intval($_POST['room_id'] ?? 0);
                    if (!$roomId) jsonResponse(false, null, 'Room ID required');
                    
                    $result = uploadFile($_FILES['photo'], 'messages');
                    if (!$result['success']) jsonResponse(false, null, $result['error']);
                    
                    $stmt = $db->prepare("INSERT INTO chat_room_messages (room_id, user_id, message_text, message_type, created_at) VALUES (?, ?, ?, 'photo', NOW())");
                    $stmt->execute([$roomId, $userId, $result['url']]);
                    
                    // Update member last_seen
                    $db->prepare("UPDATE chat_room_members SET last_seen = NOW() WHERE room_id = ? AND user_id = ?")->execute([$roomId, $userId]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId(), 'url' => $result['url']]);
                    break;
                    
                case 'send-voice':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['voice'])) jsonResponse(false, null, 'No voice message uploaded');
                    
                    $roomId = intval($_POST['room_id'] ?? 0);
                    if (!$roomId) jsonResponse(false, null, 'Room ID required');
                    
                    // Upload voice file
                    $file = $_FILES['voice'];
                    $uploadDir = __DIR__ . '/../uploads/voice/';
                    
                    if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
                    
                    $ext = 'webm';
                    $filename = uniqid('voice_') . '.' . $ext;
                    $filepath = $uploadDir . $filename;
                    
                    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
                        jsonResponse(false, null, 'Failed to save voice message');
                    }
                    
                    $url = '/uploads/voice/' . $filename;
                    
                    $stmt = $db->prepare("INSERT INTO chat_room_messages (room_id, user_id, message_text, message_type, created_at) VALUES (?, ?, ?, 'voice', NOW())");
                    $stmt->execute([$roomId, $userId, $url]);
                    
                    // Update member last_seen
                    $db->prepare("UPDATE chat_room_members SET last_seen = NOW() WHERE room_id = ? AND user_id = ?")->execute([$roomId, $userId]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId(), 'url' => $url]);
                    break;
                    
                case 'delete-message':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    
                    // Verify user owns the message
                    $stmt = $db->prepare("SELECT id FROM chat_room_messages WHERE id = ? AND user_id = ?");
                    $stmt->execute([$messageId, $userId]);
                    
                    if (!$stmt->fetch()) jsonResponse(false, null, 'Message not found or you do not have permission', 403);
                    
                    // Delete the message
                    $db->prepare("DELETE FROM chat_room_messages WHERE id = ?")->execute([$messageId]);
                    
                    jsonResponse(true, ['message' => 'Message deleted']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown chat-rooms action', 404);
            }
            break;
            
        // ==========================================
        // GALLERY ENDPOINTS
        // ==========================================
        case 'gallery':
            switch ($action) {
                case 'list':
                    $category = sanitize($_GET['category'] ?? '');
                    
                    if ($category) {
                        $stmt = $db->prepare("
                            SELECT gp.*, u.username, p.display_name,
                                   (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                            FROM gallery_photos gp
                            JOIN users u ON gp.user_id = u.id
                            LEFT JOIN profiles p ON p.user_id = u.id
                            WHERE gp.category = ?
                            ORDER BY gp.created_at DESC
                            LIMIT 100
                        ");
                        $stmt->execute([$category]);
                        jsonResponse(true, ['photos' => $stmt->fetchAll()]);
                    } else {
                        // Return category counts
                        $stmt = $db->query("
                            SELECT category, COUNT(*) as count
                            FROM gallery_photos
                            GROUP BY category
                        ");
                        $counts = [];
                        while ($row = $stmt->fetch()) {
                            $counts[$row['category']] = $row['count'];
                        }
                        jsonResponse(true, ['counts' => $counts]);
                    }
                    break;
                    
                case 'upload':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['photo'])) jsonResponse(false, null, 'No photo uploaded');
                    
                    $result = uploadFile($_FILES['photo'], 'gallery');
                    if (!$result['success']) jsonResponse(false, null, $result['error']);
                    
                    $category = sanitize($_POST['category'] ?? 'general');
                    $caption = sanitize($_POST['caption'] ?? '');
                    
                    $stmt = $db->prepare("INSERT INTO gallery_photos (user_id, photo_url, category, caption, created_at) VALUES (?, ?, ?, ?, NOW())");
                    $stmt->execute([$userId, $result['url'], $category, $caption]);
                    
                    jsonResponse(true, ['photo_id' => $db->lastInsertId(), 'url' => $result['url']]);
                    break;
                    
                case 'delete':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $photoId = intval($input['photo_id'] ?? 0);
                    
                    if (!$photoId) jsonResponse(false, null, 'Photo ID required');
                    
                    // Verify user owns the photo
                    $stmt = $db->prepare("SELECT id FROM gallery_photos WHERE id = ? AND user_id = ?");
                    $stmt->execute([$photoId, $userId]);
                    
                    if (!$stmt->fetch()) jsonResponse(false, null, 'Photo not found or you do not have permission', 403);
                    
                    // Delete the photo
                    $db->prepare("DELETE FROM gallery_photos WHERE id = ?")->execute([$photoId]);
                    
                    jsonResponse(true, ['message' => 'Photo deleted']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown gallery action', 404);
            }
            break;
            
        // ==========================================
        // STORIES ENDPOINTS
        // ==========================================
        case 'stories':
            switch ($action) {
                case 'list':
                    $category = sanitize($_GET['category'] ?? '');
                    
                    $sql = "SELECT s.*, u.username, p.display_name, p.avatar_url
                            FROM stories s
                            JOIN users u ON s.user_id = u.id
                            LEFT JOIN profiles p ON p.user_id = u.id
                            WHERE 1=1";
                    
                    if ($category) $sql .= " AND s.category = ?";
                    $sql .= " ORDER BY s.created_at DESC LIMIT 50";
                    
                    $stmt = $db->prepare($sql);
                    $stmt->execute($category ? [$category] : []);
                    
                    jsonResponse(true, ['stories' => $stmt->fetchAll()]);
                    break;
                    
                case 'get':
                    $storyId = intval($_GET['story_id'] ?? 0);
                    
                    $stmt = $db->prepare("
                        SELECT s.*, u.username, p.display_name, p.avatar_url
                        FROM stories s
                        JOIN users u ON s.user_id = u.id
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE s.id = ?
                    ");
                    $stmt->execute([$storyId]);
                    $story = $stmt->fetch();
                    
                    if (!$story) jsonResponse(false, null, 'Story not found', 404);
                    
                    // Increment views
                    $db->prepare("UPDATE stories SET view_count = view_count + 1 WHERE id = ?")->execute([$storyId]);
                    
                    jsonResponse(true, ['story' => $story]);
                    break;
                    
                case 'create':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $title = sanitize($input['title'] ?? '');
                    $content = $input['content'] ?? '';
                    $category = sanitize($input['category'] ?? 'general');
                    $tags = sanitize($input['tags'] ?? '');
                    
                    if (empty($content)) jsonResponse(false, null, 'Content required');
                    if (strlen($content) < 100) jsonResponse(false, null, 'Story must be at least 100 characters');
                    
                    $stmt = $db->prepare("INSERT INTO stories (user_id, title, content, category, tags, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                    $stmt->execute([$userId, $title, $content, $category, $tags]);
                    
                    jsonResponse(true, ['story_id' => $db->lastInsertId()]);
                    break;
                    
                case 'delete':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $storyId = intval($input['story_id'] ?? 0);
                    
                    if (!$storyId) jsonResponse(false, null, 'Story ID required');
                    
                    // Verify user owns the story
                    $stmt = $db->prepare("SELECT id FROM stories WHERE id = ? AND user_id = ?");
                    $stmt->execute([$storyId, $userId]);
                    
                    if (!$stmt->fetch()) jsonResponse(false, null, 'Story not found or you do not have permission', 403);
                    
                    // Delete the story
                    $db->prepare("DELETE FROM stories WHERE id = ?")->execute([$storyId]);
                    
                    jsonResponse(true, ['message' => 'Story deleted']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown stories action', 404);
            }
            break;
            
        // ==========================================
        // VOICE MESSAGES ENDPOINTS
        // ==========================================
        case 'voice-messages':
            switch ($action) {
                case 'list':
                    $userId = $_SESSION['user_id'] ?? null;
                    $filter = sanitize($_GET['filter'] ?? 'all');
                    
                    $where = ["vm.is_public = 1"];
                    $params = [];
                    
                    // Apply filters
                    if ($filter === 'mine' && $userId) {
                        $where = ["vm.user_id = ?"];
                        $params[] = $userId;
                    } elseif ($filter === 'liked' && $userId) {
                        $where[] = "EXISTS (SELECT 1 FROM voice_message_likes WHERE message_id = vm.id AND user_id = ?)";
                        $params[] = $userId;
                    } elseif ($filter === 'popular') {
                        // Keep only public filter for popular
                    }
                    
                    // Exclude blocked users
                    if ($userId) {
                        $where[] = "vm.user_id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)";
                        $where[] = "vm.user_id NOT IN (SELECT blocker_id FROM blocked_users WHERE blocked_id = ?)";
                        $params[] = $userId;
                        $params[] = $userId;
                    }
                    
                    $whereClause = implode(' AND ', $where);
                    $orderBy = $filter === 'popular' ? 'vm.plays_count DESC, vm.likes_count DESC' : 'vm.created_at DESC';
                    
                    $sql = "SELECT vm.*, u.username,
                                   " . ($userId ? "(SELECT COUNT(*) FROM voice_message_likes WHERE message_id = vm.id AND user_id = $userId) as is_liked" : "0 as is_liked") . "
                            FROM sexy_voice_messages vm
                            JOIN users u ON vm.user_id = u.id
                            WHERE {$whereClause}
                            ORDER BY {$orderBy}
                            LIMIT 50";
                    
                    $stmt = $db->prepare($sql);
                    $stmt->execute($params);
                    $messages = $stmt->fetchAll();
                    
                    // Get stats
                    $stats = [];
                    if ($userId) {
                        $statsStmt = $db->query("
                            SELECT 
                                (SELECT COUNT(*) FROM sexy_voice_messages WHERE user_id = $userId) as mine,
                                (SELECT SUM(plays_count) FROM sexy_voice_messages WHERE user_id = $userId) as plays,
                                (SELECT SUM(likes_count) FROM sexy_voice_messages WHERE user_id = $userId) as likes,
                                (SELECT COUNT(*) FROM sexy_voice_messages WHERE is_public = 1) as total
                        ");
                        $stats = $statsStmt->fetch();
                    } else {
                        $stats = ['mine' => 0, 'plays' => 0, 'likes' => 0, 'total' => 0];
                    }
                    
                    jsonResponse(true, ['messages' => $messages, 'stats' => $stats]);
                    break;
                    
                case 'upload':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    if (!isset($_FILES['audio'])) jsonResponse(false, null, 'No audio uploaded');
                    
                    // Get the detected MIME type
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $detectedMimeType = finfo_file($finfo, $_FILES['audio']['tmp_name']);
                    finfo_close($finfo);
                    
                    error_log("VOICE UPLOAD: Detected MIME type: {$detectedMimeType}");
                    
                    // Accept ANY audio type OR video/webm (Chrome records audio as video/webm)
                    $isAudio = (strpos($detectedMimeType, 'audio/') === 0) || 
                               ($detectedMimeType === 'application/ogg') ||
                               ($detectedMimeType === 'video/webm');
                    
                    if (!$isAudio) {
                        error_log("VOICE UPLOAD ERROR: Invalid MIME type: {$detectedMimeType}");
                        jsonResponse(false, null, "Invalid file type. Detected: {$detectedMimeType}. Please upload an audio file.");
                    }
                    
                    // Allow multiple audio formats (for reference, but we accept all audio/*)
                    $allowedTypes = [
                        'audio/webm',
                        'audio/ogg',
                        'audio/mpeg',
                        'audio/mp3',
                        'audio/mp4',
                        'audio/m4a',
                        'audio/wav',
                        'audio/x-wav',
                        'audio/wave',
                        'audio/x-m4a',
                        'audio/aac',
                        'audio/flac',
                        'audio/opus',
                        'audio/vorbis',
                        'application/ogg' // Sometimes ogg comes as application
                    ];
                    
                    // Handle upload directly (we've already validated MIME type)
                    $maxSize = 10 * 1024 * 1024; // 10MB
                    if ($_FILES['audio']['size'] > $maxSize) {
                        jsonResponse(false, null, 'File too large (max 10MB)');
                    }
                    
                    $ext = pathinfo($_FILES['audio']['name'], PATHINFO_EXTENSION);
                    $filename = generateToken(16) . '.' . $ext;
                    $uploadDir = UPLOAD_PATH . 'voice_messages/';
                    
                    if (!is_dir($uploadDir)) {
                        mkdir($uploadDir, 0755, true);
                    }
                    
                    $filepath = $uploadDir . $filename;
                    
                    if (!move_uploaded_file($_FILES['audio']['tmp_name'], $filepath)) {
                        error_log("VOICE UPLOAD ERROR: Failed to move uploaded file to {$filepath}");
                        jsonResponse(false, null, 'Upload failed - could not save file');
                    }
                    
                    $audioUrl = UPLOAD_URL . 'voice_messages/' . $filename;
                    error_log("VOICE UPLOAD SUCCESS: {$filepath}");
                    
                    $title = sanitize($_POST['title'] ?? '');
                    $description = sanitize($_POST['description'] ?? '');
                    $isPublic = !empty($_POST['is_public']) ? 1 : 0;
                    $duration = intval($_POST['duration'] ?? 0);
                    
                    if (!$title) jsonResponse(false, null, 'Title required');
                    
                    $stmt = $db->prepare("
                        INSERT INTO sexy_voice_messages 
                        (user_id, title, description, audio_url, duration, is_public, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, NOW())
                    ");
                    $stmt->execute([$userId, $title, $description, $audioUrl, $duration, $isPublic]);
                    
                    jsonResponse(true, ['message_id' => $db->lastInsertId(), 'url' => $audioUrl]);
                    break;
                    
                case 'track-play':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    
                    $stmt = $db->prepare("UPDATE sexy_voice_messages SET plays_count = plays_count + 1 WHERE id = ?");
                    $stmt->execute([$messageId]);
                    
                    jsonResponse(true, ['message' => 'Play tracked']);
                    break;
                    
                case 'toggle-like':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    
                    $stmt = $db->prepare("SELECT id FROM voice_message_likes WHERE message_id = ? AND user_id = ?");
                    $stmt->execute([$messageId, $userId]);
                    
                    if ($stmt->fetch()) {
                        $db->prepare("DELETE FROM voice_message_likes WHERE message_id = ? AND user_id = ?")->execute([$messageId, $userId]);
                        $db->prepare("UPDATE sexy_voice_messages SET likes_count = likes_count - 1 WHERE id = ?")->execute([$messageId]);
                        jsonResponse(true, ['is_liked' => false]);
                    } else {
                        $db->prepare("INSERT INTO voice_message_likes (message_id, user_id, created_at) VALUES (?, ?, NOW())")->execute([$messageId, $userId]);
                        $db->prepare("UPDATE sexy_voice_messages SET likes_count = likes_count + 1 WHERE id = ?")->execute([$messageId]);
                        
                        // Get voice message owner for notification
                        $ownerStmt = $db->prepare("SELECT user_id FROM sexy_voice_messages WHERE id = ?");
                        $ownerStmt->execute([$messageId]);
                        $owner = $ownerStmt->fetch();
                        
                        if ($owner && $owner['user_id'] != $userId) {
                            // Create notification for voice message like
                            $db->prepare("INSERT INTO notifications (user_id, from_user_id, type, created_at) VALUES (?, ?, 'vm_like', NOW())")->execute([$owner['user_id'], $userId]);
                        }
                        
                        jsonResponse(true, ['is_liked' => true]);
                    }
                    break;
                    
                case 'delete':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    
                    // Verify ownership
                    $stmt = $db->prepare("SELECT audio_url FROM sexy_voice_messages WHERE id = ? AND user_id = ?");
                    $stmt->execute([$messageId, $userId]);
                    $message = $stmt->fetch();
                    
                    if (!$message) jsonResponse(false, null, 'Message not found or not yours');
                    
                    // Delete file
                    $filepath = __DIR__ . '/..' . $message['audio_url'];
                    if (file_exists($filepath)) unlink($filepath);
                    
                    // Delete from database
                    $db->prepare("DELETE FROM sexy_voice_messages WHERE id = ?")->execute([$messageId]);
                    
                    jsonResponse(true, ['message' => 'Message deleted']);
                    break;
                    
                case 'edit':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $messageId = intval($input['message_id'] ?? 0);
                    $title = sanitize($input['title'] ?? '');
                    $description = sanitize($input['description'] ?? '');
                    
                    if (!$messageId) jsonResponse(false, null, 'Message ID required');
                    if (!$title) jsonResponse(false, null, 'Title required');
                    
                    // Verify ownership
                    $stmt = $db->prepare("SELECT id FROM sexy_voice_messages WHERE id = ? AND user_id = ?");
                    $stmt->execute([$messageId, $userId]);
                    if (!$stmt->fetch()) jsonResponse(false, null, 'Message not found or not yours');
                    
                    $stmt = $db->prepare("UPDATE sexy_voice_messages SET title = ?, description = ?, updated_at = NOW() WHERE id = ?");
                    $stmt->execute([$title, $description, $messageId]);
                    
                    jsonResponse(true, ['message' => 'Message updated']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown voice-messages action', 404);
            }
            break;
            
        // ==========================================
        // HOT OR NOT ENDPOINTS
        // ==========================================
        case 'hotornot':
            switch ($action) {
                case 'candidates':
                    $userId = requireAuth();
                    
                    // Get users not yet rated by current user
                    $stmt = $db->prepare("
                        SELECT u.id, u.username, u.gender, u.is_verified,
                               TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) as age,
                               p.display_name, p.avatar_url, p.about_me, p.city,
                               (SELECT photo_url FROM user_photos WHERE user_id = u.id AND is_primary = 1 LIMIT 1) as primary_photo
                        FROM users u
                        LEFT JOIN profiles p ON u.id = p.user_id
                        WHERE u.id != ?
                          AND u.is_banned = 0
                          AND u.id NOT IN (SELECT rated_user_id FROM hotornot_votes WHERE voter_id = ?)
                        ORDER BY RAND()
                        LIMIT 20
                    ");
                    $stmt->execute([$userId, $userId]);
                    
                    jsonResponse(true, ['candidates' => $stmt->fetchAll()]);
                    break;
                    
                case 'vote':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $ratedUserId = intval($input['user_id'] ?? 0);
                    $vote = $input['vote'] ?? ''; // 'hot' or 'nope'
                    
                    if (!$ratedUserId || !in_array($vote, ['hot', 'nope'])) {
                        jsonResponse(false, null, 'Invalid vote');
                    }
                    
                    $db->prepare("INSERT INTO hotornot_votes (voter_id, rated_user_id, vote, created_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE vote = ?, created_at = NOW()")->execute([$userId, $ratedUserId, $vote, $vote]);
                    
                    // Check for mutual 'hot' (match)
                    $isMatch = false;
                    if ($vote === 'hot') {
                        $stmt = $db->prepare("SELECT id FROM hotornot_votes WHERE voter_id = ? AND rated_user_id = ? AND vote = 'hot'");
                        $stmt->execute([$ratedUserId, $userId]);
                        if ($stmt->fetch()) {
                            $isMatch = true;
                            // Create match record
                            $db->prepare("INSERT IGNORE INTO hotornot_matches (user1_id, user2_id, created_at) VALUES (LEAST(?, ?), GREATEST(?, ?), NOW())")->execute([$userId, $ratedUserId, $userId, $ratedUserId]);
                        }
                    }
                    
                    jsonResponse(true, ['is_match' => $isMatch]);
                    break;
                    
                case 'matches':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT 
                            CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END as user_id,
                            u.username,
                            p.display_name,
                            p.avatar_url,
                            u.is_online,
                            m.created_at as matched_at
                        FROM hotornot_matches m
                        JOIN users u ON u.id = CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE m.user1_id = ? OR m.user2_id = ?
                        ORDER BY m.created_at DESC
                    ");
                    $stmt->execute([$userId, $userId, $userId, $userId]);
                    
                    jsonResponse(true, ['matches' => $stmt->fetchAll()]);
                    break;
                    
                case 'stats':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT 
                            COUNT(*) as rated,
                            SUM(CASE WHEN vote = 'hot' THEN 1 ELSE 0 END) as hot,
                            (SELECT COUNT(*) FROM hotornot_matches WHERE user1_id = ? OR user2_id = ?) as matches
                        FROM hotornot_votes
                        WHERE voter_id = ?
                    ");
                    $stmt->execute([$userId, $userId, $userId]);
                    
                    jsonResponse(true, $stmt->fetch());
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown hotornot action', 404);
            }
            break;
            
        // ==========================================
        // GIFTS ENDPOINTS
        // ==========================================
        case 'gifts':
            switch ($action) {
                case 'list':
                    $stmt = $db->query("SELECT * FROM virtual_gifts WHERE is_active = 1 ORDER BY price ASC");
                    jsonResponse(true, ['gifts' => $stmt->fetchAll()]);
                    break;
                    
                case 'send':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $toUserId = intval($input['to_user_id'] ?? 0);
                    $giftId = intval($input['gift_id'] ?? 0);
                    $message = sanitize($input['message'] ?? '');
                    
                    // Get gift info
                    $stmt = $db->prepare("SELECT * FROM virtual_gifts WHERE id = ? AND is_active = 1");
                    $stmt->execute([$giftId]);
                    $gift = $stmt->fetch();
                    
                    if (!$gift) jsonResponse(false, null, 'Gift not found');
                    
                    // Check user coins
                    $stmt = $db->prepare("SELECT coins FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $user = $stmt->fetch();
                    
                    if ($user['coins'] < $gift['price']) {
                        jsonResponse(false, null, 'Not enough coins');
                    }
                    
                    // Deduct coins and send gift
                    $db->prepare("UPDATE users SET coins = coins - ? WHERE id = ?")->execute([$gift['price'], $userId]);
                    $db->prepare("INSERT INTO sent_gifts (from_user_id, to_user_id, gift_id, message, created_at) VALUES (?, ?, ?, ?, NOW())")->execute([$userId, $toUserId, $giftId, $message]);
                    
                    jsonResponse(true, ['message' => 'Gift sent!']);
                    break;
                    
                case 'received':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT sg.*, vg.name as gift_name, vg.icon, vg.price,
                               u.username, p.display_name, p.avatar_url
                        FROM sent_gifts sg
                        JOIN virtual_gifts vg ON sg.gift_id = vg.id
                        JOIN users u ON sg.from_user_id = u.id
                        LEFT JOIN profiles p ON p.user_id = u.id
                        WHERE sg.to_user_id = ?
                        ORDER BY sg.created_at DESC
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['gifts' => $stmt->fetchAll()]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown gifts action', 404);
            }
            break;
            
        // ==========================================
        // NOTIFICATIONS ENDPOINTS
        // ==========================================
        case 'notifications':
            switch ($action) {
                case 'list':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT n.*
                        FROM notifications n
                        WHERE n.user_id = ?
                        ORDER BY n.created_at DESC
                        LIMIT 50
                    ");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['notifications' => $stmt->fetchAll()]);
                    break;
                    
                case 'read':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $notifId = intval($input['notification_id'] ?? 0);
                    
                    if ($notifId) {
                        $db->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?")->execute([$notifId, $userId]);
                    } else {
                        $db->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?")->execute([$userId]);
                    }
                    
                    jsonResponse(true, ['message' => 'Marked as read']);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown notifications action', 404);
            }
            break;
            
        // ==========================================
        // ADMIN ENDPOINTS
        // ==========================================
        case 'admin':
            $userId = requireAuth();
            
            // Check if user is admin
            $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if (!$user || !$user['is_admin']) {
                jsonResponse(false, null, 'Access denied. Admin privileges required.', 403);
            }
            
            switch ($action) {
                case 'stats':
                    // Get platform statistics
                    $stats = [];
                    
                    $stats['total_users'] = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
                    $stats['online_users'] = $db->query("SELECT COUNT(*) FROM users WHERE is_online = 1")->fetchColumn();
                    $stats['banned_users'] = $db->query("SELECT COUNT(*) FROM users WHERE is_banned = 1")->fetchColumn();
                    $stats['total_messages'] = $db->query("SELECT COUNT(*) FROM messages")->fetchColumn();
                    $stats['total_stories'] = $db->query("SELECT COUNT(*) FROM stories")->fetchColumn();
                    $stats['total_photos'] = $db->query("SELECT COUNT(*) FROM gallery_photos")->fetchColumn();
                    
                    jsonResponse(true, ['stats' => $stats]);
                    break;
                    
                case 'activity':
                    // Get recent user activity
                    $stmt = $db->query("
                        SELECT u.username, 'Joined' as action, u.created_at
                        FROM users u
                        ORDER BY u.created_at DESC
                        LIMIT 20
                    ");
                    
                    jsonResponse(true, ['activities' => $stmt->fetchAll()]);
                    break;
                    
                case 'users':
                    // Get all users
                    $stmt = $db->query("
                        SELECT u.id, u.username, u.email, u.is_online, u.is_banned, 
                               u.subscription_type, u.created_at, u.last_login
                        FROM users u
                        ORDER BY u.created_at DESC
                    ");
                    
                    jsonResponse(true, ['users' => $stmt->fetchAll()]);
                    break;
                    
                case 'edit-user':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $targetUserId = intval($input['user_id'] ?? 0);
                    $newUsername = sanitize($input['username'] ?? '');
                    
                    if (!$targetUserId || !$newUsername) {
                        jsonResponse(false, null, 'User ID and username required');
                    }
                    
                    $stmt = $db->prepare("UPDATE users SET username = ? WHERE id = ?");
                    $stmt->execute([$newUsername, $targetUserId]);
                    
                    jsonResponse(true, ['message' => 'User updated']);
                    break;
                    
                case 'ban-user':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $targetUserId = intval($input['user_id'] ?? 0);
                    $reason = sanitize($input['reason'] ?? 'Violated terms of service');
                    
                    if (!$targetUserId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("UPDATE users SET is_banned = 1 WHERE id = ?");
                    $stmt->execute([$targetUserId]);
                    
                    // Log the ban
                    $db->prepare("INSERT INTO admin_actions (admin_id, action_type, target_user_id, reason, created_at) VALUES (?, 'ban', ?, ?, NOW())")
                       ->execute([$userId, $targetUserId, $reason]);
                    
                    jsonResponse(true, ['message' => 'User banned']);
                    break;
                    
                case 'unban-user':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $targetUserId = intval($input['user_id'] ?? 0);
                    
                    if (!$targetUserId) jsonResponse(false, null, 'User ID required');
                    
                    $stmt = $db->prepare("UPDATE users SET is_banned = 0 WHERE id = ?");
                    $stmt->execute([$targetUserId]);
                    
                    jsonResponse(true, ['message' => 'User unbanned']);
                    break;
                    
                case 'delete-user':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $targetUserId = intval($input['user_id'] ?? 0);
                    
                    if (!$targetUserId) jsonResponse(false, null, 'User ID required');
                    
                    // Delete user (CASCADE will delete related data)
                    $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
                    $stmt->execute([$targetUserId]);
                    
                    jsonResponse(true, ['message' => 'User deleted']);
                    break;
                    
                case 'grant-premium':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $targetUserId = intval($input['user_id'] ?? 0);
                    $durationMonths = intval($input['duration_months'] ?? 12);
                    $reason = sanitize($input['reason'] ?? 'Admin grant');
                    
                    if (!$targetUserId) jsonResponse(false, null, 'User ID required');
                    
                    // Update user to premium
                    $stmt = $db->prepare("UPDATE users SET subscription_type = 'premium' WHERE id = ?");
                    $stmt->execute([$targetUserId]);
                    
                    // Log the grant in transactions table
                    $transactionData = json_encode([
                        'granted_by_admin' => $userId,
                        'duration_months' => $durationMonths,
                        'reason' => $reason,
                        'expires_at' => $durationMonths === 999 ? 'Never' : date('Y-m-d', strtotime("+{$durationMonths} months"))
                    ]);
                    
                    $stmt = $db->prepare("
                        INSERT INTO transactions 
                        (user_id, subscription_id, plan_name, amount, status, transaction_data, created_at) 
                        VALUES (?, ?, ?, ?, 'completed', ?, NOW())
                    ");
                    $stmt->execute([
                        $targetUserId, 
                        'ADMIN_GRANT_' . time(), 
                        'Premium - Admin Grant (' . ($durationMonths === 999 ? 'Lifetime' : $durationMonths . ' months') . ')', 
                        0.00, 
                        $transactionData
                    ]);
                    
                    // Log admin action
                    $stmt = $db->prepare("
                        INSERT INTO admin_actions 
                        (admin_id, action_type, target_user_id, reason) 
                        VALUES (?, 'grant_premium', ?, ?)
                    ");
                    $stmt->execute([$userId, $targetUserId, $reason]);
                    
                    jsonResponse(true, ['message' => 'Premium granted']);
                    break;
                    
                case 'create-user':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $username = sanitize($input['username'] ?? '');
                    $email = sanitize($input['email'] ?? '');
                    $password = $input['password'] ?? '';
                    $gender = sanitize($input['gender'] ?? '');
                    $dob = sanitize($input['date_of_birth'] ?? '');
                    $subscriptionType = sanitize($input['subscription_type'] ?? 'free');
                    $isAdmin = !empty($input['is_admin']) ? 1 : 0;
                    
                    // Validate required fields
                    if (!$username || !$email || !$password) {
                        jsonResponse(false, null, 'Username, email and password are required');
                    }
                    
                    if (strlen($password) < 6) {
                        jsonResponse(false, null, 'Password must be at least 6 characters');
                    }
                    
                    // Check if username exists
                    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    if ($stmt->fetch()) {
                        jsonResponse(false, null, 'Username already taken');
                    }
                    
                    // Check if email exists
                    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    if ($stmt->fetch()) {
                        jsonResponse(false, null, 'Email already registered');
                    }
                    
                    // Hash password
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                    
                    // Create user
                    $stmt = $db->prepare("
                        INSERT INTO users 
                        (username, email, password_hash, gender, date_of_birth, subscription_type, is_admin, is_verified, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, NOW())
                    ");
                    $stmt->execute([$username, $email, $passwordHash, $gender, $dob ?: null, $subscriptionType, $isAdmin]);
                    $newUserId = $db->lastInsertId();
                    
                    // Create profile
                    $stmt = $db->prepare("
                        INSERT INTO profiles 
                        (user_id, display_name, created_at) 
                        VALUES (?, ?, NOW())
                    ");
                    $stmt->execute([$newUserId, $username]);
                    
                    // Log admin action
                    $stmt = $db->prepare("
                        INSERT INTO admin_actions 
                        (admin_id, action_type, target_user_id, reason) 
                        VALUES (?, 'create_user', ?, ?)
                    ");
                    $stmt->execute([$userId, $newUserId, 'Admin created user']);
                    
                    jsonResponse(true, [
                        'message' => 'User created successfully',
                        'user_id' => $newUserId,
                        'username' => $username
                    ]);
                    break;
                    
                case 'rooms':
                    // Get all chat rooms
                    $stmt = $db->query("
                        SELECT cr.*, 
                               (SELECT COUNT(*) FROM chat_room_members WHERE room_id = cr.id) as member_count,
                               (SELECT COUNT(*) FROM chat_room_messages WHERE room_id = cr.id) as message_count,
                               (SELECT COUNT(*) FROM chat_room_members crm 
                                JOIN users u ON u.id = crm.user_id 
                                WHERE crm.room_id = cr.id AND u.is_online = 1) as online_count
                        FROM chat_rooms cr
                        ORDER BY cr.created_at DESC
                    ");
                    
                    jsonResponse(true, ['rooms' => $stmt->fetchAll()]);
                    break;
                    
                case 'create-room':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $name = sanitize($input['name'] ?? '');
                    $description = sanitize($input['description'] ?? '');
                    
                    if (!$name) jsonResponse(false, null, 'Room name required');
                    
                    $stmt = $db->prepare("INSERT INTO chat_rooms (name, description, created_at) VALUES (?, ?, NOW())");
                    $stmt->execute([$name, $description]);
                    
                    jsonResponse(true, ['room_id' => $db->lastInsertId()]);
                    break;
                    
                case 'edit-room':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $roomId = intval($input['room_id'] ?? 0);
                    $name = sanitize($input['name'] ?? '');
                    $description = sanitize($input['description'] ?? '');
                    
                    if (!$roomId || !$name) jsonResponse(false, null, 'Room ID and name required');
                    
                    $stmt = $db->prepare("UPDATE chat_rooms SET name = ?, description = ? WHERE id = ?");
                    $stmt->execute([$name, $description, $roomId]);
                    
                    jsonResponse(true, ['message' => 'Room updated']);
                    break;
                    
                case 'delete-room':
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $roomId = intval($input['room_id'] ?? 0);
                    
                    if (!$roomId) jsonResponse(false, null, 'Room ID required');
                    
                    // Delete room (CASCADE will delete messages and members)
                    $stmt = $db->prepare("DELETE FROM chat_rooms WHERE id = ?");
                    $stmt->execute([$roomId]);
                    
                    jsonResponse(true, ['message' => 'Room deleted']);
                    break;
                    
                case 'content':
                    $type = sanitize($_GET['type'] ?? 'messages');
                    
                    if ($type === 'stories') {
                        $stmt = $db->query("
                            SELECT s.*, u.username
                            FROM stories s
                            JOIN users u ON s.user_id = u.id
                            ORDER BY s.created_at DESC
                            LIMIT 100
                        ");
                    } elseif ($type === 'gallery') {
                        $stmt = $db->query("
                            SELECT gp.*, u.username
                            FROM gallery_photos gp
                            JOIN users u ON gp.user_id = u.id
                            ORDER BY gp.created_at DESC
                            LIMIT 100
                        ");
                    } else {
                        $stmt = $db->query("
                            SELECT m.*, u.username
                            FROM messages m
                            JOIN users u ON m.sender_id = u.id
                            ORDER BY m.created_at DESC
                            LIMIT 100
                        ");
                    }
                    
                    jsonResponse(true, ['content' => $stmt->fetchAll()]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown admin action', 404);
            }
            break;
            
        // ==========================================
        // PAYMENTS ENDPOINTS (PayPal)
        // ==========================================
        case 'payments':
            switch ($action) {
                case 'verify-subscription':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    $input = getInput();
                    $subscriptionId = sanitize($input['subscription_id'] ?? '');
                    $planName = sanitize($input['plan_name'] ?? '');
                    $planPrice = floatval($input['plan_price'] ?? 0);
                    $billingPeriod = sanitize($input['billing_period'] ?? 'Monthly');
                    
                    if (!$subscriptionId || !$planName) {
                        jsonResponse(false, null, 'Subscription data required');
                    }
                    
                    // In production, verify subscription with PayPal API
                    // For now, we'll trust the frontend data
                    
                    // Update user subscription
                    $stmt = $db->prepare("UPDATE users SET subscription_type = ? WHERE id = ?");
                    $stmt->execute([strtolower($planName), $userId]);
                    
                    // Log transaction with billing period
                    $transactionData = json_encode([
                        'billing_period' => $billingPeriod,
                        'subscription_id' => $subscriptionId
                    ]);
                    
                    $stmt = $db->prepare("
                        INSERT INTO transactions 
                        (user_id, subscription_id, plan_name, amount, status, transaction_data, created_at) 
                        VALUES (?, ?, ?, ?, 'completed', ?, NOW())
                    ");
                    $stmt->execute([$userId, $subscriptionId, $planName . ' - ' . $billingPeriod, $planPrice, $transactionData]);
                    
                    jsonResponse(true, ['message' => 'Subscription activated']);
                    break;
                    
                case 'cancel-subscription':
                    $userId = requireAuth();
                    if ($method !== 'POST') jsonResponse(false, null, 'Method not allowed', 405);
                    
                    // Get user's current subscription
                    $stmt = $db->prepare("SELECT subscription_id FROM transactions WHERE user_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1");
                    $stmt->execute([$userId]);
                    $transaction = $stmt->fetch();
                    
                    if (!$transaction) {
                        jsonResponse(false, null, 'No active subscription found');
                    }
                    
                    // In production, cancel subscription via PayPal API
                    // For now, just update database
                    
                    $stmt = $db->prepare("UPDATE users SET subscription_type = 'free' WHERE id = ?");
                    $stmt->execute([$userId]);
                    
                    jsonResponse(true, ['message' => 'Subscription cancelled']);
                    break;
                    
                case 'history':
                    $userId = requireAuth();
                    
                    $stmt = $db->prepare("
                        SELECT * FROM transactions 
                        WHERE user_id = ? 
                        ORDER BY created_at DESC 
                        LIMIT 50
                    ");
                    $stmt->execute([$userId]);
                    $transactions = $stmt->fetchAll();
                    
                    jsonResponse(true, ['transactions' => $transactions]);
                    break;
                    
                case 'webhook':
                    // PayPal webhook endpoint for IPN (Instant Payment Notification)
                    // Verify webhook signature and process payment events
                    
                    $webhookData = file_get_contents('php://input');
                    $webhookJson = json_decode($webhookData, true);
                    
                    // Log webhook for debugging
                    error_log("PayPal Webhook: " . $webhookData);
                    
                    // In production, verify webhook signature with PayPal
                    // Then process based on event_type
                    
                    if (isset($webhookJson['event_type'])) {
                        $eventType = $webhookJson['event_type'];
                        
                        if ($eventType === 'BILLING.SUBSCRIPTION.ACTIVATED') {
                            // Subscription activated
                            // Update user subscription status
                        } elseif ($eventType === 'BILLING.SUBSCRIPTION.CANCELLED') {
                            // Subscription cancelled
                            // Update user subscription status
                        } elseif ($eventType === 'PAYMENT.SALE.COMPLETED') {
                            // Payment completed
                            // Log transaction
                        }
                    }
                    
                    http_response_code(200);
                    echo json_encode(['status' => 'received']);
                    exit;
                    break;
                    
                case 'admin-transactions':
                    $userId = requireAuth();
                    
                    // Check if user is admin
                    $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $user = $stmt->fetch();
                    
                    if (!$user || !$user['is_admin']) {
                        jsonResponse(false, null, 'Access denied. Admin privileges required.', 403);
                    }
                    
                    // Get all transactions
                    $stmt = $db->query("
                        SELECT t.*, u.username, u.email
                        FROM transactions t
                        JOIN users u ON t.user_id = u.id
                        ORDER BY t.created_at DESC
                        LIMIT 100
                    ");
                    $transactions = $stmt->fetchAll();
                    
                    jsonResponse(true, ['transactions' => $transactions]);
                    break;
                    
                default:
                    jsonResponse(false, null, 'Unknown payments action', 404);
            }
            break;
            
        default:
            jsonResponse(false, null, 'Unknown endpoint', 404);
    }
    
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    jsonResponse(false, null, 'Server error: ' . $e->getMessage(), 500);
}
