<?php
// --- WARNING ---
// THIS IS A DANGEROUS SCRIPT. DELETE IT IMMEDIATELY AFTER USE.
// Leaving this on a live server creates a major security vulnerability.
// --- WARNING ---

$config_file = '/opt/sla_monitor/sla_config.env';
$message = '';

function read_config($file_path) {
    if (!file_exists($file_path) || !is_readable($file_path)) return [];
    return file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

function write_config($file_path, $lines) {
    // Use a temporary file to ensure atomic write
    $temp_file = $file_path . '.tmp';
    if (file_put_contents($temp_file, implode(PHP_EOL, $lines) . PHP_EOL) === false) {
        throw new Exception("Failed to write to temporary config file.");
    }
    if (!rename($temp_file, $file_path)) {
        throw new Exception("Failed to move temporary config file into place.");
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        $message = '<p class="error">Username and password cannot be empty.</p>';
    } else {
        try {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $config_lines = read_config($config_file);
            
            $new_config_lines = [];
            $user_found = false;
            $pass_found = false;

            foreach ($config_lines as $line) {
                if (strpos(trim($line), 'DASHBOARD_USERNAME=') === 0) {
                    $new_config_lines[] = 'DASHBOARD_USERNAME=' . $username;
                    $user_found = true;
                } elseif (strpos(trim($line), 'DASHBOARD_PASSWORD_HASH=') === 0) {
                    $new_config_lines[] = 'DASHBOARD_PASSWORD_HASH=' . $password_hash;
                    $pass_found = true;
                } else {
                    $new_config_lines[] = $line;
                }
            }

            if (!$user_found) {
                $new_config_lines[] = 'DASHBOARD_USERNAME=' . $username;
            }
            if (!$pass_found) {
                $new_config_lines[] = 'DASHBOARD_PASSWORD_HASH=' . $password_hash;
            }

            write_config($config_file, $new_config_lines);
            
            $message = '<p class="success">Admin credentials have been successfully updated. <strong>DELETE THIS FILE NOW!</strong></p>';

        } catch (Exception $e) {
            $message = '<p class="error">Error updating configuration: ' . htmlspecialchars($e->getMessage()) . '</p>';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Admin User</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; }
        .container { background-color: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 400px; border-top: 10px solid #dc3545; }
        h1 { color: #dc3545; margin-bottom: 10px; }
        h2 { font-weight: 300; color: #333; margin-top: 0; margin-bottom: 20px; }
        form input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #e0e0e0; border-radius: 4px; box-sizing: border-box; }
        form button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; transition: background-color 0.3s; }
        form button:hover { background-color: #0056b3; }
        .message { margin-top: 20px; padding: 15px; border-radius: 5px; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SECURITY WARNING</h1>
        <h2>Delete this file (<code>create_admin.php</code>) immediately after use.</h2>
        
        <form action="create_admin.php" method="post">
            <input type="text" name="username" placeholder="New Username" required>
            <input type="password" name="password" placeholder="New Password" required>
            <button type="submit">Set/Update Credentials</button>
        </form>

        <?php if (!empty($message)): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
    </div>
</body>
</html>