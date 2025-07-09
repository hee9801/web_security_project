<?php
session_start();
require 'db.php';

function sanitize($data) {
    return htmlspecialchars(trim($data));
}

$step = 1;
$errors = [];
$email = "";
$security_phrase = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $step = (int) $_POST['step'];
    $email = sanitize($_POST['email'] ?? '');
    $security_phrase = strtolower(sanitize($_POST['security_phrase'] ?? ''));

    if ($step === 1) {
        if (empty($email) || empty($security_phrase)) {
            $errors[] = "All fields are required.";
        } else {
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND LOWER(security_phrase) = ?");
            $stmt->bind_param("ss", $email, $security_phrase);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 1) {
                $_SESSION['reset_email'] = $email;
                $step = 2;
            } else {
                $errors[] = "Email or security phrase is incorrect.";
            }
            $stmt->close();
        }
    } elseif ($step === 2) {
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];

        if (empty($new_password) || empty($confirm_password)) {
            $errors[] = "All password fields are required.";
        } elseif ($new_password !== $confirm_password) {
            $errors[] = "Passwords do not match.";
        } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$/', $new_password)) {
            $errors[] = "Password must include uppercase, lowercase, number, special character, and be at least 8 characters.";
        } else {
            $email = $_SESSION['reset_email'];
            $new_hash = password_hash($new_password, PASSWORD_DEFAULT);

            $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE email = ?");
            $stmt->bind_param("ss", $new_hash, $email);
            $stmt->execute();
            $stmt->close();

            session_unset();
            session_destroy();

            echo "<div style='max-width:500px;margin:50px auto;padding:20px;background:#dcfce7;border-left:5px solid #16a34a;font-family:sans-serif; border-radius: 5px;'>
                <i class='fa-solid fa-circle-check' style='color:#16a34a;'></i> 
                Password reset successful. <a href='login.php' style='color:#2563eb;'>Click here to login</a>.
            </div>";
            exit();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        .links a {
            color: #2563eb;
            text-decoration: none;
            font-weight: bold;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>Forgot Password</h2>

    <?php if (!empty($errors)): ?>
        <div class="alert-error">
            <i class="fa-solid fa-triangle-exclamation"></i>
            Please fix the following:
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?= $error ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="POST" action="forgot_password.php">
        <?php if ($step === 1): ?>
            <input type="hidden" name="step" value="1">

            <label>Email:</label>
            <input type="email" name="email" value="<?= htmlspecialchars($email) ?>" required>

            <label>Security Phrase:</label>
            <input type="text" name="security_phrase" maxlength="50" required>

        <?php elseif ($step === 2): ?>
            <input type="hidden" name="step" value="2">

            <label>New Password:</label>
            <input type="password" name="new_password" required>
            <div class="error-message" style="margin-top: -10px;">
                Password must include uppercase, lowercase, number, special character, and be at least 8 characters.
            </div>

            <label>Confirm Password:</label>
            <input type="password" name="confirm_password" required>
        <?php endif; ?>

        <button type="submit">Submit</button>

        <div class="links">
            <p><a href="login.php">Back to Login</a></p>
        </div>
    </form>
</div>

</body>
</html>
