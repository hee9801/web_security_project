<?php
session_start();
require 'db.php';

function sanitize($data) {
    return htmlspecialchars(trim($data));
}

$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = sanitize($_POST['email']);
    $password = $_POST['password'];
    $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';

    if (empty($email) || empty($password)) {
        $errors[] = "Email and password are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($recaptcha_response)) {
        $errors[] = "Please complete the reCAPTCHA.";
    } else {
        $secret_key = '6LdK7GIrAAAAACDBNmxqXHMCTzeinocP3IWotRkY';
        $verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=" . urlencode($secret_key) . "&response=" . urlencode($recaptcha_response));
        $captcha_success = json_decode($verify)->success ?? false;

        if (!$captcha_success) {
            $errors[] = "reCAPTCHA verification failed.";
        }
    }

    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id, name, id_number, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 1) {
    $stmt->bind_result($user_id, $name, $id_number, $password_hash);
    $stmt->fetch();

    if (password_verify($password, $password_hash)) {
        $_SESSION['user_id'] = $user_id;
        $_SESSION['name'] = $name;
        $_SESSION['id_number'] = $id_number;
        $_SESSION['email'] = $email;
        header("Location: dashboard.php");
        exit();
    }
}

// Always show the same message for both cases
$errors[] = "Email or password is incorrect.";


        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    <style>
        .container {
            max-width: 450px;
            margin: 50px auto;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }

        input {
            padding: 10px;
            width: 100%;
            margin-bottom: 10px;
            border-radius: 5px;
            border: 2px solid #ccc;
        }

        .password-wrapper {
            position: relative;
        }

        .toggle-icon {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #999;
        }

        button {
            width: 100%;
            padding: 12px;
            background-color: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
        }

        .links {
            text-align: center;
            margin-top: 15px;
            font-size: 0.9em;
        }

        .links a {
            color: #2563eb;
            text-decoration: none;
            font-weight: bold;
        }

        .alert-error {
            background-color: #f87171;
            color: white;
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.95em;
        }

        .alert-success {
            background-color: #4ade80;
            color: #065f46;
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.95em;
            border: 1px solid #065f46;
        }

        .alert-error i,
        .alert-success i {
            margin-right: 8px;
            font-size: 1.1em;
            vertical-align: middle;
        }

        .alert-error ul {
            margin: 10px 0 0 25px;
            padding-left: 0;
        }

        .alert-error li {
            list-style: disc;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>Login</h2>

    <?php if (!empty($_SESSION['success_message'])): ?>
        <div class="alert-success">
            <i class="fa-solid fa-circle-check"></i>
            <?= $_SESSION['success_message']; ?>
        </div>
        <?php unset($_SESSION['success_message']); ?>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="alert-error">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <strong>Login failed. Please fix the following:</strong>
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?= $error ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form id="loginForm" method="POST" action="login.php" novalidate>
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">

        <label for="password">Password:</label>
        <div class="password-wrapper">
            <input type="password" name="password" id="password" required>
            <i class="fa-solid fa-eye toggle-icon" id="togglePassword"></i>
        </div>

        <div class="g-recaptcha" data-sitekey="6LdK7GIrAAAAAOcWq3JySGkx7AVqKy8N43MGd_LM"></div>

        <br>
        <button type="submit">Login</button>

        <div class="links">
            <p>Don't have an account? <a href="register.php">Register here</a></p>
            <p><a href="forgot_password.php">Forgot Password?</a></p>
        </div>
    </form>
</div>

<script>
    const passwordInput = document.getElementById("password");
    const toggleIcon = document.getElementById("togglePassword");

    toggleIcon.addEventListener("click", () => {
        const type = passwordInput.type === "password" ? "text" : "password";
        passwordInput.type = type;
        toggleIcon.classList.toggle("fa-eye");
        toggleIcon.classList.toggle("fa-eye-slash");
    });
</script>

</body>
</html>
