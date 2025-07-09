<?php
session_start();
require 'db.php';

function sanitize($data) {
    return htmlspecialchars(trim($data));
}

$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $name = sanitize($_POST['name']);
    $id_number = sanitize($_POST['id_number']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $security_phrase = strtolower(sanitize($_POST['security_phrase']));
    $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';

    // Name
    if (empty($name)) {
        $errors[] = "Name is required.";
    } elseif (!preg_match('/^[a-zA-Z\s]+$/', $name)) {
        $errors[] = "Name can only contain letters and spaces.";
    } elseif (strlen($name) > 100) {
        $errors[] = "Name must not exceed 100 characters.";
    }

    // ID Number
    if (empty($id_number)) {
        $errors[] = "ID Number is required.";
    } elseif (!preg_match('/^\d{12}$/', $id_number)) {
        $errors[] = "ID Number must be exactly 12 digits.";
    } else {
        $year = substr($id_number, 0, 4);
        if ((int)$year <= 2020) {
            $errors[] = "Only users enrolled after 2020 are allowed.";
        }
    }

    // Email
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    // Password
    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$/', $password)) {
        $errors[] = "Password must include uppercase, lowercase, number, special character, and be at least 8 characters.";
    }

    // Confirm Password
    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    // Security Phrase
    if (empty($security_phrase)) {
        $errors[] = "Security phrase is required.";
    } elseif (strlen($security_phrase) > 50) {
        $errors[] = "Security phrase must not exceed 50 characters.";
    } else {
        $stmt_check_phrase = $conn->prepare("SELECT id FROM users WHERE LOWER(security_phrase) = ?");
        $stmt_check_phrase->bind_param("s", $security_phrase);
        $stmt_check_phrase->execute();
        $stmt_check_phrase->store_result();

        if ($stmt_check_phrase->num_rows > 0) {
            $errors[] = "Security phrase already taken. Choose a different one.";
        }
        $stmt_check_phrase->close();
    }

    // reCAPTCHA
    $secret_key = '6LdK7GIrAAAAACDBNmxqXHMCTzeinocP3IWotRkY';
    $verify_response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secret_key&response=$recaptcha_response");
    $response_data = json_decode($verify_response);

    if (!$response_data->success) {
        $errors[] = "reCAPTCHA verification failed.";
    }

    // Insert into DB
    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (name, id_number, email, password_hash, security_phrase) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $name, $id_number, $email, $password_hash, $security_phrase);

        if ($stmt->execute()) {
            $_SESSION['success_message'] = "Registration successful! You can now log in.";
            $stmt->close();
            $conn->close();
            header("Location: login.php");
            exit();
        } else {
            if (str_contains($stmt->error, "Duplicate")) {
                $errors[] = "Email or ID Number already exists.";
            } else {
                $errors[] = "Error: " . $stmt->error;
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Registration</title>
    <link rel="stylesheet" href="style.css">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">

    <style>
        .container {
            max-width: 500px;
            margin: 50px auto;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }

        label { font-weight: bold; }

        input {
            width: 100%;
            padding: 10px;
            margin: 6px 0 12px;
            border: 2px solid #ccc;
            border-radius: 5px;
        }

        .error-message { color: red; font-size: 0.8em; display: none; }
        .error-message.show { display: block; }
        input.invalid { border: 2px solid red; }
        input.valid { border: 2px solid green; }

        .alert-error {
            background-color: #f87171;
            color: white;
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.95em;
        }

        .alert-error i {
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

        button {
            padding: 12px;
            width: 100%;
            background-color: #2563eb;
            border: none;
            color: white;
            font-weight: bold;
            border-radius: 6px;
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
    </style>
</head>
<body>

<div class="container">
    <h2>User Registration</h2>

    <?php if (!empty($errors)): ?>
        <div class="alert-error">
            <i class="fa-solid fa-triangle-exclamation"></i>
            Registration failed. Please fix the following:
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?= $error ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form id="registerForm" action="register.php" method="POST" novalidate>
        <label for="name">Full Name:</label>
        <input type="text" name="name" id="name" maxlength="100" pattern="[A-Za-z\s]+" required value="<?= $_POST['name'] ?? '' ?>">
        <div id="nameError" class="error-message">Name must only contain letters and spaces (max 100 characters).</div>

        <label for="id_number">ID Number (e.g: 202202040001):</label>
        <input type="text" name="id_number" id="id_number" pattern="\d{12}" maxlength="12" required value="<?= $_POST['id_number'] ?? '' ?>">
        <div id="idError" class="error-message">ID Number must be exactly 12 digits.</div>

        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required value="<?= $_POST['email'] ?? '' ?>">
        <div id="emailError" class="error-message">Please enter a valid email address.</div>

        <label for="password">Password:</label>
        <input type="password" name="password" id="password"
               pattern="/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$/"
               required>
        <div id="passwordError" class="error-message">
            Password must include uppercase, lowercase, number, special character, and be at least 8 characters.
        </div>

        <label for="confirm_password">Confirm Password:</label>
        <input type="password" name="confirm_password" id="confirm_password" required>
        <div id="confirmError" class="error-message">Passwords do not match.</div>

        <label for="security_phrase">Security Phrase:</label>
        <input type="text" name="security_phrase" id="security_phrase" maxlength="50" required value="<?= $_POST['security_phrase'] ?? '' ?>">

        <div class="g-recaptcha" data-sitekey="6LdK7GIrAAAAAOcWq3JySGkx7AVqKy8N43MGd_LM"></div>

        <br>
        <button type="submit">Register</button>

        <div class="links">
            <p>Already have an account? <a href="login.php">Login here</a></p>
        </div>
    </form>
</div>

<script>
    const fields = [
        { id: "name", pattern: /^[A-Za-z\s]{1,100}$/, error: "nameError" },
        { id: "id_number", pattern: /^\d{12}$/, error: "idError" },
        { id: "email", pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, error: "emailError" },
        { id: "password", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$/, error: "passwordError" }
    ];

    fields.forEach(field => {
        const input = document.getElementById(field.id);
        const errorDiv = document.getElementById(field.error);

        input.addEventListener('input', () => {
            const isValid = field.pattern.test(input.value);
            input.classList.remove('valid', 'invalid');
            if (input.value !== "") {
                input.classList.add(isValid ? 'valid' : 'invalid');
                errorDiv.classList.toggle("show", !isValid);
            } else {
                errorDiv.classList.remove("show");
            }
        });
    });

    const password = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");
    const confirmError = document.getElementById("confirmError");

    confirm.addEventListener("input", () => {
        confirm.classList.remove('valid', 'invalid');
        if (confirm.value !== "") {
            if (confirm.value !== password.value) {
                confirm.classList.add("invalid");
                confirmError.classList.add("show");
                confirm.setCustomValidity("Mismatch");
            } else {
                confirm.classList.add("valid");
                confirmError.classList.remove("show");
                confirm.setCustomValidity("");
            }
        } else {
            confirmError.classList.remove("show");
        }
    });
</script>

</body>
</html>
