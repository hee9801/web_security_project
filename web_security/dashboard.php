<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Student Dashboard</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link rel="stylesheet" href="style.css">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, sans-serif;
      margin: 0;
      background: #f1f5f9;
    }

    /* Navbar */
    .navbar {
      background-color: #1d4ed8;
      color: white;
      padding: 15px 30px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .navbar h1 {
      font-size: 1.3rem;
    }

    .navbar a {
      color: white;
      text-decoration: none;
      font-weight: bold;
      background-color: #ef4444;
      padding: 8px 14px;
      border-radius: 6px;
    }

    .navbar a:hover {
      background-color: #dc2626;
    }

    /* Main container */
    .main {
      max-width: 900px;
      margin: 40px auto;
      background: white;
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 5px 15px rgba(0,0,0,0.05);
    }

    .main h2 {
      color: #1d4ed8;
      margin-bottom: 20px;
    }

    .info-card {
      background: #e0f2fe;
      padding: 20px;
      border-radius: 10px;
      margin-bottom: 20px;
    }

    .info-card p {
      font-size: 1.05em;
      margin: 12px 0;
      color: #1e293b;
    }

    .info-card i {
      color: #2563eb;
      margin-right: 10px;
    }

    footer {
      text-align: center;
      padding: 20px;
      font-size: 0.9em;
      color: #6b7280;
    }
  </style>
</head>
<body>

  <div class="navbar">
    <h1><i class="fa-solid fa-user-graduate"></i> Student Dashboard</h1>
    <a href="logout.php" onclick="return confirmLogout();">
      <i class="fa-solid fa-arrow-right-from-bracket"></i> Logout
    </a>
  </div>

  <div class="main">
    <h2>Welcome, <?= htmlspecialchars($_SESSION['name']); ?>!</h2>

    <div class="info-card">
      <p><i class="fa-solid fa-envelope"></i><strong>Email:</strong> <?= htmlspecialchars($_SESSION['email']); ?></p>
      <p><i class="fa-solid fa-id-card"></i><strong>ID Number:</strong> <?= htmlspecialchars($_SESSION['id_number']); ?></p>
    </div>

    <div class="info-card">
      <p><i class="fa-solid fa-circle-info"></i> Need help? Contact your class teacher or system admin.</p>
    </div>
  </div>

  <footer>
    &copy; <?= date('Y'); ?> Student Dashboard. All rights reserved.
  </footer>

  <script>
    function confirmLogout() {
      return confirm("Are you sure you want to logout?");
    }
  </script>

</body>
</html>
