<?php

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer-when-downgrade");
header('Content-Type: text/html; charset=UTF-8');


require_once 'db.php';
require_once 'tokens.php';
generateCSRFToken();

if (!empty($_SESSION['login'])) {
    header('Location: index.php');
    exit();
}

$error = '';


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = trim($_POST['login'] ?? '');
    $password = trim($_POST['password'] ?? '');
    if (empty($_POST['login'])) {
        $error = 'Введите логин';
    }
    elseif (empty($_POST['password'])) {
        $error = 'Введите пароль';
    }
    else {
        try {
            $pdo = getDBConnection();

            $stmt = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
            $stmt->execute([$login]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && md5($_POST['password']) === $user['password_hash']) {
                $_SESSION['login'] = $_POST['login'];
                $_SESSION['uid'] = $user['id'];

                header('Location: index.php');
                
                exit();
            } else {
                $error = "Неверный логин или пароль";
            }
        } catch (PDOException $e) {
            $error = "Ошибка базы данных.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Вход в систему</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-section">
        <form method="POST" class="auth-form">
            <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">

            <h3>Вход в систему</h3>
            
            <?php if (!empty($error)): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <div class="form-group">
                <label for="login">Логин:</label>
                <input type="text" id="login" name="login" required 
                       value="<?= !empty($_POST['login']) ? htmlspecialchars($_POST['login']) : '' ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="auth-btn">Войти</button>
            
            <?php if (!empty($_COOKIE['login']) && !empty($_COOKIE['password'])): ?>
                <div class="auth-hint">
                    Ваши данные для входа:<br>
                    Логин: <?= htmlspecialchars($_COOKIE['login']) ?><br>
                    Пароль: <?= htmlspecialchars($_COOKIE['password']) ?>
                </div>
            <?php endif; ?>
            <div class='auth-btn'>
                <a href='admin.php' class='auth-text'>Войти в панель администратора</a>
            </div>
        </form>
    </div>
</body>
</html>