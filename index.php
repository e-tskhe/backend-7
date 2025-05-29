<?php
header('Content-Type: text/html; charset=UTF-8');
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer-when-downgrade");

session_set_cookie_params([
    'lifetime' => 86400,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();
require_once 'db.php';

function generateLogin()
{
    return 'user_' . substr(md5(uniqid()) , 0, 6) . rand(100, 999);
}

function generatePassword($length = 12)
{
    $hash = md5(uniqid() . rand());
    $uppercase = substr(str_shuffle('ABCDEFGHJKLMNPQRSTUVWXYZ') , 0, 2);
    $lowercase = substr(str_shuffle('abcdefghjkmnpqrstuvwxyz') , 0, 2);
    $numbers = substr(str_shuffle('123456789') , 0, 2);
    $special = substr(str_shuffle('!@#$%^&*') , 0, 2);
    return substr(str_shuffle(substr($hash, 0, $length - 8) . $uppercase . $lowercase . $numbers . $special) , 0, $length);
}

if ($_SERVER['REQUEST_METHOD'] == 'GET')
{
    $messages = array();

    if (!empty($_COOKIE['save']))
    {
        setcookie('save', '', 100000);

        $messages[] = 'Спасибо, результаты сохранены.';
        if (!empty($_COOKIE['password']) && !empty($_COOKIE['login']))
        {
            $messages[] = sprintf('Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong>
        и паролем <strong>%s</strong> для изменения данных.', strip_tags($_COOKIE['login']) , strip_tags($_COOKIE['password']));
        }
    }

    $errors = array();
    $errors['name'] = !empty($_COOKIE['name_error']);
    $errors['phone'] = !empty($_COOKIE['phone_error']);
    $errors['email'] = !empty($_COOKIE['email_error']);
    $errors['gender'] = !empty($_COOKIE['gender_error']);
    $errors['birthdate'] = !empty($_COOKIE['birthdate_error']);
    $errors['languages'] = !empty($_COOKIE['languages_error']);
    $errors['bio'] = !empty($_COOKIE['bio_error']);
    $errors['agreement'] = !empty($_COOKIE['agreement_error']);

    if ($errors['name'])
    {
        setcookie('name_error', '', 100000);
        $messages['name'] = '<div class="error">Заполните имя. Допустимы только буквы и пробелы.</div>';
    }
    if ($errors['phone'])
    {
        setcookie('phone_error', '', 100000);
        $messages['phone'] = '<div class="error">Заполните телефон в формате +7/7/8 и 10 цифр.</div>';
    }
    if ($errors['email'])
    {
        setcookie('email_error', '', 100000);
        $messages['email'] = '<div class="error">Заполните email в правильном формате.</div>';
    }
    if ($errors['birthdate'])
    {
        setcookie('birthdate_error', '', 100000);
        $messages['birthdate'] = '<div class="error">Заполните дату рождения.</div>';
    }
    if ($errors['gender'])
    {
        setcookie('gender_error', '', 100000);
        $messages['gender'] = '<div class="error">Укажите пол.</div>';
    }
    if ($errors['languages'])
    {
        setcookie('languages_error', '', 100000);
        $messages['languages'] = '<div class="error">Выберите хотя бы один язык программирования.</div>';
    }
    if ($errors['bio'])
    {
        setcookie('bio_error', '', 100000);
        $messages['bio'] = '<div class="error">Заполните биографию. Допустимы буквы, цифры и знаки препинания.</div>';
    }
    if ($errors['agreement'])
    {
        setcookie('agreement_error', '', 100000);
        $messages['agreement'] = '<div class="error">Необходимо ваше согласие.</div>';
    }

    $values = array();
    $values['name'] = empty($_COOKIE['name_value']) ? '' : strip_tags($_COOKIE['name_value']);
    $values['phone'] = empty($_COOKIE['phone_value']) ? '' : strip_tags($_COOKIE['phone_value']);
    $values['email'] = empty($_COOKIE['email_value']) ? '' : strip_tags($_COOKIE['email_value']);
    $values['birthdate'] = empty($_COOKIE['birthdate_value']) ? '' : strip_tags($_COOKIE['birthdate_value']);
    $values['gender'] = empty($_COOKIE['gender_value']) ? '' : strip_tags($_COOKIE['gender_value']);
    $values['languages'] = empty($_COOKIE['languages_value']) ? array() : unserialize($_COOKIE['languages_value']);
    $values['bio'] = empty($_COOKIE['bio_value']) ? '' : strip_tags($_COOKIE['bio_value']);
    $values['agreement'] = empty($_COOKIE['agreement_value']) ? '' : strip_tags($_COOKIE['agreement_value']);

    if (!empty($_SESSION['login']))
    {
        try
        {
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("SELECT * FROM application WHERE user_id = ?");
            $stmt->execute([$_SESSION['uid']]);
            $data = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($data)
            {
                $values['name'] = $data['name'];
                $values['phone'] = $data['phone'];
                $values['email'] = $data['email'];
                $values['birthdate'] = $data['birthdate'];
                $values['gender'] = $data['gender'];
                $values['bio'] = $data['bio'];

                $stmt = $pdo->prepare("SELECT pl.name FROM programming_language pl 
                                      JOIN application_language al ON pl.id = al.language_id 
                                      WHERE al.application_id = ?");
                $stmt->execute([$data['id']]);
                $values['languages'] = $stmt->fetchAll(PDO::FETCH_COLUMN);
            }
        }
        catch(PDOException $e)
        {
            $messages[] = 'Ошибка при загрузке данных.';
        }
    }
    include ('form.php');
}
else
{
    verifyCSRFToken();
    $errors = false;
    if (empty($_POST['name']))
    {
        setcookie('name_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('name_value', $_POST['name'], time() + 30 * 24 * 60 * 60);
    }
    if (empty($_POST['phone']))
    {
        setcookie('phone_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    elseif (!preg_match('/^(\+7|7|8)\d{10}$/', $_POST['phone']))
    {
        setcookie('phone_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('phone_value', $_POST['phone'], time() + 30 * 24 * 60 * 60);
    }

    if (empty($_POST['email']))
    {
        setcookie('email_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    elseif (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL))
    {
        setcookie('email_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('email_value', $_POST['email'], time() + 30 * 24 * 60 * 60);
    }
    if (empty($_POST['birthdate']))
    {
        setcookie('birthdate_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('birthdate_value', $_POST['birthdate'], time() + 30 * 24 * 60 * 60);
    }

    if (empty($_POST['gender']))
    {
        setcookie('gender_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('gender_value', $_POST['gender'], time() + 30 * 24 * 60 * 60);
    }

    if (empty($_POST['languages']))
    {
        setcookie('languages_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('languages_value', serialize($_POST['languages']) , time() + 30 * 24 * 60 * 60);
    }
    if (empty($_POST['bio']))
    {
        setcookie('bio_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    elseif (!preg_match('/^[а-яёa-z0-9\s.,!?-]+$/iu', $_POST['bio']))
    {
        setcookie('bio_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('bio_value', $_POST['bio'], time() + 30 * 24 * 60 * 60);
    }

    if (empty($_POST['agreement']))
    {
        setcookie('agreement_error', '1', time() + 24 * 60 * 60);
        $errors = true;
    }
    else
    {
        setcookie('agreement_value', $_POST['agreement'], time() + 30 * 24 * 60 * 60);
    }

    if ($errors)
    {
        header('Location: index.php');
        exit();
    }
    else
    {
        setcookie('name_error', '', 100000);
        setcookie('phone_error', '', 100000);
        setcookie('email_error', '', 100000);
        setcookie('birthdate_error', '', 100000);
        setcookie('gender_error', '', 100000);
        setcookie('languages_error', '', 100000);
        setcookie('bio_error', '', 100000);
        setcookie('agreement_error', '', 100000);
    }

    try
    {
        $pdo = getDBConnection();

        if (!empty($_SESSION['login']))
        {
            $stmt = $pdo->prepare("UPDATE application SET name = ?, phone = ?, email = ?, 
                                 birthdate = ?, gender = ?, bio = ? WHERE user_id = ?");
            $stmt->execute([$_POST['name'], $_POST['phone'], $_POST['email'], $_POST['birthdate'], $_POST['gender'], $_POST['bio'], $_SESSION['uid']]);

            $stmt = $pdo->prepare("DELETE FROM application_language WHERE application_id IN 
                                 (SELECT id FROM application WHERE user_id = ?)");
            $stmt->execute([$_SESSION['uid']]);

            $stmt = $pdo->prepare("SELECT id FROM application WHERE user_id = ?");

            $stmt->execute([$_SESSION['uid']]);

            $appId = $stmt->fetchColumn();

            $langStmt = $pdo->prepare("INSERT INTO programming_language (name) VALUES (?) 
                                      ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)");
            $appLangStmt = $pdo->prepare("INSERT INTO application_language (application_id, language_id) 
                                         VALUES (?, ?)");

            foreach ($_POST['languages'] as $langName)
            {
                $langStmt->execute([$langName]);
                $langId = $pdo->lastInsertId();
                $appLangStmt->execute([$appId, $langId]);
            }
        }
        else
        {
            $login = generateLogin();
            $password = generatePassword();
            $passwordHash = md5($password);

            setcookie('login', $login, time() + 30 * 24 * 60 * 60);
            setcookie('password', $password, time() + 30 * 24 * 60 * 60);

            $userStmt = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
            $userStmt->execute([$login, $passwordHash]);
            $userId = $pdo->lastInsertId();

            $stmt = $pdo->prepare("INSERT INTO application (user_id, name, phone, email, 
                                 birthdate, gender, bio) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$userId, $_POST['name'], $_POST['phone'], $_POST['email'], $_POST['birthdate'], $_POST['gender'], $_POST['bio']]);
            $appId = $pdo->lastInsertId();

            $langStmt = $pdo->prepare("INSERT INTO programming_language (name) VALUES (?) 
                                  ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)");
            $appLangStmt = $pdo->prepare("INSERT INTO application_language (application_id, language_id) 
                                     VALUES (?, ?)");

            foreach ($_POST['languages'] as $langName)
            {
                $langStmt->execute([$langName]);
                $langId = $pdo->lastInsertId();
                $appLangStmt->execute([$appId, $langId]);
            }
        }
        setcookie('save', '1');

        header('Location: index.php');
        exit();

    }
    catch(PDOException $e)
    {
        $messages = array();
        $messages[] = 'Ошибка базы данных.';
        include ('form.php');
    }
}

