<?php
function getDBConnection() {
    $config = require '../config.php';

    try {
        $pdo = new PDO("mysql:host={$config['db']['host']};dbname={$config['db']['name']}", $config['db']['user'], $config['db']['pass'],
            [PDO::ATTR_PERSISTENT => true,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);
        
        return $pdo;
    } catch (PDOException $e) {
        die('Ошибка базы данных.');
    }
}
?>