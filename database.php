<?php

class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        // Informations de connexion
        $host = 'mysql-footballmanagerauth.alwaysdata.net';
        $port = '3306';
        $dbname = 'footballmanagerauth_1';
        $username = '406504';
        $password = '$iutinfo';

        // DSN
        $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";

        // Création de l'instance PDO
        $this->pdo = new PDO($dsn, $username, $password);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    //retourne l'instance de la connexion à la base de données
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance->pdo;
    }
}
?>
