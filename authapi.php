<?php
require_once 'jwt_utils.php';
require_once 'database.php'; // Assurez-vous d’avoir un fichier pour la connexion BD

header("Content-Type: application/json; charset=utf-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Authorization, Content-Type");

$http_method = $_SERVER['REQUEST_METHOD'];

if ($http_method == "OPTIONS") {
    http_response_code(200);
    exit();
}

if ($http_method !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Méthode non autorisée"]);
    exit();
}

// Récupération des données envoyées
$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['login']) || !isset($input['password'])) {
    http_response_code(400);
    echo json_encode(["error" => "Login et mot de passe requis"]);
    exit();
}

$login = $input['login'];
$password = $input['password'];
try {
    // Connexion à la base de données
    $pdo = Database::getInstance();

    // Vérifier si l'utilisateur existe
    $stmt = $pdo->prepare("SELECT * FROM utilisateur WHERE login = :login");
    $stmt->bindParam(':login', $login);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || hash('sha256', $password) !== $user['password']) {
        http_response_code(403);
        echo json_encode(["error" => "Identifiants incorrects"]);
        exit();
    }

    // Création du token JWT
    $secret_key = "cle_secrete"; // Remplace par ta vraie clé secrète
    $headers = ["alg" => "HS256", "typ" => "JWT"];
    $payload = [
        "user_id" => $user['id'],
        "login" => $user['login'],
        "role" => $user['role'],
        "exp" => time() + 3600 // Expiration dans 1 heure
    ];

    $jwt = generate_jwt($headers, $payload, $secret_key);

    // Réponse avec le token
    echo json_encode(["token" => $jwt]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Erreur serveur : " . $e->getMessage()]);
}

?>
