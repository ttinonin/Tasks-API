<?php
    require_once('db.php');
    require_once('../model/Response.php');

    try {
        $writeDB = DB::connectWriteDB();
    } catch(PDOException $e) {
        error_log("Connection Error: ".$e, 0);
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Database connection error".$e);
        $response->send();
        exit;
    }

    if($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Request method not allowed");
        $response->send();
        exit;
    }

    if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Contend Type Header not set to JSON");
        $response->send();
        exit;
    }

    $rawPost = file_get_contents('php://input');

    if(!$jsonData = json_decode($rawPost)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Request body is not valid JSON");
        $response->send();
        exit;
    }

    if(!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Please fill out the fields");
        $response->send();
        exit;
    }

    if(strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255 || strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Set values bigger than 1 and lower than 255");
        $response->send();
        exit;
    }

    $fullname = trim($jsonData->fullname);
    $username = trim($jsonData->username);
    $password = $jsonData->password;

    try {
        $query = $writeDB->prepare('SELECT id FROM tblusers WHERE username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if($rowCount !== 0) {
            $response = new Response();
            $response->setHttpStatusCode(409);
            $response->setSuccess(false);
            $response->addMessage("Username already exists");
            $response->send();
            exit;
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $query = $writeDB->prepare('INSERT INTO tblusers (fullname, username, password) VALUES (:fullname, :username, :password)');
        $query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->bindParam(':password', $hashed_password, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if($rowCount === 0){
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("There was an error creating you account");
            $response->send();
            exit;
        }

        $response = new Response();
        $response->setHttpStatusCode(201);
        $response->setSuccess(true);
        $response->addMessage("User account created");
        $response->send();
        exit;
    } catch(PDOException $e) {
        error_log('Database query error: '.$e, 0);
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("There was an error creating you account");
        $response->send();
        exit;
    }
?>