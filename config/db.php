<?php

    //on va vérifier si notre session est active
    ob_start();


    //on va être activé
    if(!isset($_SESSION)){
        session_start();
    }

    //connexion à la db (Data Base)
    $host = 'localhost';
    $username = 'root';
    $pwd = '';
    $dbname = 'authentification';
    
    
    $conn = mysqli_connect($host, $username, $pwd, $dbname) or die("Connexion non effectuée")

    ?>