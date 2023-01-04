<?php

    //on doit appeler le fichier de connexion à la DB
    include('config/db.php');
    
    //on installe swiftmailer
    require_once('./lib/vendor/autoload.php');

    //on va traquer les message d'erreur et les success
    global $success_msg, $email_exist, $f_NameErr, $l_NameErr, $_emailErr, $_mobileErr, $_passwordErr, $captcha, $w_recaptcha;
    global $fNameEmptyErr, $lNameEmptyErr, $emailEmptyErr, $mobileEmptyErr, $passwordEmptyErr, $email_verify_err, $email_verify_success;

    //On va définir la variable du formulaire de mapage de validation
    $_first_name = $_last_name = $_email = $_mobile_number = $_password = "";

    //On va aller vérifier si notre bouton submit est bien soumis
    if(isset($_POST["submit"])){
        $firstname         = $_POST['firstname'];
        $lastname          = $_POST['lastname'];
        $email             = $_POST['email'];
        $mobilenumber      = $_POST['mobilenumber'];
        $password          = $_POST['password'];
    
        //on va vérifier si l'email n'est pas déjà utiliser
        $email_check_query = mysqli_query($conn, "SELECT * FROM user WHERE email = '{$email}' ") ;
      

        //on va vérifier le resultat de notre query
        $rowCount = mysqli_num_rows($email_check_query);


        //validation en php
        //je vérifie que mes champs ne sont pas empty (vide)
        if(!empty($firstname) && !empty($lastname) && !empty($email) && !empty($mobilenumber) && !empty($password)){

            //verifie si l'user existe déjà
            if($rowCount > 0) {
                $email_exist = '<div class="alert alert-danger" role="alert">
                                Un utlisateur avec ce mail existe déjà.</div>';
            }else {
                // on nettoie les données avant de les insérer dans la db
                // mysqli_real_escape_string(); 
                //[on protège les caractères les spéciaux d'une chaine de caractères 
                // pour les utiliser exclusivement dans une requète sql]
                $_first_name = mysqli_real_escape_string($conn, $firstname);
                $_last_name = mysqli_real_escape_string($conn, $lastname);
                $_email = mysqli_real_escape_string($conn, $email);
                $_mobile_number = mysqli_real_escape_string($conn, $mobilenumber);
                $_password = mysqli_real_escape_string($conn, $password);

                //verification recaptcha de google 
                if(isset($_POST['g-recaptcha-response'])){
                    $captcha = '<div class="alert alert-danger" role="alert">
                    Vérification invalide, recommencer proprement.</div>';
                }
                //on va vérifier que tous nous champs correspondent à ce que'on souhaite en entrée
                if(!preg_match("/^[a-zA-Z]*$/",$_first_name)){
                    $f_NameErr = '<div class="alert alert-danger" role="alert">
                                Seules les lettres et les espaces sont autorisées.</div>';
                }
                if(!preg_match("/^[a-zA-Z]*$/",$_last_name)){
                    $l_NameErr = '<div class="alert alert-danger" role="alert">
                                Seules les lettres et les espaces sont autorisées.</div>';
                }

                //on va vérifier que nos emails sont correctes
                if(!filter_var($_email, FILTER_VALIDATE_EMAIL)){
                    $_emailErr = '<div class="alert alert-danger" role="alert">
                                Le format de votre email est incorrect.</div>';
                }

                //on va verifier que le numéro de téléphone est correcte
                if(!preg_match("/^[0-9]{10}+$/", $_mobile_number)){
                    $_mobileErr = '<div class="alert alert-danger" role="alert">
                                Entrer votre numéro sur 10 chiffres.</div>';
                }

                // on va vérifier le format du mot de passe entre 6 et 20 caractères
                // avec un caractère spécial avec majuscule et minuscule + 1 chiffre obligatoire
                if(!preg_match("/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d])[^ ]{6,20}$/", $_password)){
                    $_passwordError = '<div class="alert alert-danger" role="alert">
                                Inserer un mot de passe de 6 à 20 caractères, 1 caractère spécial, majuscule, 
                                minuscule et un chiffre obligatoire.</div>';
                }

                // on envoie les données dans la si toute les conditions sont correctes
                if (
                    (preg_match("/^[a-zA-Z]*$/",$_first_name)) &&
                    (preg_match("/^[a-zA-Z]*$/",$_last_name)) &&
                    (filter_var($_email, FILTER_VALIDATE_EMAIL)) &&
                    (preg_match("/^[0-9]{10}+$/", $_mobile_number)) &&
                    (preg_match("/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d])[^ ]{6,20}$/", $_password))
                ) {
                    //on envoie un mail au client pour qu'il puisse valider les infos
                    //on génère un token aléatoire à partir de la fct time() de php
                    $token = md5(rand().time());

                    //on va hacher le mdp
                    $password_hash = password_hash($password, PASSWORD_BCRYPT);

                    //on va écrire notre requête sql
                    $sql ="INSERT INTO user (first_name, last_name, email, phone_number, pwd, token, is_active, date_time)
                                    VALUES ('{$firstname}','{$_last_name}','{$_email}','{$_mobile_number}','{$password_hash}','{$token}','0', now())";

                    //on va écrire la clé secrete de google
                    $secretKey = "6LdfO84jAAAAALauYTdA90NzGX2UMe22QZekzkcq";
                    $ip = $_SERVER['REMOTE_ADDR'];
                    $url = 'https://www.google.com/recaptcha/api/siteverify?secret='.urlencode($secretKey).'&response='.urlencode($_POST['g-recaptcha-response']);
                    $response = file_get_contents($url);
                    $responseKey = json_decode($response, true);

                    //je retourne le success de mon json responseKey
                    if ($responseKey['success']) {
                        //on envoie la requête dans la db
                        $sql_query = mysqli_query($conn, $sql);
                    } else {
                        $w_recaptcha = '<div class="alert alert-danger" role="alert">
                        Spammer de robot !</div>';
                    }
                    
                           
                    //on verifie si notre insertion contient une erreur
                    if(!$sql_query) {
                        die('mysql à échoué '. mysqli_error($conn));
                    }

                    //on envoie un mail à l'utilisateur
                    if($sql_query){
                        $msg = 'cliquer sur ce lien pour valider votre compte <br><br>
                        <a href="user_verification.php?token='.$token.'">cliquez ici</a>';

                        //on va créer un transporteur d'email
                        $transport = (new Swift_SmtpTransport('smtp.gmail.com', 465, 'ssl'))
                        ->setUsername('votre_email@gmail.com')
                        ->setPassword('votre_password_demail');

                        //on va configurer notre système d'envoie d'email
                        $mailer = new Swift_Mailer($transport);

                        //on va créer notre message
                        $message = (new Swift_Message('Validation d\'email'))
                        ->setFrom([$_email => $_first_name .' '. $_last_name])
                        ->setTo($_email)
                        ->addPart($msg, "text/html")
                        ->setBody($msg);

                    //on envoie le message
                    $result = $mailer->send($message);

                    if(!$result){
                        $email_verify_err = '<div class="alert alert-danger" role="alert">
                        L\'envoie du mail à échoué.</div>';
                    }else {
                        $email_verify_success ='<div class="alert alert-success" role="alert">
                        L\'envoie du mail à bien été effectué.</div>';
                    }
                    }
                }
            }
        } else {
            if(empty($firstname)){
                $fNameEmptyErr ='<div class="alert alert-danger" role="alert">
                Merci de remplir le champ "prénom".</div>';
            }
            if(empty($lastname)) {
                $lNameEmptyErr = '<div class="alert alert-danger" role="alert">
                Merci de remplir le champ "nom".</div>';
            }
            if(empty($email)) {
                $emailEmptyErr = '<div class="alert alert-danger" role="alert">
                Merci de remplir le champ "email".</div>';
            }
            if(empty($mobilenumber)) {
                $mobileEmptyErr = '<div class="alert alert-danger" role="alert">
                Merci de remplir le champ "mobile".</div>';
            }
            if(empty($password)) {
                $passwordEmptyErr = '<div class="alert alert-danger" role="alert">
                Merci de remplir le champ "password".</div>';
            }
            if(isset($_POST['g-recaptcha-response'])){
                $captcha = '<div class="alert alert-danger" role="alert">
                Vérification invalide, recommencer proprement.</div>';
            }
        }

    }

    //clé api google recaptcha
   // https://www.google.com/recaptcha/about