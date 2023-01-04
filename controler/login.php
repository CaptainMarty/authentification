<?php

include('./config/db.php');


global $wrongPwdErr, $accountNotExistErr, $emailPwdErr, $verificationRequiredErr, $email_empty_err, $pass_empty_err;

if(isset($_POST['login'])){
    $email_signin = $_POST['email_signin'];
    $password_signin = $_POST['password_signin'];

    $user_email = filter_var($email_signin, FILTER_SANITIZE_EMAIL);
    $pswd = mysqli_real_escape_string($conn, $password_signin);

    $sql = "SELECT * FROM user WHERE email = '$email_signin' ";
    $query = mysqli_query($conn, $sql);
    $rowCount = mysqli_num_rows($query);

    if(!$query){
        die("Connexion échouée . mysqli_error($conn");
    }
    if(!empty($email_signin) && !empty($password_signin)){
        if(preg_match("/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d])[^ ]{6,20}$/", $pswd)) {
            $wrongPwdErr = '<div class="alert alert-danger">
                            Le mots de passe doit contenir au moins 6 caractères, dont une lettre majuscule, une lettre miniscule, 
                            un chiffre et un caractère spéciale.
                            </div>';
        }
        if($rowCount <= 0){
            $accountNotExistErr = '<div class="alert alert-danger">
                            Le compte n\'existe pas.
                            </div>';
        } else {
            while ($row = mysqli_fetch_array($query)) {
                $id             = $row['id'];
                $firstname      = $row['first_name'];
                $lastname       = $row['last_name'];
                $email          = $row['email'];
                $mobilenumber   = $row['phone_number'];
                $pass_word      = $row['pwd'];
                $token          = $row['token'];
                $is_active      = $row['is_active'];
            }
            $password = password_verify($password_signin, $pass_word);

            if($is_active == '1'){
                if($email == $email_signin && $password == $password_signin) {
                   
                    header ("Location: ./dashboard.php"); 
                    $_SESSION['id'] = $id;
                    $_SESSION['firstname'] = $firstname;
                    $_SESSION['lastname'] = $lastname;
                    $_SESSION['email'] = $email;
                    $_SESSION['mobilenumber'] = $mobilenumber;
                    $_SESSION['token'] = $token;

                      

                } else {
                    $emailPwdErr = '<div class="alert alert-danger">
                                    L\'email ou le mot de passe est incorrect
                                    </div>';
                }
            } else {
                $verificationRequiredErr = '<div class="alert alert-danger">
                                            Veuillez vérifier votre email
                                            </div>';
            }
        }
    } else {
        if(empty($email_signin)) {
            $email_empty_err = '<div class="alert alert-danger">
                                L\'email de passe n\'est pas valide
                                </div>';
        }
        if(empty($password_signin)) {
            $password_empty_err = '<div class="alert alert-danger">
                                    L\'password de passe n\'est pas valide
                                    </div>';
        }
    }
}
