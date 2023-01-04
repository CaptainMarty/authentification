<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <link rel="stylesheet" href="./css/bootstrap.min.css">
    <link rel="stylesheet" href="./css/style.css">

    <title>PHP User Registration System Example</title>

    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
    <script src="https://www.google.com/recaptcha/api.js" defer async></script>
</head>

<body>

    <?php
    include('./hearder.php');
    include('./controler/register.php');
    ?>

    <div class="App">
        <div class="vertical-center">
            <div class="inner-block">
                <form action="" method="post">
                    <h3>Register</h3>

                    <?= $success_msg; ?>
                    <?= $email_exist; ?>

                    <?= $email_verify_err; ?>
                    <?= $email_verify_success; ?>

                    <div class="form-group">
                        <label>First name</label>
                        <input type="text" class="form-control" name="firstname" id="firstName" />

                        <?= $fNameEmptyErr; ?>
                        <?= $f_NameErr; ?>

                    </div>
                    <div class="form-group">
                        <label>Last name</label>
                        <input type="text" class="form-control" name="lastname" id="lastName" />

                        <?= $lNameEmptyErr; ?>
                        <?= $l_NameErr; ?>

                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email" id="email" />

                        <?= $emailEmptyErr; ?>
                        <?= $_emailErr; ?>

                    </div>
                    <div class="form-group">
                        <label>Mobile</label>
                        <input type="text" class="form-control" name="mobilenumber" id="mobilenumber" />

                        <?= $mobileEmptyErr; ?>
                        <?= $_mobileErr; ?>

                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password" id="password" />

                        <?= $passwordEmptyErr; ?>
                        <?= $_passwordErr; ?>

                    </div>

                    <div class="g-recaptcha" data-sitekey="6LdfO84jAAAAAIIGQkONmX8lRHKeNmuG5cBPZtmJ"></div>
                    <?php echo $captcha; ?>
                    <?php echo $w_recaptcha; ?>

                    
                    <button type="submit" name="submit" id="submit" class="btn btn-outline-primary btn-lg btn-block">
                        Sign up
                    </button>
                </form>
            </div>
        </div>
    </div>
</body>

</html>