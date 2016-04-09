<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script src="/jquery-1.11.3.min.js"></script>




    <div class="login" id="login">
        <div class="login-triangle"></div>

        <h2 class="login-header">Sign up </h2>

        <form action= "/register" method="post" id="signupForm" class="login-container">
            <label for="usernamesignup" class="uname" data-icon="u">Your Username</label>
            <p><input type="text" name="username" placeholder="Username" required></p>
            <label for="passwordsignup">Your Password </label>
            <p><input type="password" name="password" id="password" placeholder="Password" required></p>
            <label for="phonesignup">Your Phone Number (of form: 123-456-7890) </label>
            <p><input type="text" name="phoneNumber" placeholder="Phone Number" pattern="^\d{3}-\d{3}-\d{4}$" required></p>
            <label for="emailsignup">Your Email </label>
            <p><input type="email" name="email" placeholder="Email" pattern = "^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$" required></p>
            <p><input type="submit" value="Sign Up"></p>
            <p>
                Already a Member? <a href="/" class="to_register">Log In!</a>
            </p>
        </form>

    </div>
    <script>
        $(document).ready(function () {

            sessionStorage.removeItem("password");

            $("#signupForm").submit(function (event) {
                $passwordField = $('#password');
                var hashedPassword = sjcl.hash.sha256.hash(sjcl.codec.utf8String.toBits($passwordField.val()));
//                sessionStorage.setItem("password", sjcl.codec.base64url.fromBits(hashedPassword));
                var hash = sjcl.hash.sha256.hash(hashedPassword);
                $passwordField.val(sjcl.codec.base64url.fromBits(hash));
            });
        });
    </script>

</html>