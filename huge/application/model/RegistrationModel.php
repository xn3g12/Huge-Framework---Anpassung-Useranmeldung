<?php

/**
 * Class RegistrationModel
 *
 * Everything registration-related happens here.
 */
class RegistrationModel
{
    /**
     * Handles the entire registration process for DEFAULT users (not for people who register with
     * 3rd party services, like facebook) and creates a new user in the database if everything is fine
     *
     * @return boolean Gives back the success status of the registration
     */
    public static function registerNewUser()
    {
        // clean the input
        $user_name = strip_tags(Request::post('user_name'));
        //$user_email = strip_tags(Request::post('user_email'));
        //$user_email_repeat = strip_tags(Request::post('user_email_repeat'));
        $user_password_new = Request::post('user_password_new');
        $user_password_repeat = Request::post('user_password_repeat');

        // stop registration flow if registrationInputValidation() returns false (= anything breaks the input check rules)
        //$validation_result = self::registrationInputValidation(Request::post('captcha'), $user_name, $user_password_new, $user_password_repeat, $user_email, $user_email_repeat);
        $validation_result = self::registrationInputValidation($user_name, $user_password_new, $user_password_repeat /*, $user_email, $user_email_repeat*/);
        if (!$validation_result) {
            return false;
        }

        // crypt the password with the PHP 5.5's password_hash() function
        $user_password_hash = password_hash($user_password_new, PASSWORD_DEFAULT);

        // make return a bool variable
        $return = true;

        // check if username already exists
        if (UserModel::doesUsernameAlreadyExist($user_name)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_USERNAME_ALREADY_TAKEN'));
            $return = false;
        }

        // check if email already exists
        /*
        if (UserModel::doesEmailAlreadyExist($user_email)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_USER_EMAIL_ALREADY_TAKEN'));
            $return = false;
        }
        */

        // if Username or Email were false, return false
        if (!$return) return false;

        // generate random hash for email verification (40 char string)
        //$user_activation_hash = sha1(uniqid(mt_rand(), true));

        // write user data to database
        if (!self::writeNewUserToDatabase($user_name, $user_password_hash, /*$user_email,*/ time()/*, $user_activation_hash*/)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_ACCOUNT_CREATION_FAILED'));
            return false;
        }

        // get user_id of the user that has been created
        $user_id = UserModel::getUserIdByUsername($user_name);

        if (!$user_id) {
            Session::add('feedback_negative', Text::get('FEEDBACK_UNKNOWN_ERROR'));
            return false;
        }

        // self::verifyNewUser($user_id,$user_activation_hash);

        // send verification email
        /*
        if (self::sendVerificationEmail($user_id, $user_email, $user_activation_hash)) {
            Session::add('feedback_positive', Text::get('FEEDBACK_ACCOUNT_SUCCESSFULLY_CREATED'));
            return true;
        }

        // if verification email sending failed: instantly delete the user
        self::rollbackRegistrationByUserId($user_id);
        Session::add('feedback_negative', Text::get('FEEDBACK_VERIFICATION_MAIL_SENDING_FAILED'));
        return false;
        */
    }

    /**
     * Validates the registration input
     */
    public static function registrationInputValidation($user_name, $user_password_new, $user_password_repeat /*, $user_email, $user_email_repeat*/)
    {
        $return = true;

        // perform all necessary checks
        if (self::validateUserName($user_name) /*AND self::validateUserEmail($user_email, $user_email_repeat)*/ AND self::validateUserPassword($user_password_new, $user_password_repeat) AND $return) {
            return true;
        }

        return false;
    }

    public static function validateUserName($user_name)
    {
        if (empty($user_name)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_USERNAME_FIELD_EMPTY'));
            return false;
        }

        if (!preg_match('/^[a-zA-Z0-9]{2,64}$/', $user_name)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_USERNAME_DOES_NOT_FIT_PATTERN'));
            return false;
        }

        return true;
    }

    /*
    public static function validateUserEmail($user_email, $user_email_repeat)
    {
        if (empty($user_email)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_EMAIL_FIELD_EMPTY'));
            return false;
        }

        if ($user_email !== $user_email_repeat) {
            Session::add('feedback_negative', Text::get('FEEDBACK_EMAIL_REPEAT_WRONG'));
            return false;
        }

        if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_EMAIL_DOES_NOT_FIT_PATTERN'));
            return false;
        }

        return true;
    }
    */

    public static function validateUserPassword($user_password_new, $user_password_repeat)
    {
        if (empty($user_password_new) OR empty($user_password_repeat)) {
            Session::add('feedback_negative', Text::get('FEEDBACK_PASSWORD_FIELD_EMPTY'));
            return false;
        }

        if ($user_password_new !== $user_password_repeat) {
            Session::add('feedback_negative', Text::get('FEEDBACK_PASSWORD_REPEAT_WRONG'));
            return false;
        }

        if (strlen($user_password_new) < 6) {
            Session::add('feedback_negative', Text::get('FEEDBACK_PASSWORD_TOO_SHORT'));
            return false;
        }

        return true;
    }

    public static function writeNewUserToDatabase($user_name, $user_password_hash /*, $user_email, $user_creation_timestamp, $user_activation_hash*/)
    {
        $database = DatabaseFactory::getFactory()->getConnection();

        $sql = "INSERT INTO users (user_name, user_password_hash /*, user_email, user_creation_timestamp, user_activation_hash*/, user_provider_type)
                VALUES (:user_name, :user_password_hash /*, :user_email, :user_creation_timestamp, :user_activation_hash*/, :user_provider_type)";
        $query = $database->prepare($sql);
        $query->execute(array(
            ':user_name' => $user_name,
            ':user_password_hash' => $user_password_hash,
            //':user_email' => $user_email,
            //':user_creation_timestamp' => $user_creation_timestamp,
            //':user_activation_hash' => $user_activation_hash,
            ':user_provider_type' => 'DEFAULT'
        ));
        $count = $query->rowCount();
        return $count == 1;
    }

    public static function rollbackRegistrationByUserId($user_id)
    {
        $database = DatabaseFactory::getFactory()->getConnection();
        $query = $database->prepare("DELETE FROM users WHERE user_id = :user_id");
        $query->execute(array(':user_id' => $user_id));
    }

    /*
    public static function sendVerificationEmail($user_id, $user_email, $user_activation_hash)
    {
        $body = Config::get('EMAIL_VERIFICATION_CONTENT') . Config::get('URL') . Config::get('EMAIL_VERIFICATION_URL')
                . '/' . urlencode($user_id) . '/' . urlencode($user_activation_hash);

        $mail = new Mail;
        $mail_sent = $mail->sendMail($user_email, Config::get('EMAIL_VERIFICATION_FROM_EMAIL'),
            Config::get('EMAIL_VERIFICATION_FROM_NAME'), Config::get('EMAIL_VERIFICATION_SUBJECT'), $body
        );

        if ($mail_sent) {
            Session::add('feedback_positive', Text::get('FEEDBACK_VERIFICATION_MAIL_SENDING_SUCCESSFUL'));
            return true;
        } else {
            Session::add('feedback_negative', Text::get('FEEDBACK_VERIFICATION_MAIL_SENDING_ERROR') . $mail->getError() );
            return false;
        }
    }
    */

    /*
    public static function verifyNewUser($user_id, $user_activation_verification_code)
    {
        $database = DatabaseFactory::getFactory()->getConnection();

        $sql = "UPDATE users SET user_active = 1, user_activation_hash = NULL
                WHERE user_id = :user_id AND user_activation_hash = :user_activation_hash LIMIT 1";
        $query = $database->prepare($sql);
        $query->execute(array(':user_id' => $user_id, ':user_activation_hash' => $user_activation_verification_code));

        if ($query->rowCount() == 1) {
            Session::add('feedback_positive', Text::get('FEEDBACK_ACCOUNT_ACTIVATION_SUCCESSFUL'));
            return true;
        }

        Session::add('feedback_negative', Text::get('FEEDBACK_ACCOUNT_ACTIVATION_FAILED'));
        return false;
    }
    */
}
