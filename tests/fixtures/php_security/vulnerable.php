<?php

class UserController {

    public function getUser() {
        // SQL injection vulnerability
        $id = $_GET['id'];
        $result = \DB::raw("SELECT * FROM users WHERE id = " . $id);
        return $result;
    }

    public function login() {
        $password = $_POST['password'];
        // Weak crypto
        $hash = md5($password);
        return \DB::where('password_hash', $hash)->first();
    }

    public function render() {
        $name = $_GET['name'];
        // XSS vulnerability
        echo "Hello " . $name;
    }

    public function runScript() {
        $cmd = $_POST['command'];
        // eval usage
        eval($cmd);
    }

    public function getSecret() {
        // Hardcoded secret
        $api_key = "sk-1234567890abcdefghijklmnop";
        return $api_key;
    }
}
