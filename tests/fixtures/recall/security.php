<?php

// Recall fixture: every issue below is a KNOWN true positive that must keep
// firing. If FP-reduction work ever silences one of these, the recall test
// fails — that is the point of this file.

class OrderController
{
    public function show()
    {
        // SQL injection: unsanitized $_GET flows into a raw query.
        $id = $_GET['id'];
        return \DB::raw("SELECT * FROM orders WHERE id = " . $id);
    }

    public function login()
    {
        // Weak crypto in live code.
        $password = $_POST['password'];
        $hash = md5($password);
        return \DB::where('password_hash', $hash)->first();
    }

    public function runTask()
    {
        // eval on user input.
        $cmd = $_POST['command'];
        eval($cmd);
    }

    public function credentials()
    {
        // Hardcoded secret.
        $api_key = "sk-live-abcdef1234567890ghijkl";
        return $api_key;
    }

    public function render()
    {
        // Reflected XSS: user input echoed without escaping.
        $name = $_GET['name'];
        echo "Hello " . $name;
    }
}
