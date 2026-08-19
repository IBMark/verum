<?php

namespace App\Http\Controllers;

class ReportController {

    public function show() {
        $id = $_GET['id'];
        return $this->loadReport($id);
    }

    private function loadReport($reportId) {
        $rows = \DB::raw("SELECT * FROM reports WHERE id = " . $reportId);
        return $rows;
    }

    public function currentUser() {
        $name = $_GET['name'];
        return $name;
    }

    public function greet() {
        $who = $this->currentUser();
        echo "Hello " . $who;
    }

    public function safeGreet() {
        $who = htmlspecialchars($this->currentUser());
        echo "Hello " . $who;
    }
}
