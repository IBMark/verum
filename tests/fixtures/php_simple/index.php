<?php

namespace App\Helpers;

class UserHelper {

    public function getUserById($id) {
        // This function is used
        $id = intval($id);
        return \DB::find($id);
    }

    public function fetchUser($id) {
        // This is a renamed duplicate of getUserById
        $id = intval($id);
        return \DB::find($id);
    }

    public function formatLegacyDate($date) {
        // This function is never called - dead code
        return date('Y-m-d', strtotime($date));
    }

    private function internalHelper() {
        // Also dead - never called
        return "legacy";
    }
}

function calculateTotal($items) {
    // Used function
    $total = 0;
    foreach ($items as $item) {
        $total += $item['price'];
    }
    return $total;
}

function legacyFormat($data) {
    // Dead function - never called anywhere
    return implode(',', $data);
}
