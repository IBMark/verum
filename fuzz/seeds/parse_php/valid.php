<?php

namespace App\Http;

use Illuminate\Http\Request;

class Controller
{
    public function index(Request $request): string
    {
        return $request->input('q', '');
    }
}
