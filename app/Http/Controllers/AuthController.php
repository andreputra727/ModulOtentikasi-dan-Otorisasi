<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Firebase\JWT\JWT;

class AuthController extends Controller
{
    protected function jwt($user)
    {
        $payload = [
            'iss' => 'laravel-jwt',
            'sub' => $user->id,
            'iat' => time(),
            'exp' => time() + 60 * 60
        ];

        return JWT::encode($payload, env('JWT_SECRET'), 'HS256');
    }

    public function register(Request $request)
    {
        $name = $request->name;
        $email = $request->email;
        $password = Hash::make($request->password);

        $user = User::create([
            'name' => $name,
            'email' => $email,
            'password' => $password
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'user created',
            'data' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;

        $user = User::where('email', $email)->first();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'user not found'
            ], 404);
        }

        if (!Hash::check($password, $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'wrong password'
            ], 400);
        }

        $user->token = $this->jwt($user);
        $user->save();

        return response()->json([
            'status' => 'success',
            'message' => 'login success',
            'data' => $user
        ], 200);
    }
}