<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\User\UserAuthController;
use App\Http\Controllers\Auth\User\ProfileController;
use App\Http\Controllers\Auth\Admin\AdminAuthController;
use App\Http\Controllers\Auth\Admin\AdminProfileController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::prefix('auth')->group(function () {
    // User Authentication Routes
    Route::prefix('user')->group(function () {
        Route::post('/send-otp', [UserAuthController::class, 'sendOtp']);
        Route::post('/verify-otp', [UserAuthController::class, 'verifyOtp']);
        Route::post('/register', [UserAuthController::class, 'register']);
        Route::post('/login', [UserAuthController::class, 'login']);
        Route::post('/login_verify', [UserAuthController::class, 'login_verify']);

        // Protected User Routes
        Route::middleware(['auth:user', 'user'])->group(function () {
            Route::post('/logout', [UserAuthController::class, 'logout']);
            Route::get('/dashboard', [ProfileController::class, 'dashboard']);
            Route::post('/change-password', [ProfileController::class, 'changePassword']);
            Route::get('/show', [ProfileController::class, 'show']);
            Route::post('/update/{id}', [ProfileController::class, 'update']);
        });
    });

    // Admin Authentication Routes
    Route::prefix('admin')->group(function () {
        Route::post('/send-otp', [AdminAuthController::class, 'sendOtp']);
        Route::post('/verify-otp', [AdminAuthController::class, 'verifyOtp']);
        Route::post('/login', [AdminAuthController::class, 'login']);
        Route::post('/login_verify', [AdminAuthController::class, 'login_verify']);

        // Protected Admin Routes
        Route::middleware(['auth:admin', 'admin'])->group(function () {
            Route::post('/logout', [AdminAuthController::class, 'logout']);
            Route::get('/dashboard', [AdminAuthController::class, 'dashboard']);
            Route::post('/adminstore', [AdminProfileController::class, 'adminstore']);
            Route::post('/store', [AdminProfileController::class, 'store']);

        });
    });
});


