<?php

namespace App\Http\Controllers\Auth\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use App\Models\Admin;
use App\Models\User;
use Carbon\Carbon;

class AdminAuthController extends Controller
{
    public function sendOtp(Request $request)
    {
        // Validate the request
        $validated = $request->validate([
            'phone' => 'required|numeric|digits:10'
        ]);
        $phone = $validated['phone'];

        // Check if admin exists
        $admin = Admin::where('phone', $phone)->first();

        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => "You don't have an admin account. Please contact your Administrator."
            ], 404);
        }

        // Generate OTP
        $otp = str_pad(random_int(100000, 999999), 6, '0', STR_PAD_LEFT);
        $otpExpiresAt = Carbon::now('Asia/Kolkata')->addMinutes(5);

        // Store OTP in the database
        try {
            $admin->update([
                'otp' => $otp,
                'is_verified' => false,
                'otp_expires_at' => $otpExpiresAt
            ]);
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => 'Failed to store OTP'], 500);
        }

        // Send OTP via SMS
        try {
            $message = "$otp is your Antworks Account verification code - ANTWORKS";
            $encodedMessage = rawurlencode($message);

            $response = Http::withOptions([
                'verify' => false // Disable SSL verification (for development only)
            ])->asForm()->post('https://api.textlocal.in/send/', [
                'username' => env('SMS_GATEWAY_USERNAME'),
                'hash' => env('SMS_GATEWAY_HASH_API'),
                'numbers' => $phone,
                'sender' => env('SMS_GATEWAY_SENDER'),
                'message' => $encodedMessage,
            ]);

            if (!$response->successful()) {
                return response()->json(['status' => false, 'message' => 'Failed to send OTP. Please try again.'], 500);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => 'OTP sending failed. Please try again later.'], 500);
        }

        return response()->json([
            'status' => true,
            'message' => 'OTP sent successfully',
            'data' => [
                'phone' => substr($phone, 0, 3) . 'XXXXX' . substr($phone, -2) // Masked phone
            ]
        ], 200);
    }

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'phone' => 'required|numeric|digits:10',
            'otp' => 'required|numeric|digits:6'
        ]);

        $admin = Admin::where('phone', $request->phone)
            ->where('otp', $request->otp)
            ->where('otp_expires_at', '>', Carbon::now())
            ->first();

        if (!$admin) {
            return response()->json(['error' => 'Invalid OTP or OTP expired'], 401);
        }

        $admin->update(['is_verified' => true, 'otp' => null, 'otp_expires_at' => null]);
        $token = JWTAuth::fromUser($admin);

        return response()->json([
            'message' => 'OTP verified',
            'token' => $token,
            'redirect' => '/admin/admindashboard'
        ], 200);
    }

    public function login(Request $request)
    {
        // Validate incoming request
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        // Find admin by email
        $admin = Admin::where('email', $validated['email'])->first();

        if (!$admin || !Hash::check($validated['password'], $admin->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        // Generate OTP and set expiration time
        $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpExpiresAt = now()->addMinutes(10);

        // Update OTP and expiration time in the database
        $admin->update([
            'otp' => $otp,
            'otp_expires_at' => $otpExpiresAt,
            'is_verified' => false
        ]);

        try {
            // Prepare email content
            $emailContent = "Admin Login Verification\n\n"
                . "Your One-Time Password (OTP) for admin login is: $otp\n\n"
                . "This OTP is valid for 10 minutes. Do not share it.\n\n"
                . "If you didn't request this, please ignore this email.\n\n"
                . "Thanks,\n"
                . "The Team";

            // Send OTP via email
            Mail::raw($emailContent, function ($message) use ($admin) {
                $message->to($admin->email)
                    ->subject('Your User Login OTP');
            });

            return response()->json([
                'status' => 'success',
                'message' => 'OTP sent successfully to your email.',
                'data' => [
                    'email' => $admin->email,
                    'otp_expires_at' => $otpExpiresAt->toDateTimeString()
                ]
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send OTP. Please try again.',
                'error' => $e->getMessage()
            ], 500);
        }
    }


    public function login_verify(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required|string|size:6',
        ]);

        $admin = Admin::where('email', $request->email)
            ->where('otp', $request->otp)
            ->where('otp_expires_at', '>', Carbon::now())
            ->first();

        if (!$admin) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid or expired OTP'
            ], 401);
        }

        // Mark as verified and clear OTP
        $admin->update([
            'is_verified' => true,
            'otp' => null,
            'otp_expires_at' => null,
        ]);

        // Generate JWT token
        $token = JWTAuth::fromUser($admin);

        return response()->json([
            'status' => 'success',
            'message' => 'OTP verified successfully',
            'data' => [
                'access_token' => $token,
                'redirect_to' => '/admin/dashboard'
            ]
        ]);
    }

    public function dashboard()
    {
        $admin = Auth::guard('admin')->user();

        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized access.',
            ], 403);
        }

        $response = [
            'status' => true,
            'message' => 'Dashboard data retrieved successfully.',
            'admin' => $admin,
        ];

        switch ($admin->role) {
            case 1: // Super Admin - sees all admin roles
                $response['data'] = [
                    'admins' => Admin::whereIn('role', [1, 2, 3])->get()
                ];
                break;

            case 2: // Support Executive - sees own admin role + all users
                $response['data'] = [
                    'admins' => Admin::where('role', 2)->get(),
                    'users' => User::all()
                ];
                break;

            case 3: // Accounts - sees only own role
                $response['data'] = [
                    'admins' => Admin::where('role', 3)->get()
                ];
                break;

            default:
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid role assigned.',
                ], 403);
        }

        return response()->json($response, 200);
    }

    public function logout()
    {
        Auth::guard('admin')->logout();
        return response()->json([
            'status' => true,
            'message' => 'Successfully logged out.',
        ], 200);
    }
}
