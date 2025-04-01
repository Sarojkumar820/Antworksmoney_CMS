<?php

namespace App\Http\Controllers\Auth\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Http;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\Models\User;

class UserAuthController extends Controller
{
    public function sendOtp(Request $request)
    {
        try {
            // Validate the request
            $validated = $request->validate([
                'phone' => 'required|numeric|digits:10'
            ]);
            $phone = $validated['phone'];

            // Check if user exists, if not create new user
            $user = User::where('phone', $phone)->first();

            if (!$user) {
                $user = User::create([
                    'phone' => $phone,
                ]);

                if (!$user) {
                    throw new \Exception('Failed to create new user');
                }
            }

            // Generate 6-digit OTP
            $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $otpExpiresAt = Carbon::now('Asia/Kolkata')->addMinutes(5);

            // Store OTP in the database
            $user->update([
                'otp' => $otp,
                'otp_expires_at' => $otpExpiresAt,
                'is_verified' => false
            ]);

            if (!$user->save()) {
                throw new \Exception('Failed to update user OTP');
            }

            // Send OTP via SMS
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
                return response()->json([
                    'status' => false,
                    'message' => 'OTP generated but failed to send SMS'
                ], 500);
            }

            return response()->json([
                'status' => true,
                'message' => 'OTP sent successfully',
                'data' => [
                    'phone' => substr($phone, 0, 3) . 'XXXXX' . substr($phone, -2) // Masked phone
                ]
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'An error occurred while processing your request',
                'error' => env('APP_DEBUG') ? $e->getMessage() : null
            ], 500);
        }
    }

    // Verify OTP and Handle Registration/Login
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'phone' => 'required|numeric|digits:10',
            'otp' => 'required|numeric|digits:6'
        ]);

        $user = User::where('phone', $request->phone)
            ->where('otp', $request->otp)
            ->where('otp_expires_at', '>', Carbon::now())
            ->first();

        if (!$user) {
            return response()->json(['error' => 'Invalid OTP or OTP expired'], 401);
        }

        $user->update(['is_verified' => true, 'otp' => null, 'otp_expires_at' => null]);

        if ($user->email) {
            $token = JWTAuth::fromUser($user);
            return response()->json([
                'message' => 'OTP verified',
                'token' => $token,
                'redirect' => '/user/dashboard'
            ], 200);
        }

        return response()->json([
            'message' => 'OTP verified. Complete registration.',
            'redirect' => '/user/register'
        ], 200);
    }

    public function register(Request $request)
    {
        $validated = $request->validate([
            'phone' => 'required|numeric|digits:10|exists:users,phone',
            'full_name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email,' . ($request->user_id ?? 'NULL'),
            'user_type' => 'required|in:1,2',
            'dob_or_incorporation' => 'nullable|date',
            'pan_number' => 'nullable|string|regex:/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/',
            'address_line' => 'nullable|string|max:255',
            'state' => 'nullable|string|max:100',
            'city' => 'nullable|string|max:100',
            'pincode' => 'nullable|string|digits:6',
        ]);

        $user = User::where('phone', $validated['phone'])->firstOrFail();
        $password = $this->generateStrongPassword(16);

        try {
            // Prepare email content
            $emailContent = "Thank you for registering!\n\n"
                . "Your account has been successfully created.\n\n"
                . "Your temporary password is: $password\n\n"
                . "Please login and change your password immediately for security reasons.\n\n"
                . "Thanks,\n"
                . "The Team";

            // Send email with raw content
            Mail::raw($emailContent, function ($message) use ($validated) {
                $message->to($validated['email'])
                    ->subject('Your Account Password');
            });

            // Update user only after successful email
            $user->update([
                'full_name' => $validated['full_name'],
                'email' => $validated['email'],
                'password' => Hash::make($password),
                'user_type' => $validated['user_type'],
                'dob_or_incorporation' => $validated['dob_or_incorporation'],
                'pan_number' => $validated['pan_number'],
                'address_line' => $validated['address_line'],
                'state' => $validated['state'],
                'city' => $validated['city'],
                'pincode' => $validated['pincode'],
                'password_changed_at' => null,
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json([
                'success' => true,
                'message' => 'Registration completed successfully. Check your email for password.',
                'token' => $token,
                'redirect' => '/user/dashboard'
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Registration failed. Could not send email.',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    protected function generateStrongPassword($length = 16)
    {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        return substr(str_shuffle(str_repeat($characters, ceil($length / strlen($characters)))), 0, $length);
    }

    public function login(Request $request)
    {
        // Validate incoming request
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        // Find user by email
        $user = User::where('email', $validated['email'])->first();

        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        // Generate OTP and set expiration time
        $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpExpiresAt = now()->addMinutes(10);

        // Update OTP and expiration time in the database
        $user->update([
            'otp' => $otp,
            'otp_expires_at' => $otpExpiresAt,
            'is_verified' => false
        ]);

        try {
            // Prepare email content
            $emailContent = "User Login Verification\n\n"
                . "Your One-Time Password (OTP) for User login is: $otp\n\n"
                . "This OTP is valid for 10 minutes. Do not share it.\n\n"
                . "If you didn't request this, please ignore this email.\n\n"
                . "Thanks,\n"
                . "The Team";

            // Send OTP via email
            Mail::raw($emailContent, function ($message) use ($user) {
                $message->to($user->email)
                    ->subject('Your User Login OTP');
            });

            return response()->json([
                'status' => 'success',
                'message' => 'OTP sent successfully to your email.',
                'data' => [
                    'email' => $user->email,
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

        $user = User::where('email', $request->email)
            ->where('otp', $request->otp)
            ->where('otp_expires_at', '>', Carbon::now())
            ->first();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid or expired OTP'
            ], 401);
        }

        // Mark as verified and clear OTP
        $user->update([
            'is_verified' => true,
            'otp' => null,
            'otp_expires_at' => null,
        ]);

        // Generate JWT token
        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status' => 'success',
            'message' => 'OTP verified successfully',
            'data' => [
                'access_token' => $token,
                'redirect_to' => '/user/dashboard'
            ]
        ]);
    }


    // Get Logged-in User Details
    public function dashboard()
    {
        return response()->json([
            'status' => true,
            'message' => 'User dashboard data retrieved successfully.',
            'user' => Auth::user(),
        ], 201);
    }
    public function changePassword(Request $request)
    {
        /** @var \App\Models\User $user */
        $user = Auth::user();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access. Please log in again.',
            ], 401);
        }

        $validated = $request->validate([
            'current_password' => ['required', 'string'],
            'new_password' => [
                'required',
                'string',
                'min:6',
                'max:24',
                'different:current_password',
                'same:new_password_confirmation',
                function ($attribute, $value, $fail) {
                    $complexity = 0;

                    if (preg_match('/[A-Z]/', $value)) $complexity++;
                    if (preg_match('/[a-z]/', $value)) $complexity++;
                    if (preg_match('/[0-9]/', $value)) $complexity++;
                    if (preg_match('/[^A-Za-z0-9]/', $value)) $complexity++;

                    if ($complexity < 3) {
                        $fail('The password must be 6-24 characters and contain at least three of: uppercase, lowercase, numbers, or special characters.');
                    }
                }
            ],
            'new_password_confirmation' => ['required', 'string']
        ]);

        if (!Hash::check($validated['current_password'], $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'The current password is incorrect.',
            ], 422);
        }

        // Update password
        $user->update([
            'password' => Hash::make($validated['new_password']),
            'password_changed_at' => now()->setTimezone('Asia/Kolkata'),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Password changed successfully.',
            'data' => [
                'password_changed_at' => $user->password_changed_at->format('Y-m-d H:i:s'),
                'next_steps' => 'You may need to log in again with your new password.'
            ]
        ]);
    }

    // User Logout
    public function logout()
    {
        Auth::guard('user')->logout();
        return response()->json(['message' => 'Successfully logged out'], 200);
    }
}
