<?php

namespace App\Http\Controllers\Auth\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use App\Models\Admin;
use App\Models\User;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class AdminProfileController extends Controller
{
    public function adminstore(Request $request)
    {
        try {
            $request->validate([
                'full_name' => 'required|string|max:255',
                'email' => 'required|email|unique:admins,email',
                'phone' => 'required|string|unique:admins,phone',
                'role' => 'required|in:1,2,3',
                'gender' => 'nullable|in:Male,Female,Other',
                'designation' => 'nullable|string|max:255',
                'department' => 'nullable|string|max:255',
                'employee_id' => 'required|string|unique:admins,employee_id',
            ]);

            $randomPassword = Str::random(8);

            // ✅ Send raw email if email exists
            if ($request->filled('email')) {
                try {
                    $emailContent = "Dear {$request->full_name},\n\n"
                        . "You have been registered as an Admin user.\n\n"
                        . "Login Credentials:\n"
                        . "Email: {$request->email}\n"
                        . "Phone: {$request->phone}\n"
                        . "Temporary Password: {$randomPassword}\n\n"
                        . "Please log in and change your password immediately.\n\n"
                        . "Regards,\nYour Team";

                    Mail::raw($emailContent, function ($message) use ($request) {
                        $message->to($request->email)
                            ->subject('Your Admin Login Details');
                    });
                } catch (\Exception $mailException) {
                    return response()->json([
                        'status' => false,
                        'message' => 'Failed to send password email. Registration aborted.',
                    ], 500);
                }
            }

            // ✅ Create Admin
            $admin = new Admin();
            $admin->full_name = $request->full_name;
            $admin->email = $request->email;
            $admin->phone = $request->phone;
            $admin->password = Hash::make($randomPassword);
            $admin->role = $request->role;
            $admin->gender = $request->gender;
            $admin->designation = $request->designation;
            $admin->department = $request->department;
            $admin->employee_id = $request->employee_id;
            $admin->is_verified = true;
            $admin->save();

            return response()->json([
                'status' => true,
                'message' => 'Admin created and email sent successfully.',
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'Failed to create admin user.',
            ], 500);
        }
    }

    public function store(Request $request)
    {
        try {
            $admin = Auth::guard('admin')->user();

            // Only allow role = 2 (Support Executive)
            if (!$admin || $admin->role !== '2') {
                return response()->json([
                    'status' => false,
                    'message' => 'Only Support Executives (role 2) can create users.',
                ], 403);
            }

            $request->validate([
                'full_name' => 'required|string|max:255',
                'phone' => 'required|unique:users,phone',
                'user_type' => 'required|in:2,3',
                'email' => 'nullable|email|unique:users,email',
                'pan_number' => 'nullable|string|size:10|regex:/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/',
            ]);

            $randomPassword = Str::random(8);
            $createdByName = $admin->full_name;

            // Attempt to send email before saving user
            if ($request->filled('email')) {
                try {
                    $emailContent = "Dear {$request->full_name},\n\n"
                        . "Your account has been created by: {$createdByName}\n\n"
                        . "Here are your login credentials:\n"
                        . "Email: {$request->email}\n"
                        . "Phone: {$request->phone}\n"
                        . "Temporary Password: {$randomPassword}\n\n"
                        . "Please log in and change your password immediately.\n\n"
                        . "Regards,\nYour Team";

                    Mail::raw($emailContent, function ($message) use ($request) {
                        $message->to($request->email)
                            ->subject('Your Registration Details');
                    });
                } catch (\Exception $mailException) {
                    return response()->json([
                        'status' => false,
                        'message' => 'Failed to send password email. Registration aborted.',
                    ], 500);
                }
            }

            // Create user after successful email
            $user = new User();
            $user->full_name = $request->full_name;
            $user->phone = $request->phone;
            $user->user_type = $request->user_type;
            $user->email = $request->email;
            $user->password = Hash::make($request->randomPassword);
            $user->pan_number = $request->pan_number;
            $user->is_verified = true;
            $user->admin_id = $admin->id;
            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'Admin User created and email sent successfully.',
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'Something went wrong while creating the user',
            ], 500);
        }
    }

}
