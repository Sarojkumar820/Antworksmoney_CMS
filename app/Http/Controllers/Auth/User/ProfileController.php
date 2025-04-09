<?php

namespace App\Http\Controllers\Auth\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Storage;
use App\Models\User;
use Illuminate\Support\Facades\Hash;


class ProfileController extends Controller
{
    public function dashboard()
    {
        try {
            /** @var User $user */
            $user = Auth::user();

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not authenticated',
                ], 401);
            }

            // Run the queries but don't assign to a variable we won't use
            if ($user->user_type == 2) {
                User::whereIn('user_type', [2, 3])->get();
            } elseif ($user->user_type == 1) {
                User::where('user_type', 1)->get();
            } elseif ($user->user_type == 3) {
                User::where('user_type', 3)->get();
            }
            // No else needed since we don't use the data

            return response()->json([
                'status' => true,
                'message' => 'User dashboard data retrieved successfully.',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'Failed to retrieve dashboard data',
            ], 500);
        }
    }

    public function update(Request $request, $id)
    {
        try {
            /** @var User $authUser */
            $authUser = Auth::user();

            if (!$authUser) {
                return response()->json([
                    'status' => false,
                    'message' => 'Unauthorized.',
                ], 401);
            }

            if ($authUser->id != $id) {
                return response()->json([
                    'status' => false,
                    'message' => 'Forbidden. You can only update your own profile.',
                ], 403);
            }

            $user = User::find($id);

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not found.',
                ], 404);
            }

            // ✅ Update basic fields if present
            $user->full_name = $request->input('full_name', $user->full_name);
            $user->dob_or_incorporation = $request->input('dob_or_incorporation', $user->dob_or_incorporation);
            $user->gst_details = $request->input('gst_details', $user->gst_details);
            $user->address_line = $request->input('address_line', $user->address_line);
            $user->state = $request->input('state', $user->state);
            $user->city = $request->input('city', $user->city);
            $user->pincode = $request->input('pincode', $user->pincode);

            // ✅ Handle address_proof upload
            if ($request->hasFile('address_proof')) {
                if ($user->address_proof && Storage::disk('public')->exists($user->address_proof)) {
                    Storage::disk('public')->delete($user->address_proof);
                }

                $addressFile = $request->file('address_proof');
                $folder = 'address_proof/' . $user->id;
                $filename = time() . '_' . $addressFile->getClientOriginalName();
                $addressFile->storeAs($folder, $filename, 'public');
                $user->address_proof = $folder . '/' . $filename;
            }

            // Handle identity proof upload
            if ($request->hasFile('identity_proof')) {
                if ($user->identity_proof && Storage::disk('public')->exists($user->identity_proof)) {
                    Storage::disk('public')->delete($user->identity_proof);
                }

                $identityFile = $request->file('identity_proof');
                $folder = 'identity_proof/' . $user->id;
                $filename = time() . '_' . $identityFile->getClientOriginalName();
                $identityFile->storeAs($folder, $filename, 'public');
                $user->identity_proof = $folder . '/' . $filename;
            }

            // Handle profile logo upload
            if ($request->hasFile('profile_logo')) {
                if ($user->profile_logo && Storage::disk('public')->exists($user->profile_logo)) {
                    Storage::disk('public')->delete($user->profile_logo);
                }

                $logoFile = $request->file('profile_logo');
                $folder = 'profile_logo/' . $user->id;
                $filename = time() . '_' . $logoFile->getClientOriginalName();
                $logoFile->storeAs($folder, $filename, 'public');
                $user->profile_logo = $folder . '/' . $filename;
            }

            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'User profile updated successfully.',
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'An error occurred while updating the profile.',
            ], 500);
        }
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
                function ($attribute, $value, $fail) {
                    $complexity = 0;
                    if (preg_match('/[A-Z]/', $value)) $complexity++;
                    if (preg_match('/[a-z]/', $value)) $complexity++;
                    if (preg_match('/[0-9]/', $value)) $complexity++;
                    if (preg_match('/[^A-Za-z0-9]/', $value)) $complexity++;
                    if ($complexity < 3) {
                        $fail('Use 6-24 characters with 3 character types (A-Z, a-z, 0-9, or symbols).');
                    }
                }
            ],
            'new_password_confirmation' => ['required', 'string', 'same:new_password'],
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
        ], 200);
    }
}
