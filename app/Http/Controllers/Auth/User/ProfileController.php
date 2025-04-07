<?php

namespace App\Http\Controllers\Auth\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Http;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Storage;
use App\Models\User;

class ProfileController extends Controller
{
    public function show()
    {
        /** @var User $user */
        $user = Auth::user();

        return response()->json([
            'status' => true,
            'data' => $user
        ], 200);
    }

    public function update(Request $request)
    {
        /** @var User $user */
        $user = Auth::user();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        // Fields that should never be updated through this endpoint
        $protectedFields = ['phone', 'email', 'user_type', 'gender'];

        // Remove protected fields from the request data before validation
        $requestData = $request->except(array_merge($protectedFields, [
            'address_proof',
            'identity_proof',
            'profile_logo'
        ]));

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'dob_or_incorporation' => 'sometimes|date',
            'gst_details' => 'sometimes|string|nullable',
            'address_proof' => 'sometimes|file|mimes:jpg,jpeg,png,pdf|max:2048',
            'identity_proof' => 'sometimes|file|mimes:jpg,jpeg,png,pdf|max:2048',
            'profile_logo' => 'sometimes|file|image|mimes:jpg,jpeg,png|max:1024|nullable',
            'address_line' => 'sometimes|string',
            'state' => 'sometimes|string',
            'city' => 'sometimes|string',
            'pincode' => 'sometimes|string|size:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Validation failed.',
                'errors' => $validator->errors()
            ], 422);
        }

        $validatedData = $validator->validated();

        // Handle file uploads
        if ($request->hasFile('address_proof')) {
            // Delete old file if exists
            if ($user->address_proof) {
                Storage::disk('public')->delete($user->address_proof);
            }
            $validatedData['address_proof'] = $request->file('address_proof')->store('documents/address', 'public');
        }

        if ($request->hasFile('identity_proof')) {
            // Delete old file if exists
            if ($user->identity_proof) {
                Storage::disk('public')->delete($user->identity_proof);
            }
            $validatedData['identity_proof'] = $request->file('identity_proof')->store('documents/identity', 'public');
        }

        if ($request->hasFile('profile_logo')) {
            // Delete old file if exists
            if ($user->profile_logo) {
                Storage::disk('public')->delete($user->profile_logo);
            }
            $validatedData['profile_logo'] = $request->file('profile_logo')->store('profiles', 'public');
        }

        $user->update($validatedData);

        return response()->json([
            'status' => true,
            'message' => 'Profile updated successfully.',
            'data' => $user->fresh()
        ], 200);
    }
}
