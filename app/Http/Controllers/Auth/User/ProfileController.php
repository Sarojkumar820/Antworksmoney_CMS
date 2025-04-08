<?php

namespace App\Http\Controllers\Auth\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
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

                $file = $request->file('address_proof');
                $filename = $user->id . '_address_' . uniqid() . '_' . $file->getClientOriginalName();
                $file->storeAs('address_proof', $filename, 'public');
                $user->address_proof = 'address_proof/' . $filename;
            }

            // ✅ Handle identity_proof upload
            if ($request->hasFile('identity_proof')) {
                if ($user->identity_proof && Storage::disk('public')->exists($user->identity_proof)) {
                    Storage::disk('public')->delete($user->identity_proof);
                }

                $file = $request->file('identity_proof');
                $filename = $user->id . '_identity_' . uniqid() . '_' . $file->getClientOriginalName();
                $file->storeAs('identity_proof', $filename, 'public');
                $user->identity_proof = 'identity_proof/' . $filename;
            }

            // ✅ Handle profile_logo upload
            if ($request->hasFile('profile_logo')) {
                if ($user->profile_logo && Storage::disk('public')->exists($user->profile_logo)) {
                    Storage::disk('public')->delete($user->profile_logo);
                }

                $file = $request->file('profile_logo');
                $filename = $user->id . '_logo_' . uniqid() . '_' . $file->getClientOriginalName();
                $file->storeAs('profile_logo', $filename, 'public');
                $user->profile_logo = 'profile_logo/' . $filename;
            }

            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'User profile updated successfully.',
                'data' => $user,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'An error occurred while updating the profile.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
