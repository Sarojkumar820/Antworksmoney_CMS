<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    protected $fillable = [
        'full_name', 'email', 'phone', 'user_type', 'dob_or_incorporation',
        'gst_details', 'aadhaar_number', 'pan_number', 'address_proof',
        'identity_proof', 'profile_logo', 'address_line', 'state', 'city',
        'pincode', 'consent', 'password', 'otp', 'otp_expires_at',
        'is_verified', 'password_changed_at','gender'
    ];

    protected $hidden = [
        'password', 'remember_token', 'otp', 'aadhaar_number', 'pan_number'
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'otp_expires_at' => 'datetime',
        'is_verified' => 'boolean',
        'consent' => 'boolean',
        'dob_or_incorporation' => 'date',
        'password_changed_at' => 'datetime'
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [
            'user_type' => $this->user_type,
            'phone' => $this->phone,
            'is_verified' => $this->is_verified
        ];
    }
}
