<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Contracts\JWTSubject;

class Admin extends Authenticatable implements JWTSubject
{
    protected $fillable = [
        'full_name', 'email', 'phone', 'password', 'role',
        'designation', 'department', 'employee_id', 'date_of_joining',
        'status', 'otp', 'is_verified', 'otp_expires_at', 'password_changed_at','gender'
    ];

    protected $hidden = [
        'password', 'otp', 'remember_token'
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'date_of_joining' => 'date',
        'last_login' => 'datetime',
        'otp_expires_at' => 'datetime',
        'is_verified' => 'boolean',
        'password_changed_at' => 'datetime'
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [
            'role' => $this->role,
            'employee_id' => $this->employee_id,
            'is_verified' => $this->is_verified
        ];
    }

    /**
     * Automatically hash the password when setting it
     */
    public function setPasswordAttribute($value)
    {
        $this->attributes['password'] = Hash::make($value);
    }
}
