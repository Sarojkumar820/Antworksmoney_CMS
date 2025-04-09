<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\Admin;
use Illuminate\Support\Str;
use Carbon\Carbon;

class AdminSeeder extends Seeder
{
    public function run(): void
    {
        Admin::create([
            'full_name'      => 'Admin',
            'email'          => 'sarojkumarantworksmoney@gmail.com',
            'phone'          => '123456789',
            'password'       => Hash::make('Admin@123'),
            'role'           => '1',
            'gender'         => 'Male',
            'designation'    => 'System Administrator',
            'department'     => 'IT',
            'employee_id'    => strtoupper(Str::random(5)),
            'date_of_joining'=> Carbon::now(),
            'status'         => 'active',
            'last_login'     => Carbon::now(),
            'otp'            => null,
            'is_verified'    => true,
            'otp_expires_at' => null,
            'password_changed_at' => Carbon::now(),
            'created_at'     => Carbon::now(),
            'updated_at'     => Carbon::now(),
        ]);
    }
}
