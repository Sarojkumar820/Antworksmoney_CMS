<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\User;
use App\Models\Admin;
use Illuminate\Support\Facades\Log;

class CleanExpiredOtps extends Command
{
    protected $signature = 'otp:clean';
    protected $description = 'Clean up expired OTPs for both Users and Admins';

    public function handle()
    {
        try {
            // Clean expired OTPs for Users
            $userCount = User::whereNotNull('otp')
                ->where('otp_expires_at', '<', now())
                ->update([
                    'otp' => null,
                    'otp_expires_at' => null,
                    'is_verified' => false
                ]);

            // Clean expired OTPs for Admins
            $adminCount = Admin::whereNotNull('otp')
                ->where('otp_expires_at', '<', now())
                ->update([
                    'otp' => null,
                    'otp_expires_at' => null,
                    'is_verified' => false
                ]);

            $totalCount = $userCount + $adminCount;

            $this->info("Successfully cleaned up {$totalCount} expired OTPs (Users: {$userCount}, Admins: {$adminCount})");

            // Log the cleanup for auditing
            Log::info("OTP Cleanup Job: Removed {$totalCount} expired OTPs", [
                'users_cleaned' => $userCount,
                'admins_cleaned' => $adminCount,
                'timestamp' => now()
            ]);

            return 0;

        } catch (\Exception $e) {
            $this->error("Failed to clean expired OTPs: " . $e->getMessage());
            Log::error("OTP Cleanup Job Failed: " . $e->getMessage());
            return 1;
        }
    }
}
