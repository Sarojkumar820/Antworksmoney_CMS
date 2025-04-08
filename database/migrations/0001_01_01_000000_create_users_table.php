<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('admin_id')->nullable();
            $table->string('full_name')->nullable();
            $table->string('email')->unique()->nullable()->collation('utf8mb4_unicode_ci');
            $table->string('phone')->unique();
            $table->enum('user_type', ['1', '2', '3'])->nullable()->comment('1: Buddy, 2: Bizbuddy, 3: Bizbuddy Executive');
            $table->enum('gender', ['Male', 'Female', 'Other'])->nullable();
            $table->date('dob_or_incorporation')->nullable();
            $table->string('gst_details')->nullable();
            $table->string('aadhaar_number', 12)->nullable();
            $table->string('pan_number', 10)->nullable();
            $table->string('address_proof')->nullable();
            $table->string('identity_proof')->nullable();
            $table->string('profile_logo')->nullable();
            $table->string('address_line')->nullable();
            $table->string('state')->nullable();
            $table->string('city')->nullable();
            $table->string('pincode', 6)->nullable();
            $table->string('password')->nullable();
            $table->string('otp')->nullable();
            $table->timestamp('otp_expires_at')->nullable();
            $table->boolean('is_verified')->default(false);
            $table->timestamp('password_changed_at')->nullable();
            $table->rememberToken();
            $table->timestamps();

            $table->foreign('admin_id')->references('id')->on('admins')->onDelete('set null');
            // Index for performance optimization
            $table->index('phone');
        });

        // Add table comment
        DB::statement("ALTER TABLE users COMMENT 'Stores user registration details including Buddy, Bizbuddy, and Bizbuddy Executive roles.'");

        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->constrained('users')->onDelete('cascade')->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });

        // Add comments to tables
        DB::statement("ALTER TABLE password_reset_tokens COMMENT 'Stores password reset tokens for users.'");
        DB::statement("ALTER TABLE sessions COMMENT 'Tracks user sessions and activity.'");
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('users');
    }
};
