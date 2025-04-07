<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('admins', function (Blueprint $table) {
            $table->id();
            $table->string('full_name');
            $table->string('email')->unique();
            $table->string('phone')->unique();
            $table->string('password');
            $table->enum('role', ['1', '2', '3'])->default('2')->comment('1: Admin, 2: Support Executive, 3: Accounts');
            $table->enum('gender', ['Male', 'Female', 'Other'])->nullable();
            $table->string('designation')->nullable();
            $table->string('department')->nullable();
            $table->string('employee_id')->unique();
            $table->date('date_of_joining')->nullable();
            $table->enum('status', ['active', 'inactive', 'suspended'])->default('active');
            $table->timestamp('last_login')->nullable();
            $table->string('otp')->nullable();
            $table->boolean('is_verified')->default(false);
            $table->timestamp('otp_expires_at')->nullable();
            $table->timestamp('password_changed_at')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('admins');
    }
};
