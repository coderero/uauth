CREATE TABLE "auth_users"(
    "id" SERIAL NOT NULL,
    "first_name" TEXT NULL,
    "last_name" TEXT NULL,
    "username" VARCHAR(100) NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "password" TEXT NOT NULL,
    "is_superadmin" BOOLEAN NULL DEFAULT FALSE,
    "is_admin" BOOLEAN NULL DEFAULT FALSE,
    "is_active" BOOLEAN NULL DEFAULT TRUE,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL
);
ALTER TABLE
    "auth_users" ADD PRIMARY KEY("id");
ALTER TABLE
    "auth_users" ADD CONSTRAINT "auth_users_username_unique" UNIQUE("username");
ALTER TABLE
    "auth_users" ADD CONSTRAINT "auth_users_email_unique" UNIQUE("email");

CREATE TABLE "auth_passwords"(
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "password" TEXT NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "auth_passwords" ADD PRIMARY KEY("id");
CREATE TABLE "auth_logs"(
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "ip_address" VARCHAR(45) NULL,
    "user_agent" TEXT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "auth_logs" ADD PRIMARY KEY("id");
ALTER TABLE
    "auth_passwords" ADD CONSTRAINT "auth_passwords_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id") ON DELETE CASCADE;
ALTER TABLE
    "auth_logs" ADD CONSTRAINT "auth_logs_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id") ON DELETE CASCADE;