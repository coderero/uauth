CREATE TABLE "auth_users" (
    "id" SERIAL PRIMARY KEY,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "username" TEXT NOT NULL UNIQUE,
    "email" TEXT NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "is_superadmin" BOOLEAN NOT NULL DEFAULT FALSE,
    "is_admin" BOOLEAN NOT NULL DEFAULT FALSE,
    "is_active" BOOLEAN NOT NULL DEFAULT TRUE,
    "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP
);

CREATE TABLE "auth_passwords" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "password" TEXT NOT NULL UNIQUE,
    "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "fk_used_passwords_user_id" FOREIGN KEY ("user_id") REFERENCES "auth_users" ("id") ON DELETE CASCADE
);

CREATE TABLE "auth_logs" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "ip_address" TEXT NOT NULL,
    "user_agent" TEXT NOT NULL,
    "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "fk_auth_logs_user_id" FOREIGN KEY ("user_id") REFERENCES "auth_users" ("id") ON DELETE CASCADE
);
