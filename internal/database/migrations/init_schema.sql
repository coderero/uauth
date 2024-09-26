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
CREATE TABLE "projects"(
    "id" SERIAL NOT NULL,
    "title" VARCHAR(255) NOT NULL,
    "deadline" TIMESTAMP(0) WITHOUT TIME ZONE NULL,
    "user_id" INTEGER NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP,
    "permission_id" INTEGER NULL,
    "is_active" BOOLEAN NULL DEFAULT TRUE
);
ALTER TABLE
    "projects" ADD PRIMARY KEY("id");
CREATE TABLE "auth_passwords"(
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "password" TEXT NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "auth_passwords" ADD PRIMARY KEY("id");
CREATE TABLE "project_roles"(
    "id" SERIAL NOT NULL,
    "project_id" INTEGER NOT NULL,
    "title" VARCHAR(255) NULL,
    "slug" VARCHAR(255) NULL,
    "description" TEXT NULL,
    "created_by" INTEGER NOT NULL,
    "is_active" BOOLEAN NULL DEFAULT TRUE,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "project_roles" ADD PRIMARY KEY("id");
CREATE TABLE "auth_logs"(
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "ip_address" VARCHAR(45) NULL,
    "user_agent" TEXT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "auth_logs" ADD PRIMARY KEY("id");
CREATE TABLE "project_task"(
    "id" SERIAL NOT NULL,
    "title" VARCHAR(255) NULL,
    "description" TEXT NULL,
    "logo" VARCHAR(255) NULL,
    "cover" VARCHAR(255) NULL,
    "project_id" INTEGER NOT NULL,
    "slug" VARCHAR(255) NULL,
    "created_by" INTEGER NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP,
    "deadline" TIMESTAMP(0) WITHOUT TIME ZONE NULL,
    "completed" BOOLEAN NULL DEFAULT FALSE
);
ALTER TABLE
    "project_task" ADD PRIMARY KEY("id");
CREATE TABLE "roles_permissions"(
    "id" SERIAL NOT NULL,
    "title" VARCHAR(255) NULL,
    "description" VARCHAR(255) NULL,
    "created_by" INTEGER NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "roles_permissions" ADD PRIMARY KEY("id");
CREATE TABLE "project_user_task"(
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "task_id" INTEGER NOT NULL,
    "permission_id" INTEGER NOT NULL,
    "created_by" INTEGER NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "project_user_task" ADD PRIMARY KEY("id");
CREATE TABLE "project_users"(
    "id" SERIAL NOT NULL,
    "project_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "created_at" TIMESTAMP(0) WITHOUT TIME ZONE NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE
    "project_users" ADD PRIMARY KEY("id");
ALTER TABLE
    "project_user_task" ADD CONSTRAINT "project_user_task_task_id_foreign" FOREIGN KEY("task_id") REFERENCES "project_task"("id");
ALTER TABLE
    "project_user_task" ADD CONSTRAINT "project_user_task_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id");
ALTER TABLE
    "project_task" ADD CONSTRAINT "project_task_project_id_foreign" FOREIGN KEY("project_id") REFERENCES "projects"("id");
ALTER TABLE
    "project_users" ADD CONSTRAINT "project_users_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id");
ALTER TABLE
    "roles_permissions" ADD CONSTRAINT "roles_permissions_created_by_foreign" FOREIGN KEY("created_by") REFERENCES "auth_users"("id");
ALTER TABLE
    "project_task" ADD CONSTRAINT "project_task_created_by_foreign" FOREIGN KEY("created_by") REFERENCES "auth_users"("id");
ALTER TABLE
    "auth_passwords" ADD CONSTRAINT "auth_passwords_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id");
ALTER TABLE
    "project_user_task" ADD CONSTRAINT "project_user_task_permission_id_foreign" FOREIGN KEY("permission_id") REFERENCES "roles_permissions"("id");
ALTER TABLE
    "auth_logs" ADD CONSTRAINT "auth_logs_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id");
ALTER TABLE
    "projects" ADD CONSTRAINT "projects_permission_id_foreign" FOREIGN KEY("permission_id") REFERENCES "roles_permissions"("id");
ALTER TABLE
    "project_user_task" ADD CONSTRAINT "project_user_task_created_by_foreign" FOREIGN KEY("created_by") REFERENCES "auth_users"("id");
ALTER TABLE
    "project_users" ADD CONSTRAINT "project_users_project_id_foreign" FOREIGN KEY("project_id") REFERENCES "projects"("id");
ALTER TABLE
    "project_roles" ADD CONSTRAINT "project_roles_created_by_foreign" FOREIGN KEY("created_by") REFERENCES "auth_users"("id");
ALTER TABLE
    "projects" ADD CONSTRAINT "projects_user_id_foreign" FOREIGN KEY("user_id") REFERENCES "auth_users"("id");
ALTER TABLE
    "project_roles" ADD CONSTRAINT "project_roles_project_id_foreign" FOREIGN KEY("project_id") REFERENCES "projects"("id");