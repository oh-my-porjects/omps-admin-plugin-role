package main

import (
	"context"
	"time"
)

func (p *RolePlugin) initStorage(ctx context.Context) error {
	p.ensureMemoryStore()
	if p.db == nil {
		return nil
	}
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS role_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			parent_id UUID,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'enabled',
			system BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT role_roles_parent_fk FOREIGN KEY (parent_id) REFERENCES role_roles(id),
			CONSTRAINT role_roles_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
		)`,
		// 兼容老库：早期没有 system 字段
		`ALTER TABLE role_roles ADD COLUMN IF NOT EXISTS system BOOLEAN NOT NULL DEFAULT false`,
		`CREATE TABLE IF NOT EXISTS role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			code TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS role_role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			role_id UUID NOT NULL,
			permission_id UUID NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (role_id, permission_id),
			CONSTRAINT role_role_permissions_role_fk FOREIGN KEY (role_id) REFERENCES role_roles(id) ON DELETE CASCADE,
			CONSTRAINT role_role_permissions_permission_fk FOREIGN KEY (permission_id) REFERENCES role_permissions(id) ON DELETE CASCADE
		)`,
	}
	for _, stmt := range stmts {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, status, description)
		VALUES ($1, 'Root', 'enabled', 'system root role')
		ON CONFLICT (id) DO NOTHING`, rootRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'system.manage', 'System Manage', 'root management permission')
		ON CONFLICT (id) DO NOTHING`, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'users.read', 'View Users', 'permission intentionally not assigned to root')
		ON CONFLICT (id) DO NOTHING`, unassignedPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, parent_id, status, description)
		VALUES ($1, 'Support', $2, 'enabled', 'bootstrap child role')
		ON CONFLICT (id) DO NOTHING`, supportRoleID, rootRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, status, description)
		VALUES ($1, 'Disabled Role', 'disabled', 'bootstrap disabled role')
		ON CONFLICT (id) DO NOTHING`, disabledRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, rootRoleID, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, supportRoleID, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, disabledRoleID, rootPermID); err != nil {
		return err
	}

	// 系统角色 seed：超级管理员 / 开发者 / 运营，固定 ID + system=true
	// 这三个角色不允许业务侧修改名称/状态，删除按钮在 UI 上隐藏
	systemRoles := []struct {
		id, name, desc string
	}{
		{superAdminRoleID, "超级管理员", "系统预设角色，拥有最高权限"},
		{developerRoleID, "开发者", "系统预设角色，开发人员使用"},
		{operatorRoleID, "运营", "系统预设角色，运营人员使用"},
	}
	for _, sr := range systemRoles {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO role_roles (id, name, status, description, system)
			VALUES ($1, $2, 'enabled', $3, true)
			ON CONFLICT (id) DO UPDATE SET system = true`, sr.id, sr.name, sr.desc); err != nil {
			return err
		}
	}
	// 给超级管理员授予 root 权限
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, superAdminRoleID, rootPermID); err != nil {
		return err
	}
	return nil
}

func (p *RolePlugin) ensureMemoryStore() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.roles == nil {
		p.roles = map[string]roleRecord{}
	}
	if p.permissions == nil {
		p.permissions = map[string]permissionRecord{}
	}
	if p.rolePerms == nil {
		p.rolePerms = map[string]map[string]bool{}
	}
	if _, exists := p.roles[rootRoleID]; !exists {
		now := time.Now().UTC()
		p.roles[rootRoleID] = roleRecord{ID: rootRoleID, Name: "Root", Status: "enabled", CreatedAt: now, UpdatedAt: now}
		p.permissions[rootPermID] = permissionRecord{ID: rootPermID, Code: "system.manage", Name: "System Manage", CreatedAt: now, UpdatedAt: now}
		p.permissions[unassignedPermID] = permissionRecord{ID: unassignedPermID, Code: "users.read", Name: "View Users", Description: "permission intentionally not assigned to root", CreatedAt: now, UpdatedAt: now}
		p.roles[supportRoleID] = roleRecord{ID: supportRoleID, Name: "Support", ParentID: rootRoleID, Status: "enabled", Description: "bootstrap child role", CreatedAt: now, UpdatedAt: now}
		p.roles[disabledRoleID] = roleRecord{ID: disabledRoleID, Name: "Disabled Role", Status: "disabled", Description: "bootstrap disabled role", CreatedAt: now, UpdatedAt: now}
		// 系统预设三个不可修改角色
		p.roles[superAdminRoleID] = roleRecord{ID: superAdminRoleID, Name: "超级管理员", Status: "enabled", System: true, Description: "系统预设角色，拥有最高权限", CreatedAt: now, UpdatedAt: now}
		p.roles[developerRoleID] = roleRecord{ID: developerRoleID, Name: "开发者", Status: "enabled", System: true, Description: "系统预设角色，开发人员使用", CreatedAt: now, UpdatedAt: now}
		p.roles[operatorRoleID] = roleRecord{ID: operatorRoleID, Name: "运营", Status: "enabled", System: true, Description: "系统预设角色，运营人员使用", CreatedAt: now, UpdatedAt: now}
		p.rolePerms[rootRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[supportRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[disabledRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[superAdminRoleID] = map[string]bool{rootPermID: true}
	}
}
