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
		// 平台短 ID 标准：12 字符 base62
		// generate_short_id() 函数由 runtime migration11 注入，这里直接使用
		// （如果 runtime 是老版没注入，CREATE TABLE 报错；新部署不存在此问题）
		`CREATE TABLE IF NOT EXISTS role_roles (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			name TEXT NOT NULL,
			parent_id TEXT,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'enabled',
			system BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT role_roles_parent_fk FOREIGN KEY (parent_id) REFERENCES role_roles(id),
			CONSTRAINT role_roles_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
		)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			code TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS role_role_permissions (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			role_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
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
	// 加 name UNIQUE 索引让 ON CONFLICT (name) 可用（业务字段做 system 角色 seed 幂等）
	if _, err := p.db.ExecContext(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_roles_name ON role_roles(name)`); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_permissions_code ON role_permissions(code)`); err != nil {
		return err
	}

	// seed 系统预设角色 + 权限：ID 由 generate_short_id() 随机生成（每次部署/项目都不同）
	// 业务代码用 name / code 字段查找系统角色，不依赖硬编码 ID 常量
	// system=true 标记 + ON CONFLICT (name/code) 保证幂等
	seedRoles := []struct {
		name, status, desc string
		system             bool
		parentName         string // 空表示 NULL parent_id
	}{
		{"Root", "enabled", "system root role", true, ""},
		{"Support", "enabled", "bootstrap child role", true, "Root"},
		{"Disabled Role", "disabled", "bootstrap disabled role", true, ""},
		{"超级管理员", "enabled", "系统预设角色，拥有最高权限", true, ""},
		{"开发者", "enabled", "系统预设角色，开发人员使用", true, ""},
		{"运营", "enabled", "系统预设角色，运营人员使用", true, ""},
	}
	for _, sr := range seedRoles {
		if sr.parentName == "" {
			if _, err := p.db.ExecContext(ctx, `
				INSERT INTO role_roles (name, status, description, system)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (name) DO UPDATE SET system = EXCLUDED.system`,
				sr.name, sr.status, sr.desc, sr.system); err != nil {
				return err
			}
		} else {
			if _, err := p.db.ExecContext(ctx, `
				INSERT INTO role_roles (name, parent_id, status, description, system)
				VALUES ($1, (SELECT id FROM role_roles WHERE name=$2 LIMIT 1), $3, $4, $5)
				ON CONFLICT (name) DO UPDATE SET system = EXCLUDED.system`,
				sr.name, sr.parentName, sr.status, sr.desc, sr.system); err != nil {
				return err
			}
		}
	}

	seedPerms := []struct {
		code, name, desc string
	}{
		{"system.manage", "System Manage", "root management permission"},
		{"users.read", "View Users", "permission intentionally not assigned to root"},
	}
	for _, sp := range seedPerms {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO role_permissions (code, name, description)
			VALUES ($1, $2, $3)
			ON CONFLICT (code) DO NOTHING`, sp.code, sp.name, sp.desc); err != nil {
			return err
		}
	}

	// 角色权限绑定：Root / Support / Disabled Role / 超级管理员 → system.manage
	// 通过 name / code 子查询拿到随机生成的 ID
	for _, roleName := range []string{"Root", "Support", "Disabled Role", "超级管理员"} {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO role_role_permissions (role_id, permission_id)
			SELECT r.id, p.id FROM role_roles r, role_permissions p
			WHERE r.name = $1 AND p.code = 'system.manage'
			ON CONFLICT (role_id, permission_id) DO NOTHING`, roleName); err != nil {
			return err
		}
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
