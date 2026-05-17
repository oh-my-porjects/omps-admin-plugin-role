package main

import (
	"regexp"
	"time"
)

type roleRecord struct {
	ID          string    `json:"role_id"`
	Name        string    `json:"name"`
	ParentID    string    `json:"parent_id,omitempty"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	System      bool      `json:"system"` // system=true 的角色由模块 Init 自动 seed，业务侧不允许修改/禁用
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type permissionRecord struct {
	ID          string    `json:"permission_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type roleResponse struct {
	RoleID      string               `json:"role_id"`
	Name        string               `json:"name"`
	ParentID    *string              `json:"parent_id"`
	ParentName  string               `json:"parent_name"`
	Status      string               `json:"status"`
	System      bool                 `json:"system"`
	Description string               `json:"description"`
	CreatedAt   string               `json:"created_at,omitempty"`
	UpdatedAt   string               `json:"updated_at,omitempty"`
	Permissions []permissionResponse `json:"permissions"`
}

type permissionResponse struct {
	PermissionID string `json:"permission_id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// 平台短 ID 标准：12 字符 base62 ([A-Za-z0-9])，由 runtime migration11 注入的
// generate_short_id() PG 函数生成。详见 admin-server/prompts/_shared_constraints.md §6
//
// 系统预设 ID 命名约定：开头 8 个 0 + 4 字符语义后缀（撞库概率 ~10^-15）
//   - "00000000Root" Root 根角色（兼容旧 ID rootRoleID 语义）
//   - "00000000Supp" Support 子角色（演示父-子角色继承）
//   - "00000000Disb" Disabled 演示禁用角色
//   - "00000000SAdm" 超级管理员（system=true 不可改名）
//   - "00000000Devp" 开发者（system=true）
//   - "00000000Optr" 运营（system=true）
//   - "00000000SysP" rootPermID system.manage 根权限
//   - "00000000UsrR" unassignedPermID users.read 故意不绑给 root
const (
	rootRoleID       = "00000000Root"
	rootPermID       = "00000000SysP"
	supportRoleID    = "00000000Supp"
	unassignedPermID = "00000000UsrR"
	disabledRoleID   = "00000000Disb"

	// system 角色（system=true 不可改名/禁用）
	superAdminRoleID = "00000000SAdm"
	developerRoleID  = "00000000Devp"
	operatorRoleID   = "00000000Optr"
)

var (
	// 12 字符 base62 短 ID 格式校验
	shortIDRE        = regexp.MustCompile(`^[A-Za-z0-9]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
