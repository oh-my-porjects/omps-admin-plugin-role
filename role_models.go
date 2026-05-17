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
// 系统预设 ID 命名约定：完整语义名 + 数字填充到 12 字符
// 每个 ID 前 8 位完全独立（UI 上 short_id 渲染器取前 8 位时一眼区分）
// 撞库概率 ~10^-15（generate_short_id 不可能产生这种带语义前缀的串）
const (
	rootRoleID       = "Root00000001"
	rootPermID       = "SysManage001"
	supportRoleID    = "Support00001"
	unassignedPermID = "UsersRead001"
	disabledRoleID   = "Disabled0001"

	// system 角色（system=true 不可改名/禁用）
	superAdminRoleID = "SuperAdmin01"
	developerRoleID  = "Developer001"
	operatorRoleID   = "Operator0001"
)

var (
	// 12 字符 base62 短 ID 格式校验
	shortIDRE        = regexp.MustCompile(`^[A-Za-z0-9]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
