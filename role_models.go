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
// 系统预设 ID 命名约定：语义前缀 + 编号填充到 12 字符
// 前 8 位每个都不一样（避免 UI 缩短显示时看起来重复）
// 撞库概率 ~10^-15（generate_short_id 不可能产生这种带语义前缀串）
const (
	rootRoleID       = "RoleRoot0001"
	rootPermID       = "PermSysMan01"
	supportRoleID    = "RoleSupp0001"
	unassignedPermID = "PermUsrRead1"
	disabledRoleID   = "RoleDisb0001"

	// system 角色（system=true 不可改名/禁用）
	superAdminRoleID = "RoleSuperAdm"
	developerRoleID  = "RoleDevelope"
	operatorRoleID   = "RoleOperator"
)

var (
	// 12 字符 base62 短 ID 格式校验
	shortIDRE        = regexp.MustCompile(`^[A-Za-z0-9]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
