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

// === 仅用于 db=nil 单元测试场景的内存兜底 ID ===
//
// 生产路径：role_storage.go initStorage 用 ON CONFLICT (name/code) 通过业务字段
// seed，ID 由 PG generate_short_id() 真随机生成（12 字符 base62）。
//
// 这些常量**不会**出现在生产 DB / UI 上。仅 ensureMemoryStore 路径（go test
// 跑 plugin 时 p.db=nil 兜底）用作内存 map 的 key 占位。生产代码靠
// `WHERE name='Root'` 或 `WHERE code='system.manage'` 查找系统角色 / 权限。
const (
	rootRoleID       = "Root00000001"
	rootPermID       = "SysManage001"
	supportRoleID    = "Support00001"
	unassignedPermID = "UsersRead001"
	disabledRoleID   = "Disabled0001"
	superAdminRoleID = "SuperAdmin01"
	developerRoleID  = "Developer001"
	operatorRoleID   = "Operator0001"
)

var (
	// 12 字符 base62 短 ID 格式校验
	shortIDRE        = regexp.MustCompile(`^[A-Za-z0-9]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
