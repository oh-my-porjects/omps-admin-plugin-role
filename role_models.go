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

const (
	rootRoleID       = "00000000-0000-0000-0000-000000000001"
	rootPermID       = "00000000-0000-0000-0000-000000000002"
	supportRoleID    = "00000000-0000-0000-0000-000000000003"
	unassignedPermID = "00000000-0000-0000-0000-000000000004"
	disabledRoleID   = "00000000-0000-0000-0000-000000000005"

	// system 角色：模块 Init 时 seed，业务侧不允许修改/禁用
	// ID 选用 0...10/11/12 形式便于人眼识别
	superAdminRoleID = "00000000-0000-0000-0000-000000000010"
	developerRoleID  = "00000000-0000-0000-0000-000000000011"
	operatorRoleID   = "00000000-0000-0000-0000-000000000012"
)

var (
	uuidRE           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
