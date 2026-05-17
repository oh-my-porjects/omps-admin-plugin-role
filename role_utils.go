package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func roleToResponse(role roleRecord, parentName string) roleResponse {
	resp := roleResponse{
		RoleID:      role.ID,
		Name:        role.Name,
		ParentName:  parentName,
		Status:      role.Status,
		System:      role.System,
		Description: role.Description,
		CreatedAt:   formatTime(role.CreatedAt),
		UpdatedAt:   formatTime(role.UpdatedAt),
		Permissions: []permissionResponse{},
	}
	if role.ParentID != "" {
		parentID := role.ParentID
		resp.ParentID = &parentID
	}
	return resp
}

func permissionToResponse(perm permissionRecord) permissionResponse {
	return permissionResponse{
		PermissionID: perm.ID,
		Code:         perm.Code,
		Name:         perm.Name,
		Description:  perm.Description,
		CreatedAt:    formatTime(perm.CreatedAt),
	}
}

func validName(s string) bool {
	n := runeLen(s)
	return n >= 2 && n <= 30
}

func runeLen(s string) int {
	return len([]rune(s))
}

func validStatus(s string) bool {
	return s == "enabled" || s == "disabled"
}

// validShortID 校验 12 字符 base62 ID 格式
// 替代旧的 validUUID；函数名保留 validUUID 别名给历史调用方
func validShortID(s string) bool {
	return shortIDRE.MatchString(s)
}

// validUUID 保留作为 validShortID 别名（外部调用兼容）
// 新代码用 validShortID
func validUUID(s string) bool {
	return validShortID(s)
}

func validPermissionCode(s string) bool {
	return permissionCodeRE.MatchString(s)
}

func parsePage(pageRaw, sizeRaw string) (int, int, bool) {
	page, err1 := strconv.Atoi(strings.TrimSpace(pageRaw))
	size, err2 := strconv.Atoi(strings.TrimSpace(sizeRaw))
	if err1 != nil || err2 != nil || page < 1 || size < 1 || size > 100 {
		return 0, 0, false
	}
	return page, size, true
}

func pageBounds(total, page, size int) (int, int) {
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return start, end
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	return json.NewDecoder(r.Body).Decode(dst)
}

// newShortID 内存兜底场景（db 为 nil 单元测试）的 ID 生成
// 12 字符 base62，用 unix nano 做来源（单元测试足够），不用 crypto rand 避免依赖
// 生产路径 (db != nil) 由 PG generate_short_id() 函数兜底，不走这里
func newShortID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	n := time.Now().UnixNano()
	out := make([]byte, 12)
	for i := 0; i < 12; i++ {
		out[i] = chars[n%62]
		n /= 62
		if n == 0 {
			// 后续位用线程不安全但单测够用的 fallback
			n = time.Now().UnixNano() + int64(i)
		}
	}
	return string(out)
}

// newUUIDLikeID 保留旧名给兼容（实际生成短 ID）
func newUUIDLikeID() string { return newShortID() }

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
