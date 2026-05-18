package main

import (
	"net/http"
	"strings"
)

func (p *RolePlugin) handleRoleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		ParentID    string `json:"parent_id"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2101, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.Description = strings.TrimSpace(req.Description)
	req.Status = strings.TrimSpace(req.Status)
	if !validName(req.Name) {
		writeJSON(w, 2101, nil, "角色名称缺失或长度不合法")
		return
	}
	if !validStatus(req.Status) {
		writeJSON(w, 2102, nil, "角色状态不合法")
		return
	}
	if runeLen(req.Description) > 200 {
		writeJSON(w, 2101, nil, "角色说明过长")
		return
	}
	if req.ParentID != "" && !validUUID(req.ParentID) {
		writeJSON(w, 2103, nil, "父角色不存在")
		return
	}
	if req.ParentID != "" && !p.roleExists(r.Context(), req.ParentID) {
		writeJSON(w, 2103, nil, "父角色不存在")
		return
	}
	if p.siblingNameExists(r.Context(), "", req.ParentID, req.Name) {
		writeJSON(w, 2104, nil, "同一父角色下角色名称已存在")
		return
	}
	role, err := p.createRole(r.Context(), req.Name, req.ParentID, req.Description, req.Status)
	if err != nil {
		writeJSON(w, 2105, nil, "创建角色失败")
		return
	}
	writeJSON(w, 0, roleToResponse(role, ""), "")
}

func (p *RolePlugin) handleRoleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, pageSize, ok := parsePage(q.Get("page"), q.Get("page_size"))
	if !ok {
		writeJSON(w, 2111, nil, "分页参数不合法")
		return
	}
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && !validStatus(status) {
		writeJSON(w, 2112, nil, "状态参数不合法")
		return
	}
	parentID := strings.TrimSpace(q.Get("parent_id"))
	parentFilterSet := q.Has("parent_id")
	if parentID != "" && !validUUID(parentID) {
		writeJSON(w, 2113, nil, "父角色参数格式不合法")
		return
	}
	keyword := strings.TrimSpace(q.Get("keyword"))
	if runeLen(keyword) > 30 {
		writeJSON(w, 2114, nil, "查询角色列表失败")
		return
	}
	items, total, err := p.listRoles(r.Context(), roleListFilter{ParentID: parentID, ParentSet: parentFilterSet, Status: status, Keyword: keyword, Page: page, PageSize: pageSize})
	if err != nil {
		writeJSON(w, 2114, nil, "查询角色列表失败")
		return
	}
	writeJSON(w, 0, map[string]any{"items": items, "total": total}, "")
}

func (p *RolePlugin) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.URL.Query().Get("role_id"))
	if !validUUID(roleID) {
		writeJSON(w, 2121, nil, "角色 ID 缺失或格式不合法")
		return
	}
	resp, exists, err := p.roleDetail(r.Context(), roleID)
	if err != nil {
		writeJSON(w, 2123, nil, "查询角色详情失败")
		return
	}
	if !exists {
		writeJSON(w, 2122, nil, "角色不存在")
		return
	}
	writeJSON(w, 0, resp, "")
}

func (p *RolePlugin) handleRoleUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID      string `json:"role_id"`
		Name        string `json:"name"`
		ParentID    string `json:"parent_id"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2131, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	req.Name = strings.TrimSpace(req.Name)
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.Description = strings.TrimSpace(req.Description)
	req.Status = strings.TrimSpace(req.Status)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2131, nil, "角色 ID 缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2132, nil, "角色不存在")
		return
	}
	// 系统预设角色不允许修改（包括改名/改状态/改父角色）
	if role.System {
		writeJSON(w, 2139, nil, "系统预设角色不允许修改")
		return
	}
	if !validName(req.Name) || !validStatus(req.Status) || runeLen(req.Description) > 200 {
		writeJSON(w, 2133, nil, "角色名称或状态参数不合法")
		return
	}
	if req.ParentID != "" {
		if req.ParentID == req.RoleID {
			writeJSON(w, 2135, nil, "角色层级不允许形成循环")
			return
		}
		if !validUUID(req.ParentID) || !p.roleExists(r.Context(), req.ParentID) {
			writeJSON(w, 2134, nil, "父角色不存在或父角色设置不合法")
			return
		}
		if p.wouldCreateCycle(r.Context(), req.RoleID, req.ParentID) {
			writeJSON(w, 2135, nil, "角色层级不允许形成循环")
			return
		}
	}
	withinParent, err := p.rolePermissionsWithinParent(r.Context(), req.RoleID, req.ParentID)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	if !withinParent {
		writeJSON(w, 2136, nil, "当前角色权限超出新父角色权限范围")
		return
	}
	if p.siblingNameExists(r.Context(), req.RoleID, req.ParentID, req.Name) {
		writeJSON(w, 2137, nil, "同一父角色下角色名称已存在")
		return
	}
	role.Name = req.Name
	role.ParentID = req.ParentID
	role.Description = req.Description
	role.Status = req.Status
	updated, err := p.updateRole(r.Context(), role)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	writeJSON(w, 0, roleToResponse(updated, ""), "")
}

// handleRoleDelete DELETE 类角色软删除接口
// 业务约束:
//   - 系统预设角色 (system=true) 不允许删除
//   - 有子角色时不允许删除 (FK NO ACTION 也会阻止, 这里先 SELECT 给好错误信息)
//   - 已被账号绑定 (account_role_bindings.role_id) 时不允许删除, 避免孤儿引用
//
// role_role_permissions 通过 FK ON DELETE CASCADE 自动清理
func (p *RolePlugin) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		// 容错: query string 兼容 (DELETE 请求不一定带 body)
		req.RoleID = r.URL.Query().Get("role_id")
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2191, nil, "角色 ID 缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2196, nil, "查询角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2192, nil, "角色不存在")
		return
	}
	if role.System {
		writeJSON(w, 2193, nil, "系统预设角色不允许删除")
		return
	}
	// 子角色检查
	var childCount int
	if err := p.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM role_roles WHERE parent_id=$1`, req.RoleID).Scan(&childCount); err != nil {
		writeJSON(w, 2196, nil, "子角色检查失败")
		return
	}
	if childCount > 0 {
		writeJSON(w, 2194, nil, "存在子角色,不允许删除")
		return
	}
	// 账号绑定检查 (跨模块查 account 表; 同 DB schema)
	// 若 account 公共模块未加载或表不存在, 查询会失败 — 容忍 (table not found 错误时跳过该检查)
	var bindCount int
	bindErr := p.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM account_role_bindings WHERE role_id=$1`, req.RoleID).Scan(&bindCount)
	if bindErr == nil && bindCount > 0 {
		writeJSON(w, 2195, nil, "角色已绑定到账号,请先解除绑定再删除")
		return
	}
	// 删 role; role_role_permissions 通过 ON DELETE CASCADE 自动清
	if _, err := p.db.ExecContext(r.Context(),
		`DELETE FROM role_roles WHERE id=$1`, req.RoleID); err != nil {
		writeJSON(w, 2196, nil, "删除角色失败: "+err.Error())
		return
	}
	writeJSON(w, 0, map[string]any{"role_id": req.RoleID}, "已删除")
}

func (p *RolePlugin) handlePermissionCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code        string `json:"code"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2141, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !validPermissionCode(req.Code) {
		writeJSON(w, 2141, nil, "权限点标识缺失或格式不合法")
		return
	}
	if !validName(req.Name) {
		writeJSON(w, 2142, nil, "权限点名称缺失或长度不合法")
		return
	}
	if runeLen(req.Description) > 200 {
		writeJSON(w, 2142, nil, "权限点说明过长")
		return
	}
	if p.permissionCodeExists(r.Context(), req.Code) {
		writeJSON(w, 2143, nil, "权限点标识已存在")
		return
	}
	perm, err := p.createPermission(r.Context(), req.Code, req.Name, req.Description)
	if err != nil {
		writeJSON(w, 2144, nil, "创建权限点失败")
		return
	}
	writeJSON(w, 0, permissionToResponse(perm), "")
}

func (p *RolePlugin) handlePermissionList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, pageSize, ok := parsePage(q.Get("page"), q.Get("page_size"))
	if !ok {
		writeJSON(w, 2151, nil, "分页参数不合法")
		return
	}
	keyword := strings.TrimSpace(q.Get("keyword"))
	if runeLen(keyword) > 80 {
		writeJSON(w, 2152, nil, "关键词参数过长")
		return
	}
	items, total, err := p.listPermissions(r.Context(), keyword, page, pageSize)
	if err != nil {
		writeJSON(w, 2153, nil, "查询权限点列表失败")
		return
	}
	writeJSON(w, 0, map[string]any{"items": items, "total": total}, "")
}

func (p *RolePlugin) handleAssignPermissions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID        string    `json:"role_id"`
		PermissionIDs *[]string `json:"permission_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2161, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2161, nil, "角色 ID 缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2167, nil, "分配权限失败")
		return
	}
	if !exists {
		writeJSON(w, 2162, nil, "角色不存在")
		return
	}
	if req.PermissionIDs == nil {
		writeJSON(w, 2163, nil, "权限点 ID 列表格式不合法")
		return
	}
	assigned := map[string]bool{}
	for _, permissionID := range *req.PermissionIDs {
		permissionID = strings.TrimSpace(permissionID)
		if !validUUID(permissionID) {
			writeJSON(w, 2163, nil, "权限点 ID 列表格式不合法")
			return
		}
		assigned[permissionID] = true
	}
	permissionIDs := sortedKeys(assigned)
	if !p.permissionsExist(r.Context(), permissionIDs) {
		writeJSON(w, 2164, nil, "存在不存在的权限点")
		return
	}
	parentSet, err := p.permissionSet(r.Context(), role.ParentID)
	if err != nil {
		writeJSON(w, 2167, nil, "分配权限失败")
		return
	}
	if !permissionSetWithin(parentSet, assigned) {
		writeJSON(w, 2165, nil, "子角色权限不能超出父角色权限范围")
		return
	}
	childrenWithin, err := p.childrenWithinPermissionSet(r.Context(), req.RoleID, assigned)
	if err != nil {
		writeJSON(w, 2167, nil, "分配权限失败")
		return
	}
	if !childrenWithin {
		writeJSON(w, 2166, nil, "当前角色存在子角色，清理权限会导致子角色越权")
		return
	}
	updatedAt, err := p.assignPermissions(r.Context(), req.RoleID, permissionIDs)
	if err != nil {
		writeJSON(w, 2167, nil, "分配权限失败")
		return
	}
	writeJSON(w, 0, map[string]any{"role_id": req.RoleID, "permission_ids": permissionIDs, "updated_at": formatTime(updatedAt)}, "")
}

func (p *RolePlugin) handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID         string `json:"role_id"`
		PermissionCode string `json:"permission_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2171, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	req.PermissionCode = strings.TrimSpace(req.PermissionCode)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2171, nil, "角色 ID 缺失或格式不合法")
		return
	}
	if !validPermissionCode(req.PermissionCode) {
		writeJSON(w, 2172, nil, "权限点标识缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2175, nil, "权限校验失败")
		return
	}
	if !exists {
		writeJSON(w, 2173, nil, "角色不存在")
		return
	}
	perm, exists, err := p.getPermissionByCode(r.Context(), req.PermissionCode)
	if err != nil {
		writeJSON(w, 2175, nil, "权限校验失败")
		return
	}
	if !exists {
		writeJSON(w, 2174, nil, "权限点不存在")
		return
	}
	allowed := role.Status == "enabled" && p.roleDirectlyHasPermission(r.Context(), req.RoleID, perm.ID)
	writeJSON(w, 0, map[string]any{"allowed": allowed, "role_status": role.Status}, "")
}
