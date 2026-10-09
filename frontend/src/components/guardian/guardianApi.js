/* Guardian Slice 3 API client — reuses existing backend endpoints only.
 * No policy mutation is simulated in the browser; every mutation calls the
 * authorized backend API. Backend RBAC remains authoritative.
 * Never logs tokens or secrets.
 */

const joinParams = (params = {}) => {
    const search = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') return;
        search.append(key, String(value));
    });
    const query = search.toString();
    return query ? `?${query}` : '';
};

const safeDetail = async (res) => {
    try {
        const data = await res.json();
        if (typeof data === 'string') return data;
        if (data && typeof data.detail === 'string') return data.detail;
        if (data && typeof data.detail === 'object') {
            return data.detail.error || data.detail.gate
                ? `${data.detail.error || ''} ${data.detail.gate ? `(gate: ${data.detail.gate})` : ''}`.trim()
                : JSON.stringify(data.detail).slice(0, 500);
        }
        if (data && data.message) return String(data.message).slice(0, 500);
        return `HTTP ${res.status}`;
    } catch (e) {
        return `HTTP ${res.status}`;
    }
};

export async function guardianFetch(path, token, options = {}) {
    const { method = 'GET', body, params } = options;
    const url = `${path}${joinParams(params)}`;
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    let res;
    try {
        res = await fetch(url, {
            method,
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
    } catch (err) {
        throw new Error('Network error: API unreachable');
    }
    if (!res.ok) {
        const detail = await safeDetail(res);
        const error = new Error(detail || `Request failed (HTTP ${res.status})`);
        error.status = res.status;
        throw error;
    }
    try {
        return await res.json();
    } catch (e) {
        return {};
    }
}

export const getRoleFromToken = (token) => {
    if (!token || typeof token !== 'string') return null;
    try {
        const payload = token.split('.')[1];
        const json = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
        return json.role || null;
    } catch (e) {
        return null;
    }
};

export const V5 = '/api/v1/guardian/automation/v5';

export const fetchGuardianDashboard = (token) =>
    guardianFetch('/api/v1/guardian/dashboard', token);

export const fetchCollectorHealth = (token) =>
    guardianFetch('/api/v1/guardian/collectors/health', token);

export const fetchGuardianStats = (token) =>
    guardianFetch('/api/v1/guardian/stats', token);

export const fetchNdrMetrics = () =>
    guardianFetch('/api/v1/metrics', null);

export const listNdrIncidents = (token, { limit = 50, offset = 0, status, severity } = {}) =>
    guardianFetch('/api/v1/incidents', token, { params: { limit, offset, status, severity } });

export const listGuardianIncidents = (token, { limit = 50, offset = 0, severity, status } = {}) =>
    guardianFetch('/api/v1/guardian/incidents', token, { params: { limit, offset, severity, status } });

export const listApprovals = (token, { limit = 50, offset = 0, status, action_type } = {}) =>
    guardianFetch('/api/v1/guardian/approvals', token, { params: { limit, offset, status, action_type } });

export const listPolicies = (token, includeDisabled = true) =>
    guardianFetch(`${V5}/policies`, token, { params: { include_disabled: includeDisabled } });

export const getPolicy = (token, policyId) =>
    guardianFetch(`${V5}/policies/${encodeURIComponent(policyId)}`, token);

export const createPolicy = (token, payload) =>
    guardianFetch(`${V5}/policies`, token, { method: 'POST', body: payload });

export const updatePolicy = (token, policyId, payload) =>
    guardianFetch(`${V5}/policies/${encodeURIComponent(policyId)}`, token, { method: 'PATCH', body: payload });

export const setPolicyEnabled = (token, policyId, enabled) =>
    guardianFetch(
        `${V5}/policies/${encodeURIComponent(policyId)}/${enabled ? 'enable' : 'disable'}`,
        token,
        { method: 'POST' }
    );

export const simulatePolicy = (token, payload) =>
    guardianFetch(`${V5}/simulate`, token, { method: 'POST', body: payload });

export const listEvaluations = (token, { policy_id, incident_id, limit = 50, offset = 0 } = {}) =>
    guardianFetch(`${V5}/evaluations`, token, { params: { policy_id, incident_id, limit, offset } });

export const listConflicts = (token, { policy_id, include_disabled = true } = {}) =>
    guardianFetch(`${V5}/conflicts`, token, { params: { policy_id, include_disabled } });

export const listExecutions = (token, { policy_id, incident_id, status, limit = 50, offset = 0 } = {}) =>
    guardianFetch(`${V5}/executions`, token, { params: { policy_id, incident_id, status, limit, offset } });

export const getExecution = (token, executionId) =>
    guardianFetch(`${V5}/executions/${encodeURIComponent(executionId)}`, token);

export const fetchSafetyStatus = (token) =>
    guardianFetch(`${V5}/safety/status`, token);

export const listActionAttempts = (token, { limit = 50, offset = 0, status, action_type } = {}) =>
    guardianFetch('/api/v1/guardian/actions', token, { params: { limit, offset, status, action_type } });

export const fetchActionRegistry = (token) =>
    guardianFetch('/api/v1/guardian/actions/registry', token);

export const listGuardianAudit = (token, { limit = 50, offset = 0, status } = {}) =>
    guardianFetch('/api/v1/guardian/audit', token, { params: { limit, offset, status } });

export const normalizePage = (data) => {
    if (!data) return { total: 0, items: [] };
    if (Array.isArray(data)) return { total: data.length, items: data };
    if (Array.isArray(data.items)) return { total: data.total ?? data.items.length, items: data.items };
    // ApprovalQueue legacy shape {approvals: [...]}
    if (Array.isArray(data.approvals)) return { total: data.total ?? data.approvals.length, items: data.approvals };
    if (Array.isArray(data.policies)) return { total: data.policies.length, items: data.policies };
    if (Array.isArray(data.collectors)) return { total: data.collectors.length, items: data.collectors };
    return { total: 0, items: [] };
};
