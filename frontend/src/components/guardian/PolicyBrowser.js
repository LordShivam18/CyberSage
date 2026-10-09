import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
    listPolicies, getPolicy, updatePolicy, setPolicyEnabled, listEvaluations, listConflicts,
    getPreauthGrant, activatePreauth, revokePreauth,
} from './guardianApi';
import { formatTimestamp, statusStyle, sharedStyles as s, isExpired } from './formatters';

const MODES = ['approval_required', 'prepare_only', 'disabled'];

function PolicyBadge({ policy }) {
    const expired = isExpired(policy.expires_at);
    return (
        <span style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            <span style={{ ...s.badge, ...(policy.enabled ? { color: '#3FB950', backgroundColor: 'rgba(46,160,67,0.15)' } : { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' }) }}>
                {policy.enabled ? 'enabled' : 'disabled'}
            </span>
            <span style={{ ...s.badge, ...statusStyle(policy.mode) }}>{policy.mode}</span>
            {expired && <span style={{ ...s.badge, color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' }}>expired</span>}
            <span style={{ ...s.badge, color: '#8B949E', backgroundColor: 'rgba(139,148,158,0.15)' }}>v{policy.version}</span>
        </span>
    );
}

const PolicyBrowser = ({ token, role }) => {
    const [policies, setPolicies] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [filter, setFilter] = useState('all');
    const [query, setQuery] = useState('');
    const [selectedId, setSelectedId] = useState(null);
    const [detail, setDetail] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);
    const [detailError, setDetailError] = useState('');
    const [history, setHistory] = useState({ total: 0, items: [] });
    const [conflictMap, setConflictMap] = useState({});
    const [mutating, setMutating] = useState(false);
    const [message, setMessage] = useState('');
    const [editForm, setEditForm] = useState(null);
    const [grant, setGrant] = useState(null);
    const [grantLoading, setGrantLoading] = useState(false);
    const [preauthForm, setPreauthForm] = useState({
        allowed_actions: '[{"action_type": "network", "action_name": "block_destination"}]',
        target_scope: '{"destination_ips": ["203.0.113.66"]}',
        agent_scope: '{}',
        max_risk_score: 80,
        max_executions_per_hour: 5,
        cooldown_seconds: 300,
        expires_at: '',
        reason: '',
        rollback_required: false,
    });

    const isAdmin = role === 'administrator';

    const load = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        setError('');
        try {
            const data = await listPolicies(token, true);
            setPolicies(data.items || []);
            try {
                const conflicts = await listConflicts(token, { include_disabled: true });
                const map = {};
                (conflicts.items || []).filter((c) => c.is_conflict).forEach((c) => {
                    (c.rules || []).forEach((r) => {
                        map[r.policy_id] = (map[r.policy_id] || 0) + 1;
                    });
                });
                setConflictMap(map);
            } catch (e) {
                setConflictMap({});
            }
        } catch (err) {
            setError(err.status === 403 ? 'Forbidden for your role (HTTP 403).' : (err.message || 'Failed to load policies.'));
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => { load(); }, [load]);

    const loadDetail = useCallback(async (policyId) => {
        if (!token || !policyId) return;
        setSelectedId(policyId);
        setDetailLoading(true);
        setDetailError('');
        setDetail(null);
        try {
            const [policy, evals] = await Promise.all([
                getPolicy(token, policyId),
                listEvaluations(token, { policy_id: policyId, limit: 20 }).catch(() => ({ total: 0, items: [] })),
            ]);
            setDetail(policy);
            setHistory({ total: evals.total ?? (evals.items || []).length, items: evals.items || [] });
            setEditForm({ name: policy.name || '', description: policy.description || '', mode: policy.mode || 'approval_required', priority: policy.priority ?? 100, expires_at: policy.expires_at || '' });
            setGrant(null);
            setGrantLoading(true);
            try {
                const existing = await getPreauthGrant(token, policyId);
                setGrant(existing);
            } catch (err) {
                if (err.status !== 404) setDetailError((err.message || 'Failed to load grant state.'));
                setGrant(null);
            } finally {
                setGrantLoading(false);
            }
        } catch (err) {
            setDetailError(err.status === 404 ? 'Policy not found (HTTP 404).' : (err.message || 'Failed to load policy.'));
        } finally {
            setDetailLoading(false);
        }
    }, [token]);

    const filtered = useMemo(() => {
        const q = query.toLowerCase();
        return policies.filter((p) => {
            if (filter === 'enabled' && !p.enabled) return false;
            if (filter === 'disabled' && p.enabled) return false;
            if (filter === 'expired' && !isExpired(p.expires_at)) return false;
            if (filter === 'conflicting' && !conflictMap[p.policy_id]) return false;
            if (q && !`${p.policy_id} ${p.name}`.toLowerCase().includes(q)) return false;
            return true;
        });
    }, [policies, filter, query, conflictMap]);

    const mutate = async (operation, successText) => {
        setMutating(true);
        setMessage('');
        setError('');
        try {
            const result = await operation();
            setMessage(successText);
            await load();
            if (selectedId) await loadDetail(selectedId);
            return result;
        } catch (err) {
            setError(err.message || 'Mutation failed.');
            return null;
        } finally {
            setMutating(false);
        }
    };

    const confirmAnd = (label, fn) => {
        if (!window.confirm(`${label}? This is a privileged policy mutation and is audited.`)) return;
        mutate(fn, `${label} succeeded.`);
    };

    if (!token) return <div style={s.empty}>Sign in to browse automation policies.</div>;
    if (loading) return <div style={{ color: '#8B949E' }}>Loading policies…</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
                <h2 style={{ ...s.title, margin: 0 }}>Automation Policies</h2>
                <span style={s.muted}>{filtered.length} of {policies.length} shown</span>
                <span style={{ flex: 1 }} />
                <input aria-label="Search policies" placeholder="Search id or name" value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...s.input, maxWidth: '220px' }} />
                <select aria-label="Policy filter" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ ...s.input, maxWidth: '170px' }}>
                    <option value="all">All</option>
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                    <option value="expired">Expired</option>
                    <option value="conflicting">Conflicting</option>
                </select>
                <button style={s.btn} onClick={load} aria-label="Reload policies">Reload</button>
            </div>

            {error && <div style={s.error} role="alert">{error}</div>}
            {message && <div style={{ ...s.error, color: '#3FB950', borderColor: 'rgba(46,160,67,0.3)', backgroundColor: 'rgba(46,160,67,0.08)' }} role="status">{message}</div>}
            {!isAdmin && <div style={s.muted}>Your role ({role || 'unknown'}) is read-only for policy mutations. Activation, editing and enable/disable require administrator; the backend enforces this.</div>}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
                <section style={s.panel} aria-label="Policy list">
                    <div style={s.tableWrap}>
                        <table style={s.table}>
                            <thead><tr><th style={s.th}>Policy</th><th style={s.th}>Status</th><th style={s.th}>Rules</th></tr></thead>
                            <tbody>
                                {filtered.length === 0 && <tr><td colSpan="3" style={s.empty}>No policies match this filter.</td></tr>}
                                {filtered.map((p) => (
                                    <tr key={p.policy_id} onClick={() => loadDetail(p.policy_id)} style={{ cursor: 'pointer', backgroundColor: selectedId === p.policy_id ? '#232B36' : 'transparent' }} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') loadDetail(p.policy_id); }} aria-label={`Inspect policy ${p.policy_id}`}>
                                        <td style={s.td}>
                                            <strong title={p.policy_id}>{p.policy_id}</strong>
                                            <div style={s.muted}>{p.name} · priority {p.priority}</div>
                                            {conflictMap[p.policy_id] ? <div style={{ ...s.badge, color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)', marginTop: '4px' }}>{conflictMap[p.policy_id]} conflict(s)</div> : null}
                                        </td>
                                        <td style={s.td}><PolicyBadge policy={p} /></td>
                                        <td style={s.td}>{(p.rules || []).length}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section style={s.panel} aria-label="Policy detail">
                    <h3 style={s.title}>Policy Detail</h3>
                    {!selectedId && <div style={s.empty}>Select a policy to inspect rules and precedence.</div>}
                    {detailLoading && <div style={s.muted}>Loading policy detail…</div>}
                    {detailError && <div style={s.error} role="alert">{detailError}</div>}
                    {detail && (
                        <>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                <strong>{detail.policy_id}</strong>
                                <PolicyBadge policy={detail} />
                            </div>
                            <div style={{ ...s.muted, marginTop: '6px' }}>
                                {detail.description || 'No description'} · updated {formatTimestamp(detail.updated_at)} · expires {detail.expires_at ? formatTimestamp(detail.expires_at) : 'never'}
                            </div>
                            <h4 style={{ color: '#E0E6ED', margin: '14px 0 8px 0' }}>Rules &amp; precedence</h4>
                            <div style={s.muted}>Winner order: higher rule priority → narrower scope → higher policy priority → lexicographic ids. DENY overrides all non-DENY.</div>
                            <div style={{ ...s.tableWrap, marginTop: '8px' }}>
                                <table style={s.table}>
                                    <thead><tr><th style={s.th}>Rule</th><th style={s.th}>Action</th><th style={s.th}>Conditions</th><th style={s.th}>Outcome</th></tr></thead>
                                    <tbody>
                                        {(detail.rules || []).map((r) => (
                                            <tr key={r.rule_id}>
                                                <td style={s.td}><strong title={r.rule_id}>{r.rule_id}</strong><div style={s.muted}>priority {r.priority}</div><div style={s.muted}>{r.description}</div></td>
                                                <td style={s.td}>{r.action_type}:{r.action_name}<div style={s.muted}>scope: {Object.keys(r.target_scope || {}).join(', ') || 'any'}</div></td>
                                                <td style={s.td}>risk {r.min_risk_score}–{r.max_risk_score}<br />severity {r.incident_severity || 'any'}<br /><span style={s.muted}>{JSON.stringify(r.target_scope || {})}</span></td>
                                                <td style={s.td}><span style={{ ...s.badge, ...statusStyle(r.decision) }}>{r.decision}</span><div style={s.muted}>approval: {r.approval_mode} · requires_approval={String(r.requires_approval)}</div></td>
                                            </tr>
                                        ))}
                                        {!(detail.rules || []).length && <tr><td colSpan="4" style={s.empty}>No rules in this policy.</td></tr>}
                                    </tbody>
                                </table>
                            </div>

                            <h4 style={{ color: '#E0E6ED', margin: '14px 0 8px 0' }}>Version history &amp; evaluations</h4>
                            <div style={s.muted}>
                                Current version v{detail.version}. Only the current row is persisted; history is reconstructed from evaluation audit rows.
                                {history.items.some((e) => (e.policy_version ?? 0) < detail.version) ? ' Some evaluations reference superseded versions.' : ''}
                            </div>
                            {(history.items || []).slice(0, 8).map((e) => (
                                <div key={e.evaluation_id} style={{ padding: '6px 0', borderBottom: '1px solid #2A303C', display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                    <span style={{ ...s.badge, ...statusStyle(e.decision) }}>{e.decision}</span>
                                    <span style={s.muted}>v{e.policy_version} · rule {e.matched_rule_id || 'none'} · {formatTimestamp(e.created_at)}{(e.policy_version ?? 0) < detail.version ? ' · superseded' : ''}</span>
                                </div>
                            ))}
                            {!(history.items || []).length && <div style={s.empty}>No historical evaluations for this policy.</div>}

                            <h4 style={{ color: '#E0E6ED', margin: '14px 0 8px 0' }}>Bounded pre-authorization (Slice 4)</h4>
                            <div style={s.muted}>
                                Disabled by default. Activation is an explicit administrator operation, persisted and audited,
                                bound to the current policy version. Existing evaluations never gain new authorization.
                                Kill switch overrides all authorization.
                            </div>
                            {grantLoading && <div style={s.muted}>Loading grant state…</div>}
                            {!grantLoading && !grant && <div style={s.empty}>No bounded grant for this policy — pre-authorized execution is disabled; manual approval remains required.</div>}
                            {!grantLoading && grant && (
                                <div style={{ ...s.muted, color: '#C9D1D9', marginTop: '6px' }}>
                                    <span style={{ ...s.badge, ...(grant.active ? { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' } : { color: '#8B949E', backgroundColor: 'rgba(139,148,158,0.15)' }) }}>
                                        {grant.active ? 'grant active' : 'grant revoked/inactive'}
                                    </span>
                                    <div style={{ marginTop: '6px' }}>
                                        Policy v{grant.policy_version} · risk cap {grant.max_risk_score} · {grant.max_executions_per_hour}/hour · cooldown {grant.cooldown_seconds}s · expires {grant.expires_at ? formatTimestamp(grant.expires_at) : 'n/a'}
                                    </div>
                                    <div>Allowed: {(grant.allowed_actions || []).map((a) => `${a.action_type}:${a.action_name}`).join(', ') || 'none'}</div>
                                    <div>Target scope: {JSON.stringify(grant.target_scope || {})}</div>
                                    <div>Agent scope: {JSON.stringify(grant.agent_scope || {}) || 'none'} · by {grant.activated_by || 'n/a'} at {formatTimestamp(grant.activated_at)}</div>
                                </div>
                            )}
                            {isAdmin && (
                                <div style={{ display: 'flex', gap: '8px', marginTop: '10px', flexWrap: 'wrap' }}>
                                    {grant?.active && (
                                        <button style={{ ...s.btn, ...s.btnDanger }} disabled={mutating} onClick={() => confirmAnd('Revoke bounded grant', () => revokePreauth(token, { policy_id: detail.policy_id, reason: 'operator revocation from Guardian Ops UI' }).then(() => loadDetail(detail.policy_id)))} aria-label="Revoke bounded grant">
                                            Revoke grant
                                        </button>
                                    )}
                                </div>
                            )}
                            {isAdmin && (
                                <form
                                    style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        let allowed;
                                        let targetScope;
                                        let agentScope;
                                        try {
                                            allowed = JSON.parse(preauthForm.allowed_actions);
                                            targetScope = JSON.parse(preauthForm.target_scope);
                                            agentScope = preauthForm.agent_scope.trim() ? JSON.parse(preauthForm.agent_scope) : {};
                                        } catch (err) {
                                            setError(`Invalid grant JSON: ${err.message}`);
                                            return;
                                        }
                                        confirmAnd('Activate bounded grant', () => activatePreauth(token, {
                                            policy_id: detail.policy_id,
                                            allowed_actions: allowed,
                                            target_scope: targetScope,
                                            agent_scope: agentScope,
                                            max_risk_score: Number(preauthForm.max_risk_score),
                                            max_executions_per_hour: Number(preauthForm.max_executions_per_hour),
                                            cooldown_seconds: Number(preauthForm.cooldown_seconds),
                                            expires_at: preauthForm.expires_at,
                                            reason: preauthForm.reason || 'bounded rollout from Guardian Ops UI',
                                            rollback_required: Boolean(preauthForm.rollback_required),
                                        }).then(() => loadDetail(detail.policy_id)));
                                    }}
                                >
                                    <span style={s.label}>Activate bounded grant (admin only — shows full scope before activation)</span>
                                    <label style={s.label}>Allowed actions (JSON list, concrete registered actions only, no wildcards)<textarea style={{ ...s.input, fontFamily: 'monospace' }} rows={2} value={preauthForm.allowed_actions} onChange={(e) => setPreauthForm({ ...preauthForm, allowed_actions: e.target.value })} /></label>
                                    <label style={s.label}>Target scope (JSON, at least one key required)<textarea style={{ ...s.input, fontFamily: 'monospace' }} rows={2} value={preauthForm.target_scope} onChange={(e) => setPreauthForm({ ...preauthForm, target_scope: e.target.value })} /></label>
                                    <label style={s.label}>Agent scope (JSON, optional)<textarea style={{ ...s.input, fontFamily: 'monospace' }} rows={2} value={preauthForm.agent_scope} onChange={(e) => setPreauthForm({ ...preauthForm, agent_scope: e.target.value })} /></label>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px' }}>
                                        <label style={s.label}>Risk cap<input style={s.input} type="number" min={0} max={100} step="0.1" value={preauthForm.max_risk_score} onChange={(e) => setPreauthForm({ ...preauthForm, max_risk_score: e.target.value })} /></label>
                                        <label style={s.label}>Max/hour<input style={s.input} type="number" min={1} max={1000} value={preauthForm.max_executions_per_hour} onChange={(e) => setPreauthForm({ ...preauthForm, max_executions_per_hour: e.target.value })} /></label>
                                        <label style={s.label}>Cooldown (s)<input style={s.input} type="number" min={0} max={86400} value={preauthForm.cooldown_seconds} onChange={(e) => setPreauthForm({ ...preauthForm, cooldown_seconds: e.target.value })} /></label>
                                    </div>
                                    <label style={s.label}>Expires at (ISO, required)<input style={s.input} placeholder="2027-01-01T00:00:00Z" value={preauthForm.expires_at} onChange={(e) => setPreauthForm({ ...preauthForm, expires_at: e.target.value })} required /></label>
                                    <label style={s.label}>Reason<input style={s.input} value={preauthForm.reason} onChange={(e) => setPreauthForm({ ...preauthForm, reason: e.target.value })} maxLength={2048} /></label>
                                    <button style={{ ...s.btn, ...s.btnPrimary }} type="submit" disabled={mutating}>Activate bounded grant (audited)</button>
                                </form>
                            )}

                            {isAdmin && (
                                <div style={{ display: 'flex', gap: '8px', marginTop: '14px', flexWrap: 'wrap' }}>
                                    <button style={s.btn} disabled={mutating} onClick={() => confirmAnd(detail.enabled ? 'Disable policy' : 'Enable policy', () => setPolicyEnabled(token, detail.policy_id, !detail.enabled))} aria-label={detail.enabled ? 'Disable policy' : 'Enable policy'}>
                                        {detail.enabled ? 'Disable' : 'Enable'}
                                    </button>
                                </div>
                            )}
                            {isAdmin && editForm && (
                                <form
                                    style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        confirmAnd('Save policy edits', () => updatePolicy(token, detail.policy_id, {
                                            name: editForm.name,
                                            description: editForm.description,
                                            mode: editForm.mode,
                                            priority: Number(editForm.priority),
                                            expires_at: editForm.expires_at || null,
                                        }));
                                    }}
                                >
                                    <span style={s.label}>Edit policy (admin only, bumps version)</span>
                                    <label style={s.label}>Name<input style={s.input} value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} required maxLength={255} /></label>
                                    <label style={s.label}>Description<textarea style={s.input} value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} maxLength={4096} rows={2} /></label>
                                    <label style={s.label}>Mode<select style={s.input} value={editForm.mode} onChange={(e) => setEditForm({ ...editForm, mode: e.target.value })}>{MODES.map((m) => <option key={m} value={m}>{m}</option>)}</select></label>
                                    <label style={s.label}>Priority (0–1000)<input style={s.input} type="number" min={0} max={1000} value={editForm.priority} onChange={(e) => setEditForm({ ...editForm, priority: e.target.value })} /></label>
                                    <label style={s.label}>Expires at (ISO, blank = never)<input style={s.input} placeholder="2026-12-31T00:00:00Z" value={editForm.expires_at} onChange={(e) => setEditForm({ ...editForm, expires_at: e.target.value })} /></label>
                                    <button style={{ ...s.btn, ...s.btnPrimary }} type="submit" disabled={mutating}>Save edits (version bump)</button>
                                </form>
                            )}
                        </>
                    )}
                </section>
            </div>
        </div>
    );
};

export default PolicyBrowser;
