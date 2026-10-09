import React, { useCallback, useEffect, useState } from 'react';
import { listExecutions, getExecution, listActionAttempts, listGuardianAudit } from './guardianApi';
import { formatTimestamp, formatTarget, truncateId, statusStyle, sharedStyles as s } from './formatters';

const STATUSES = ['', 'blocked', 'succeeded', 'executing', 'verifying', 'execution_failed', 'verification_failed', 'rollback_available', 'rolled_back', 'rollback_failed'];

const ExecutionBrowser = ({ token }) => {
    const [filters, setFilters] = useState({ policy_id: '', status: '', limit: 20, offset: 0 });
    const [page, setPage] = useState({ total: 0, items: [] });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [selectedId, setSelectedId] = useState(null);
    const [detail, setDetail] = useState(null);
    const [detailError, setDetailError] = useState('');
    const [related, setRelated] = useState({ actions: [], audit: [] });

    const load = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        setError('');
        try {
            const data = await listExecutions(token, {
                policy_id: filters.policy_id || undefined,
                status: filters.status || undefined,
                limit: filters.limit,
                offset: filters.offset,
            });
            setPage({ total: data.total ?? (data.items || []).length, items: data.items || [] });
        } catch (err) {
            setError(err.status === 403 ? 'Forbidden for your role (HTTP 403).' : (err.message || 'Failed to load executions.'));
        } finally {
            setLoading(false);
        }
    }, [token, filters]);

    useEffect(() => { load(); }, [load]);

    const loadDetail = async (executionId) => {
        setSelectedId(executionId);
        setDetail(null);
        setDetailError('');
        try {
            const [exec, actions, audit] = await Promise.all([
                getExecution(token, executionId),
                listActionAttempts(token, { limit: 5 }).catch(() => ({ items: [] })),
                listGuardianAudit(token, { limit: 5 }).catch(() => ({ items: [] })),
            ]);
            setDetail(exec);
            setRelated({
                actions: (actions.items || []).filter((a) => a.action_id === exec.action_id).slice(0, 3),
                audit: (audit.items || []).filter((a) => a.action_id === exec.action_id).slice(0, 3),
            });
        } catch (err) {
            setDetailError(err.status === 404 ? 'Execution not found (HTTP 404).' : (err.message || 'Failed to load execution.'));
        }
    };

    if (!token) return <div style={s.empty}>Sign in to inspect execution and audit history.</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <h2 style={{ ...s.title, margin: 0 }}>Executions &amp; Audit Observability</h2>
                <span style={s.muted}>{page.total} total · showing {(page.items || []).length}</span>
                <span style={{ flex: 1 }} />
                <input aria-label="Filter by policy id" placeholder="policy_id filter" value={filters.policy_id} onChange={(e) => setFilters({ ...filters, policy_id: e.target.value, offset: 0 })} style={{ ...s.input, maxWidth: '180px' }} />
                <select aria-label="Filter by status" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value, offset: 0 })} style={{ ...s.input, maxWidth: '190px' }}>
                    {STATUSES.map((st) => <option key={st} value={st}>{st || 'All statuses'}</option>)}
                </select>
                <button style={s.btn} onClick={() => setFilters({ ...filters, offset: Math.max(0, filters.offset - filters.limit) })} disabled={filters.offset === 0} aria-label="Previous page">Prev</button>
                <button style={s.btn} onClick={() => setFilters({ ...filters, offset: filters.offset + filters.limit })} disabled={(page.items || []).length < filters.limit} aria-label="Next page">Next</button>
                <button style={s.btn} onClick={load} aria-label="Reload executions">Reload</button>
            </div>

            <div style={s.muted}>
                Read-only observability. Execution success is never inferred from an HTTP response alone — verify the independent verification
                result, rollback state and audit record below. No execution can be started from this view; approved manual execution remains a
                separately authorized Slice 2 API call with a valid approval.
            </div>
            {error && <div style={s.error} role="alert">{error}</div>}
            {loading && <div style={{ color: '#8B949E' }}>Loading executions…</div>}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '16px' }}>
                <section style={s.panel} aria-label="Execution list">
                    <div style={s.tableWrap}>
                        <table style={s.table}>
                            <thead><tr><th style={s.th}>Execution</th><th style={s.th}>Policy / action</th><th style={s.th}>Status</th></tr></thead>
                            <tbody>
                                {(page.items || []).length === 0 && !loading && <tr><td colSpan="3" style={s.empty}>No executions match these filters.</td></tr>}
                                {(page.items || []).map((e) => (
                                    <tr key={e.execution_id} onClick={() => loadDetail(e.execution_id)} tabIndex={0} onKeyDown={(ev) => { if (ev.key === 'Enter') loadDetail(e.execution_id); }} style={{ cursor: 'pointer', backgroundColor: selectedId === e.execution_id ? '#232B36' : 'transparent' }} aria-label={`Inspect execution ${e.execution_id}`}>
                                        <td style={s.td}><strong title={e.execution_id}>{truncateId(e.execution_id)}</strong><div style={s.muted}>{formatTimestamp(e.created_at)}</div></td>
                                        <td style={s.td}>{e.policy_id} v{e.policy_version}<div style={s.muted}>{e.action_type}:{e.action_name}</div></td>
                                        <td style={s.td}><span style={{ ...s.badge, ...statusStyle(e.status) }}>{e.status}</span>{e.error ? <div style={s.muted} title={e.error}>{String(e.error).slice(0, 80)}</div> : null}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section style={s.panel} aria-label="Execution detail" aria-live="polite">
                    <h3 style={s.title}>Execution Detail</h3>
                    {!selectedId && <div style={s.empty}>Select an execution to inspect identity, gates, verification, rollback and audit references.</div>}
                    {detailError && <div style={s.error} role="alert">{detailError}</div>}
                    {detail && (
                        <>
                            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '13px' }}>
                                <span style={s.muted}>Execution id</span><strong title={detail.execution_id}>{detail.execution_id}</strong>
                                <span style={s.muted}>Correlation</span><strong>{detail.correlation_id || 'n/a'}</strong>
                                <span style={s.muted}>Policy</span><strong>{detail.policy_id} v{detail.policy_version} · rule {detail.rule_id || 'n/a'}</strong>
                                <span style={s.muted}>Evaluation</span><strong title={detail.evaluation_id}>{detail.evaluation_id || 'no binding'}</strong>
                                <span style={s.muted}>Approval / decision</span><strong>{detail.approval_id || 'n/a'} / {detail.decision_id || 'n/a'}</strong>
                                <span style={s.muted}>Action &amp; target</span><strong>{detail.action_type}:{detail.action_name} · {formatTarget(detail.target)}</strong>
                                <span style={s.muted}>Actor</span><strong>{detail.actor || 'n/a'} · action {detail.action_id || 'n/a'}</strong>
                                <span style={s.muted}>State</span><span><span style={{ ...s.badge, ...statusStyle(detail.status) }}>{detail.status}</span></span>
                                <span style={s.muted}>Error / reason</span><strong>{detail.error || 'none recorded'}</strong>
                                <span style={s.muted}>Created / updated</span><strong>{formatTimestamp(detail.created_at)} / {formatTimestamp(detail.updated_at)}</strong>
                            </div>

                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Safety gates (ordered, auditable)</h4>
                            <div style={s.tableWrap}>
                                <table style={s.table}>
                                    <thead><tr><th style={s.th}>Gate</th><th style={s.th}>Passed</th><th style={s.th}>Reason</th></tr></thead>
                                    <tbody>
                                        {(detail.gates || detail.gate_results || []).map((g, i) => (
                                            <tr key={i}>
                                                <td style={s.td}>{g.gate}</td>
                                                <td style={s.td}>{String(g.passed)}</td>
                                                <td style={s.td}>{g.reason}{g.detail ? <div style={s.muted}>{g.detail}</div> : null}</td>
                                            </tr>
                                        ))}
                                        {!(detail.gates || detail.gate_results || []).length && <tr><td colSpan="3" style={s.empty}>No gate results recorded.</td></tr>}
                                    </tbody>
                                </table>
                            </div>

                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Independent verification</h4>
                            {!detail.verification && <div style={s.empty}>No independent verification recorded (blocked attempts never run the action).</div>}
                            {detail.verification && (
                                <div style={s.muted}>
                                    passed: {String(detail.verification.passed ?? detail.verification.verification_passed ?? 'unknown')}
                                    {' · '}checks: {JSON.stringify(detail.verification.checks || detail.verification.verification_result || []).slice(0, 300)}
                                    {detail.verification.failure_reason ? ` · failure: ${detail.verification.failure_reason}` : ''}
                                </div>
                            )}

                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Rollback</h4>
                            {!detail.rollback && <div style={s.empty}>No rollback staged. Rollback is explicit-only and appears only after a verified failure with snapshot support.</div>}
                            {detail.rollback && <div style={s.muted}>{JSON.stringify(detail.rollback).slice(0, 500)}</div>}

                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Audit references</h4>
                            <div style={s.muted}>Execution result: {JSON.stringify(detail.execution_result || {}).slice(0, 300) || 'n/a'}</div>
                            {(related.actions || []).map((a) => (
                                <div key={a.action_id} style={s.muted}>action attempt {a.action_id}: {a.status}</div>
                            ))}
                            {(related.audit || []).map((a) => (
                                <div key={a.audit_id || a.id} style={s.muted}>audit {a.audit_id || a.id}: {a.status} by {a.actor} at {formatTimestamp(a.created_at)}</div>
                            ))}
                        </>
                    )}
                </section>
            </div>
        </div>
    );
};

export default ExecutionBrowser;
