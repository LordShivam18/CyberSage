import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
    fetchGuardianDashboard,
    fetchCollectorHealth,
    fetchGuardianStats,
    listGuardianIncidents,
    listNdrIncidents,
    listApprovals,
    listEvaluations,
    listExecutions,
    fetchSafetyStatus,
    normalizePage,
} from './guardianApi';
import { formatTimestamp, formatTarget, severityStyle, statusStyle, sharedStyles as s } from './formatters';

const countOrUnavailable = (value) => (value === null || value === undefined ? 'unavailable' : value);

function Tile({ label, value, tone }) {
    return (
        <div style={styles.tile}>
            <span style={styles.tileLabel}>{label}</span>
            <strong style={{ ...styles.tileValue, ...(tone || {}) }}>{countOrUnavailable(value)}</strong>
        </div>
    );
}

const GuardianDashboard = ({ token }) => {
    const [loading, setLoading] = useState(true);
    const [refreshAt, setRefreshAt] = useState(null);
    const [errors, setErrors] = useState({});
    const [dashboard, setDashboard] = useState(null);
    const [collectors, setCollectors] = useState([]);
    const [guardianStats, setGuardianStats] = useState(null);
    const [guardianIncidents, setGuardianIncidents] = useState({ total: 0, items: [] });
    const [ndrIncidents, setNdrIncidents] = useState({ total: 0, items: [] });
    const [approvals, setApprovals] = useState({ total: 0, items: [] });
    const [evaluations, setEvaluations] = useState({ total: 0, items: [] });
    const [executions, setExecutions] = useState({ total: 0, items: [] });
    const [safety, setSafety] = useState(null);

    const load = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        const nextErrors = {};
        const settled = await Promise.allSettled([
            fetchGuardianDashboard(token),
            fetchCollectorHealth(token),
            fetchGuardianStats(token),
            listGuardianIncidents(token, { limit: 100 }),
            listNdrIncidents(token, { limit: 100 }),
            listApprovals(token, { limit: 20 }),
            listEvaluations(token, { limit: 5 }),
            listExecutions(token, { limit: 10 }),
            fetchSafetyStatus(token),
        ]);
        const get = (index, label) => {
            const entry = settled[index];
            if (entry.status === 'fulfilled') return entry.value;
            nextErrors[label] = entry.reason?.status === 403
                ? 'Forbidden for your role (HTTP 403)'
                : (entry.reason?.message || 'Unavailable');
            return null;
        };
        const dash = get(0, 'overview');
        const health = get(1, 'collectors');
        const stats = get(2, 'guardian');
        const gInc = get(3, 'guardianIncidents');
        const nInc = get(4, 'ndrIncidents');
        const apv = get(5, 'approvals');
        const evl = get(6, 'evaluations');
        const exe = get(7, 'executions');
        const sfty = get(8, 'safety');

        if (dash) setDashboard(dash);
        if (health) setCollectors(health.collectors || []);
        else if (settled[1].status === 'rejected') setCollectors([]);
        if (stats) setGuardianStats(stats);
        if (gInc) setGuardianIncidents(normalizePage(gInc));
        if (nInc) setNdrIncidents(normalizePage(nInc));
        if (apv) setApprovals(normalizePage(apv));
        if (evl) setEvaluations(normalizePage(evl));
        if (exe) setExecutions(normalizePage(exe));
        if (sfty) setSafety(sfty);
        setErrors(nextErrors);
        setRefreshAt(new Date());
        setLoading(false);
    }, [token]);

    useEffect(() => {
        load();
        const timer = setInterval(load, 30000);
        return () => clearInterval(timer);
    }, [load]);

    const severityDist = useMemo(() => {
        const counts = {};
        [...(guardianIncidents.items || []), ...(ndrIncidents.items || [])].forEach((inc) => {
            const key = String(inc.severity || 'unknown').toLowerCase();
            counts[key] = (counts[key] || 0) + 1;
        });
        return Object.entries(counts).sort((a, b) => b[1] - a[1]);
    }, [guardianIncidents, ndrIncidents]);

    const killSwitchActive = useMemo(() => {
        const switches = safety?.kill_switches || [];
        return switches.some((entry) => entry.active);
    }, [safety]);

    const blockedFailed = useMemo(() => {
        const items = executions.items || [];
        return items.filter((e) => ['blocked', 'execution_failed', 'verification_failed', 'rollback_failed'].includes(String(e.status)));
    }, [executions]);

    if (!token) {
        return <div style={s.empty}>Sign in to view Guardian protection status. No data is shown without authentication.</div>;
    }
    if (loading && !refreshAt) return <div style={styles.message}>Loading Guardian operations overview…</div>;

    const stale = refreshAt && (Date.now() - refreshAt.getTime() > 60000);
    const pendingApprovals = approvals.total ?? dashboard?.pending_approvals_count;
    const activeIncidents = dashboard?.active_incidents_count;

    return (
        <div style={styles.wrap}>
            <div style={styles.headerRow}>
                <div>
                    <h2 style={s.title}>Guardian Operations Overview</h2>
                    <span style={s.muted}>
                        Backend-grounded protection and execution safety status
                        {refreshAt ? ` · refreshed ${formatTimestamp(refreshAt.toISOString())}` : ''}
                        {stale ? ' · stale (refresh pending)' : ''}
                    </span>
                </div>
                <button style={s.btn} onClick={load} aria-label="Refresh Guardian overview">Refresh</button>
            </div>

            {Object.keys(errors).length > 0 && (
                <div style={s.error} role="alert">
                    Some sections are unavailable: {Object.entries(errors).map(([k, v]) => `${k} (${v})`).join('; ')}.
                    Unavailable is shown explicitly and never reported as zero.
                </div>
            )}

            {killSwitchActive && (
                <div style={styles.killBanner} role="alert">
                    Kill switch ACTIVE — new executions are blocked fail-closed. See Safety section below.
                </div>
            )}

            <div style={styles.tileGrid}>
                <Tile label="Active incidents (dashboard)" value={activeIncidents} tone={{ color: '#F85149' }} />
                <Tile label="Pending approvals" value={pendingApprovals} tone={{ color: '#D29922' }} />
                <Tile label="Policy evaluations (total)" value={evaluations.total} tone={{ color: '#6aa8ff' }} />
                <Tile label="Executions (total)" value={executions.total} tone={{ color: '#3FB950' }} />
                <Tile label="Blocked / failed (recent)" value={blockedFailed.length} tone={{ color: '#F85149' }} />
                <Tile label="Kill switch" value={safety ? (killSwitchActive ? 'ACTIVE' : 'clear') : 'unavailable'} tone={killSwitchActive ? { color: '#F85149' } : {}} />
            </div>

            <div style={styles.grid}>
                <section style={s.panel} aria-label="Guardian and collector health">
                    <h3 style={s.title}>Guardian &amp; Collector Health</h3>
                    {errors.guardian && <div style={s.muted}>Guardian stats unavailable: {errors.guardian}</div>}
                    {guardianStats ? (
                        <div style={s.muted}>
                            Agents: {guardianStats.agents?.active ?? 'n/a'}/{guardianStats.agents?.total ?? 'n/a'}
                            {' · '}Events: {guardianStats.events?.total ?? 'n/a'}
                            {' · '}Heartbeats: {guardianStats.heartbeats?.total ?? 'n/a'}
                        </div>
                    ) : (
                        <div style={s.muted}>Guardian health: {errors.guardian ? 'unavailable' : 'no data'}</div>
                    )}
                    <div style={{ ...s.tableWrap, marginTop: '12px' }}>
                        <table style={s.table}>
                            <thead><tr><th style={s.th}>Agent</th><th style={s.th}>Collector</th><th style={s.th}>State</th><th style={s.th}>Last event</th><th style={s.th}>Received</th></tr></thead>
                            <tbody>
                                {collectors.length === 0 && (
                                    <tr><td colSpan="5" style={s.empty}>{errors.collectors ? `Collectors unavailable (${errors.collectors})` : 'No collectors found'}</td></tr>
                                )}
                                {collectors.slice(0, 8).map((c, i) => (
                                    <tr key={i}>
                                        <td style={s.td}>{c.agent_id || 'n/a'}</td>
                                        <td style={s.td}>{c.collector_type || 'n/a'}</td>
                                        <td style={s.td}><span style={{ ...s.badge, ...(c.health_state === 'running' ? { color: '#3FB950', backgroundColor: 'rgba(46,160,67,0.15)' } : { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' }) }}>{c.health_state || 'unknown'}</span></td>
                                        <td style={s.td}>{formatTimestamp(c.last_event_at)}</td>
                                        <td style={s.td}>{c.events_received ?? 'n/a'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section style={s.panel} aria-label="Severity distribution">
                    <h3 style={s.title}>Severity Distribution</h3>
                    {severityDist.length === 0 && <div style={s.empty}>No incidents to distribute.</div>}
                    {severityDist.map(([sev, count]) => (
                        <div key={sev} style={styles.barRow}>
                            <span style={{ ...s.badge, ...severityStyle(sev) }}>{sev}</span>
                            <strong>{count}</strong>
                        </div>
                    ))}
                    <div style={s.muted}>Source: live Guardian + NDR incident listings (up to 100 each).</div>
                </section>

                <section style={s.panel} aria-label="Pending approvals">
                    <h3 style={s.title}>Pending Approvals</h3>
                    {errors.approvals && <div style={s.muted}>Approvals unavailable: {errors.approvals}</div>}
                    {(approvals.items || []).filter((a) => a.status === 'pending').slice(0, 5).map((a) => (
                        <div key={a.approval_id || a.id} style={styles.queueItem}>
                            <strong title={a.approval_id}>{String(a.approval_id || '').slice(0, 12)}…</strong>
                            <span style={s.muted}>{a.action_type}:{a.requested_action} · {formatTarget(a.target)}</span>
                        </div>
                    ))}
                    {!(approvals.items || []).some((a) => a.status === 'pending') && (
                        <div style={s.empty}>{errors.approvals ? 'Approvals unavailable — not zero.' : 'No pending approvals.'}</div>
                    )}
                </section>

                <section style={s.panel} aria-label="Recent policy evaluations">
                    <h3 style={s.title}>Recent Policy Evaluations</h3>
                    {errors.evaluations && <div style={s.muted}>Evaluations unavailable: {errors.evaluations}</div>}
                    {(evaluations.items || []).slice(0, 5).map((e) => (
                        <div key={e.evaluation_id} style={styles.queueItem}>
                            <span style={{ ...s.badge, ...statusStyle(e.decision) }}>{e.decision}</span>
                            <span style={s.muted} title={e.evaluation_id}>{String(e.evaluation_id || '').slice(0, 12)}… · {e.policy_id || 'no policy'} v{e.policy_version ?? '?'} · {e.action_type}:{e.action_name}</span>
                        </div>
                    ))}
                    {!(evaluations.items || []).length && (
                        <div style={s.empty}>{errors.evaluations ? 'Evaluations unavailable — not zero.' : 'No evaluations recorded.'}</div>
                    )}
                </section>

                <section style={s.panel} aria-label="Recent execution outcomes">
                    <h3 style={s.title}>Recent Execution Outcomes</h3>
                    {errors.executions && <div style={s.muted}>Executions unavailable: {errors.executions}</div>}
                    {(executions.items || []).slice(0, 5).map((e) => (
                        <div key={e.execution_id} style={styles.queueItem}>
                            <span style={{ ...s.badge, ...statusStyle(e.status) }}>{e.status}</span>
                            <span style={s.muted} title={e.execution_id}>{String(e.execution_id || '').slice(0, 12)}… · {e.policy_id} v{e.policy_version} · {e.action_type}:{e.action_name}</span>
                        </div>
                    ))}
                    {!(executions.items || []).length && (
                        <div style={s.empty}>{errors.executions ? 'Executions unavailable — not zero.' : 'No executions recorded.'}</div>
                    )}
                </section>

                <section style={s.panel} aria-label="Safety status">
                    <h3 style={s.title}>Kill Switch &amp; Circuit Breakers</h3>
                    {!safety && <div style={s.empty}>{errors.safety ? `Safety status unavailable (${errors.safety}) — not zero.` : 'No safety data.'}</div>}
                    {safety && (
                        <>
                            <div style={s.muted}>Kill switches: {(safety.kill_switches || []).filter((k) => k.active).length} active / {(safety.kill_switches || []).length} known</div>
                            {(safety.kill_switches || []).filter((k) => k.active).slice(0, 5).map((k, i) => (
                                <div key={i} style={styles.queueItem}>
                                    <span style={{ ...s.badge, color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' }}>active</span>
                                    <span style={s.muted}>{k.scope}:{k.switch_key} · {k.reason || 'no reason'} ({k.source || 'unknown'})</span>
                                </div>
                            ))}
                            <div style={{ ...s.muted, marginTop: '8px' }}>
                                Breakers: {Object.keys(safety.circuit_breakers || {}).length || 'none reported'}
                                {' · '}Limiter: {safety.rate_limiter ? JSON.stringify(safety.rate_limiter).slice(0, 160) : 'n/a'}
                            </div>
                            <div style={s.muted}>Modes: {(safety.execution_modes || []).join(', ') || 'n/a'}</div>
                        </>
                    )}
                </section>
            </div>

            <section style={s.panel} aria-label="Blocked or failed executions">
                <h3 style={s.title}>Recent Blocked / Failed Attempts</h3>
                {blockedFailed.length === 0 && (
                    <div style={s.empty}>{errors.executions ? 'Execution history unavailable — not zero.' : 'No blocked or failed attempts in the recent window.'}</div>
                )}
                {blockedFailed.slice(0, 8).map((e) => (
                    <div key={e.execution_id} style={styles.queueItem}>
                        <span style={{ ...s.badge, ...statusStyle(e.status) }}>{e.status}</span>
                        <span style={s.muted}>{e.policy_id} · {e.error || 'no reason recorded'} · {formatTimestamp(e.created_at)}</span>
                    </div>
                ))}
            </section>
        </div>
    );
};

const styles = {
    wrap: { display: 'flex', flexDirection: 'column', gap: '20px' },
    message: { color: '#8B949E', fontSize: '14px' },
    headerRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' },
    tileGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '12px' },
    tile: { backgroundColor: '#1E232E', border: '1px solid #2A303C', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '6px' },
    tileLabel: { color: '#8B949E', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.5px' },
    tileValue: { fontSize: '22px', fontWeight: '800', color: '#E0E6ED' },
    grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' },
    barRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #2A303C' },
    queueItem: { display: 'flex', flexDirection: 'column', gap: '4px', padding: '8px 0', borderBottom: '1px solid #2A303C' },
    killBanner: { backgroundColor: 'rgba(248,81,73,0.12)', border: '1px solid rgba(248,81,73,0.4)', color: '#F85149', borderRadius: '8px', padding: '12px 14px', fontWeight: '700' },
};

export default GuardianDashboard;
