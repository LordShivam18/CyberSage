import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { listConflicts, listPolicies } from './guardianApi';
import { sharedStyles as s } from './formatters';

const ConflictViewer = ({ token }) => {
    const [items, setItems] = useState([]);
    const [summary, setSummary] = useState({ total: 0, conflicts: 0, advisories: 0 });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [filter, setFilter] = useState('all');
    const [policyFilter, setPolicyFilter] = useState('');
    const [includeDisabled, setIncludeDisabled] = useState(true);
    const [policies, setPolicies] = useState([]);

    const load = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        setError('');
        try {
            const [conflicts, pols] = await Promise.all([
                listConflicts(token, { policy_id: policyFilter || undefined, include_disabled: includeDisabled }),
                listPolicies(token, true).catch(() => ({ items: [] })),
            ]);
            setItems(conflicts.items || []);
            setSummary({ total: conflicts.total ?? 0, conflicts: conflicts.conflicts ?? 0, advisories: conflicts.notices ?? conflicts.advisories ?? 0 });
            setPolicies(pols.items || []);
        } catch (err) {
            setError(err.status === 403 ? 'Forbidden for your role (HTTP 403).' : (err.message || 'Failed to load conflicts.'));
        } finally {
            setLoading(false);
        }
    }, [token, policyFilter, includeDisabled]);

    useEffect(() => { load(); }, [load]);

    const filtered = useMemo(() => {
        if (filter === 'conflicts') return items.filter((c) => c.is_conflict);
        if (filter === 'redundant') return items.filter((c) => c.type === 'redundant_overlap');
        if (filter === 'dormant') return items.filter((c) => c.type === 'dormant_overlap');
        if (filter === 'shadow') return items.filter((c) => c.type === 'precedence_shadow' || (c.shadowed && c.is_conflict));
        return items;
    }, [items, filter]);

    if (!token) return <div style={s.empty}>Sign in to inspect policy conflicts.</div>;
    if (loading) return <div style={{ color: '#8B949E' }}>Analyzing policy overlaps…</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <h2 style={{ ...s.title, margin: 0 }}>Conflict &amp; Overlap Inspector</h2>
                <span style={s.muted}>{summary.conflicts} conflicts · {summary.advisories} advisories · {summary.total} overlapping pairs</span>
                <span style={{ flex: 1 }} />
                <select aria-label="Conflict filter" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ ...s.input, maxWidth: '190px' }}>
                    <option value="all">All overlaps</option>
                    <option value="conflicts">Conflicts only (deny vs non-deny)</option>
                    <option value="shadow">Shadowed / precedence</option>
                    <option value="redundant">Redundant overlaps</option>
                    <option value="dormant">Dormant (inactive policy)</option>
                </select>
                <select aria-label="Policy filter" value={policyFilter} onChange={(e) => setPolicyFilter(e.target.value)} style={{ ...s.input, maxWidth: '200px' }}>
                    <option value="">All policies</option>
                    {policies.map((p) => <option key={p.policy_id} value={p.policy_id}>{p.policy_id}</option>)}
                </select>
                <label style={{ ...s.muted, display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <input type="checkbox" checked={includeDisabled} onChange={(e) => setIncludeDisabled(e.target.checked)} />
                    Include disabled
                </label>
                <button style={s.btn} onClick={load} aria-label="Re-analyze conflicts">Re-analyze</button>
            </div>

            <div style={s.error} role="note">
                Advisory only — conflict visualization never overrides the deterministic policy engine.
                A conflict requires overlapping applicability AND incompatible outcomes (DENY vs non-DENY).
                Different actions alone are never labeled conflicting.
            </div>
            {error && <div style={s.error} role="alert">{error}</div>}
            {filtered.length === 0 && <div style={s.empty}>No overlapping rule pairs for this filter. This means no conflicting decisions share match conditions — not that policies are absent.</div>}

            {filtered.map((c) => (
                <section key={c.conflict_id} style={s.panel} aria-label={`Conflict ${c.conflict_id}`}>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                        <span style={{
                            ...s.badge,
                            ...(c.is_conflict
                                ? { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' }
                                : { color: '#D29922', backgroundColor: 'rgba(210,153,34,0.15)' }),
                        }}>
                            {c.is_conflict ? 'conflict' : c.type.replace(/_/g, ' ')}
                        </span>
                        <span style={s.muted}>severity {c.severity} · runtime impact: {String(c.runtime_impact)} · {c.ambiguous ? 'ambiguous (partial overlap, operator review)' : 'fully shadowed'}</span>
                        <span style={{ flex: 1 }} />
                        <span style={s.muted} title={c.conflict_id}>{c.conflict_id.slice(0, 12)}…</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', marginTop: '10px', fontSize: '13px' }}>
                        <div>
                            <div style={s.label}>Rules</div>
                            {(c.rules || []).map((r) => (
                                <div key={`${r.policy_id}:${r.rule_id}`} style={{ padding: '4px 0' }}>
                                    <strong>{r.policy_id}:{r.rule_id}</strong>
                                    <span style={s.muted}> · {r.decision} · priority {r.priority} · {r.action_type}:{r.action_name}</span>
                                </div>
                            ))}
                        </div>
                        <div>
                            <div style={s.label}>Overlap (shared applicability)</div>
                            <div style={s.muted}>risk {c.overlap?.risk_range?.[0]}–{c.overlap?.risk_range?.[1]} · severity {c.overlap?.severities?.join(', ') || 'any'}</div>
                            <div style={s.muted}>scope keys: {c.overlap?.scope_keys?.join(', ') || 'broad (one side unconstrained)'}</div>
                            <div style={s.muted}>actions: {(c.overlap?.action_type || []).join(' vs ')} / {(c.overlap?.action_name || []).join(' vs ')}</div>
                        </div>
                        <div>
                            <div style={s.label}>Precedence &amp; shadowing</div>
                            <div><strong>{c.precedence?.winner_rule_id}</strong><span style={s.muted}> wins ({c.precedence?.reason}) · {c.precedence?.winner_policy_id} v{c.precedence?.winner_policy_version}</span></div>
                            <div style={s.muted}>shadowed: {c.shadowed?.policy_id}:{c.shadowed?.rule_id} ({c.shadowed?.coverage} coverage)</div>
                        </div>
                    </div>
                    <p style={{ ...s.muted, color: '#C9D1D9', marginTop: '10px' }}>{c.explanation}</p>
                </section>
            ))}

            <div style={s.muted}>
                Limitations: pairwise deterministic analysis over persisted rules; scope overlap is an existence check (a common target can match both),
                not an exhaustive target enumeration. Expired/disabled policies are reported as dormant with no runtime impact. Version shown is the currently active version.
            </div>
        </div>
    );
};

export default ConflictViewer;
