import React, { useState, useEffect, useCallback } from 'react';
import { listApprovals, normalizePage } from './guardianApi';
import { formatTarget, truncateId, sharedStyles as s } from './formatters';

const ApprovalQueue = ({ token, role }) => {
    const [page, setPage] = useState({ total: 0, items: [] });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [statusFilter, setStatusFilter] = useState('');
    const [offset, setOffset] = useState(0);
    const limit = 20;

    const fetchApprovals = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        setError('');
        try {
            const data = await listApprovals(token, { limit, offset, status: statusFilter || undefined });
            setPage(normalizePage(data));
        } catch (err) {
            setError(err.status === 403 ? 'Forbidden for your role (HTTP 403).' : (err.message || 'Failed to fetch approvals.'));
        } finally {
            setLoading(false);
        }
    }, [token, offset, statusFilter]);

    useEffect(() => {
        fetchApprovals();
    }, [fetchApprovals]);

    const handleAction = async (id, action) => {
        if (!window.confirm(`${action === 'approve' ? 'Approve' : 'Reject'} approval ${id}? This is audited and cannot be undone from this view.`)) return;
        try {
            const res = await fetch(`/api/v1/guardian/approvals/${encodeURIComponent(id)}/${action}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ notes: `Operator ${action} from Guardian Ops UI` })
            });
            if (res.ok) {
                fetchApprovals();
            } else {
                let detail = `Failed to ${action} approval (HTTP ${res.status}).`;
                try {
                    const body = await res.json();
                    if (body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail).slice(0, 300);
                } catch (e) { /* keep default */ }
                setError(detail);
            }
        } catch (err) {
            setError('Action failed: API unreachable.');
        }
    };

    const canDecide = role === 'administrator' || role === 'security_analyst' || role === 'incident_responder';

    if (!token) return <div style={s.empty}>Sign in to view the approval queue.</div>;

    return (
        <div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '16px' }}>
                <h2 style={{ ...s.title, margin: 0 }}>Approval Queue</h2>
                <span style={s.muted}>{page.total} total</span>
                <span style={{ flex: 1 }} />
                <select aria-label="Filter approvals by status" value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }} style={{ ...s.input, maxWidth: '170px' }}>
                    <option value="">All statuses</option>
                    <option value="pending">Pending</option>
                    <option value="approved">Approved</option>
                    <option value="rejected">Rejected</option>
                    <option value="expired">Expired</option>
                </select>
                <button style={s.btn} onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset === 0} aria-label="Previous approvals page">Prev</button>
                <button style={s.btn} onClick={() => setOffset(offset + limit)} disabled={(page.items || []).length < limit} aria-label="Next approvals page">Next</button>
                <button style={s.btn} onClick={fetchApprovals} aria-label="Reload approvals">Reload</button>
            </div>
            {!canDecide && <div style={s.muted}>Your role ({role || 'unknown'}) is read-only for approvals. Approve/reject requires analyst, responder or administrator; the backend enforces this.</div>}
            {error && <div style={s.error} role="alert">{error}</div>}
            <div style={s.tableWrap}>
                <table style={s.table}>
                    <thead>
                        <tr>
                            <th style={s.th}>Approval ID</th>
                            <th style={s.th}>Action</th>
                            <th style={s.th}>Target</th>
                            <th style={s.th}>Status</th>
                            <th style={s.th}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" style={s.empty}>Loading…</td></tr>
                        ) : (page.items || []).length > 0 ? (
                            (page.items || []).map((app) => (
                                <tr key={app.approval_id || app.id}>
                                    <td style={s.td} title={app.approval_id}>
                                        {truncateId(app.approval_id, 12)}
                                    </td>
                                    <td style={s.td}>{app.action_type}:{app.requested_action}</td>
                                    <td style={s.td} title={JSON.stringify(app.target)}>{formatTarget(app.target)}</td>
                                    <td style={s.td}>
                                        <span style={{
                                            ...s.badge,
                                            backgroundColor: app.status === 'pending' ? 'rgba(210,153,34,0.15)' : 'rgba(139,148,158,0.15)',
                                            color: app.status === 'pending' ? '#D29922' : '#C9D1D9'
                                        }}>
                                            {app.status}
                                        </span>
                                    </td>
                                    <td style={s.td}>
                                        {app.status === 'pending' && canDecide && (
                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                <button
                                                    style={{ ...s.btn, ...s.btnPrimary }}
                                                    onClick={() => handleAction(app.approval_id, 'approve')}
                                                    aria-label={`Approve ${app.approval_id}`}
                                                >
                                                    Approve
                                                </button>
                                                <button
                                                    style={{ ...s.btn, ...s.btnDanger }}
                                                    onClick={() => handleAction(app.approval_id, 'reject')}
                                                    aria-label={`Reject ${app.approval_id}`}
                                                >
                                                    Reject
                                                </button>
                                            </div>
                                        )}
                                        {app.status === 'pending' && !canDecide && (
                                            <span style={s.muted}>Read-only for your role</span>
                                        )}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr><td colSpan="5" style={s.empty}>No approvals match this filter.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ApprovalQueue;
