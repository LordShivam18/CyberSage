import React, { useState, useEffect, useCallback } from 'react';
import { listNdrIncidents, normalizePage } from './guardianApi';
import { formatTimestamp, severityStyle, sharedStyles as s } from './formatters';

const IncidentQueue = ({ token }) => {
    const [page, setPage] = useState({ total: 0, items: [] });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const load = useCallback(async () => {
        if (!token) {
            setLoading(false);
            return;
        }
        setLoading(true);
        setError('');
        try {
            // NDR incidents endpoint is unauthenticated for reads in this app,
            // but we pass the token when present for consistency.
            const data = await listNdrIncidents(token, { limit: 50 });
            setPage(normalizePage(data));
        } catch (err) {
            setError(err.message || 'Failed to fetch incidents.');
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        load();
    }, [load]);

    if (!token) return <div style={s.empty}>Sign in to view the incident queue.</div>;

    return (
        <div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '16px' }}>
                <h2 style={{ ...s.title, margin: 0 }}>Incident Queue</h2>
                <span style={s.muted}>{page.total} total</span>
                <span style={{ flex: 1 }} />
                <button style={s.btn} onClick={load} aria-label="Reload incidents">Reload</button>
            </div>
            {error && <div style={s.error} role="alert">{error}</div>}
            <div style={s.tableWrap}>
                <table style={s.table}>
                    <thead>
                        <tr>
                            <th style={s.th}>ID</th>
                            <th style={s.th}>Title</th>
                            <th style={s.th}>Severity</th>
                            <th style={s.th}>Status</th>
                            <th style={s.th}>Last seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" style={s.empty}>Loading…</td></tr>
                        ) : (page.items || []).length > 0 ? (
                            (page.items || []).map((inc) => (
                                <tr key={inc.id}>
                                    <td style={s.td}>INC-{inc.id}</td>
                                    <td style={s.td}>{inc.title}</td>
                                    <td style={s.td}>
                                        <span style={{ ...s.badge, ...severityStyle(inc.severity) }}>
                                            {inc.severity || 'unknown'}
                                        </span>
                                    </td>
                                    <td style={s.td}>{inc.status}</td>
                                    <td style={s.td}>{formatTimestamp(inc.last_seen || inc.created_at)}</td>
                                </tr>
                            ))
                        ) : (
                            <tr><td colSpan="5" style={s.empty}>No active incidents.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default IncidentQueue;
