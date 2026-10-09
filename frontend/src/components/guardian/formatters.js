/* Shared formatting helpers — consistent timestamps, targets, identifiers. */

export const formatTimestamp = (value) => {
    if (value === null || value === undefined || value === '') return 'n/a';
    try {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString();
    } catch (e) {
        return String(value);
    }
};

export const formatTarget = (target) => {
    if (!target || typeof target !== 'object') return 'n/a';
    const entries = Object.entries(target);
    if (!entries.length) return 'any target';
    return entries.map(([k, v]) => `${k}=${String(v)}`).join(', ');
};

export const truncateId = (value, length = 12) => {
    if (!value) return 'n/a';
    const text = String(value);
    return text.length > length ? `${text.slice(0, length)}…` : text;
};

export const severityStyle = (severity) => {
    switch (String(severity || '').toLowerCase()) {
        case 'critical': return { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' };
        case 'high': return { color: '#D29922', backgroundColor: 'rgba(210,153,34,0.15)' };
        case 'medium': return { color: '#A371F7', backgroundColor: 'rgba(163,113,247,0.15)' };
        case 'low': return { color: '#3FB950', backgroundColor: 'rgba(46,160,67,0.15)' };
        default: return { color: '#8B949E', backgroundColor: 'rgba(139,148,158,0.15)' };
    }
};

export const statusStyle = (status) => {
    const value = String(status || '').toLowerCase();
    if (['deny', 'blocked', 'failed', 'execution_failed', 'verification_failed', 'rollback_failed'].includes(value)) {
        return { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' };
    }
    if (['succeeded', 'allow', 'active', 'running', 'approved'].includes(value)) {
        return { color: '#3FB950', backgroundColor: 'rgba(46,160,67,0.15)' };
    }
    if (['pending', 'awaiting_approval', 'require_approval', 'approval_required', 'rollback_available'].includes(value)) {
        return { color: '#D29922', backgroundColor: 'rgba(210,153,34,0.15)' };
    }
    return { color: '#8B949E', backgroundColor: 'rgba(139,148,158,0.15)' };
};

export const isExpired = (expiresAt) => {
    if (!expiresAt) return false;
    try {
        return new Date(expiresAt).getTime() <= Date.now();
    } catch (e) {
        return false;
    }
};

export const sharedStyles = {
    panel: { backgroundColor: '#1E232E', borderRadius: '8px', border: '1px solid #2A303C', padding: '20px' },
    title: { fontSize: '20px', fontWeight: '600', color: '#E0E6ED', margin: '0 0 12px 0' },
    muted: { color: '#8B949E', fontSize: '13px' },
    tableWrap: { overflowX: 'auto', backgroundColor: '#1E232E', borderRadius: '8px', border: '1px solid #2A303C' },
    table: { width: '100%', borderCollapse: 'collapse', minWidth: '640px' },
    th: { padding: '12px', textAlign: 'left', color: '#8B949E', fontSize: '13px', fontWeight: '600', borderBottom: '1px solid #2A303C', backgroundColor: '#161B22' },
    td: { padding: '12px', fontSize: '13px', color: '#C9D1D9', verticalAlign: 'top' },
    badge: { padding: '3px 8px', borderRadius: '12px', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', display: 'inline-block' },
    btn: { border: '1px solid #2A303C', padding: '7px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', backgroundColor: '#2A303C', color: '#FFF' },
    btnDanger: { backgroundColor: '#DA3633', borderColor: '#DA3633', color: '#FFF' },
    btnPrimary: { backgroundColor: '#238636', borderColor: '#238636', color: '#FFF' },
    input: { backgroundColor: '#0D1117', border: '1px solid #2A303C', borderRadius: '6px', color: '#C9D1D9', padding: '8px 10px', fontSize: '13px', width: '100%' },
    label: { color: '#8B949E', fontSize: '12px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.4px' },
    error: { color: '#F85149', fontSize: '13px', backgroundColor: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: '6px', padding: '10px 12px' },
    empty: { padding: '24px', textAlign: 'center', color: '#8B949E', fontStyle: 'italic', fontSize: '13px' },
};
