import { useState, useEffect, useCallback } from 'react';

const API_BASE = '/api/v1/guardian';

/**
 * Hook to fetch Guardian Operational Dashboard Data
 */
export function useGuardianDashboard(token) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const refresh = useCallback(async () => {
        if (!token) return;
        try {
            setLoading(true);
            const res = await fetch(`${API_BASE}/dashboard`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const json = await res.json();
            setData(json);
            setError(null);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        refresh();
        const interval = setInterval(refresh, 15000); // 15s poll
        return () => clearInterval(interval);
    }, [refresh]);

    return { data, loading, error, refresh };
}

/**
 * Hook to fetch Guardian Approval Queue
 */
export function useGuardianApprovals(token) {
    const [approvals, setApprovals] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const refresh = useCallback(async () => {
        if (!token) return;
        try {
            setLoading(true);
            const res = await fetch(`${API_BASE}/approvals`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const json = await res.json();
            setApprovals(json.approvals || []);
            setError(null);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { approvals, loading, error, refresh };
}

/**
 * Hook to fetch Collector Health
 */
export function useCollectorHealth(token) {
    const [collectors, setCollectors] = useState([]);
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        if (!token) return;
        try {
            setLoading(true);
            const res = await fetch(`${API_BASE}/collectors/health`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) return;
            const json = await res.json();
            setCollectors(json.collectors || []);
        } catch (err) {
            console.error('Collector health fetch failed:', err);
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        refresh();
        const interval = setInterval(refresh, 30000); // 30s poll
        return () => clearInterval(interval);
    }, [refresh]);

    return { collectors, loading, refresh };
}
