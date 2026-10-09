import React, { useEffect, useState } from 'react';
import GuardianNav from './GuardianNav';
import GuardianDashboard from './GuardianDashboard';
import PolicyBrowser from './PolicyBrowser';
import SimulatePanel from './SimulatePanel';
import ConflictViewer from './ConflictViewer';
import ExecutionBrowser from './ExecutionBrowser';
import ApprovalQueue from './ApprovalQueue';
import IncidentQueue from './IncidentQueue';
import { getRoleFromToken } from './guardianApi';

const GuardianOps = ({ token: initialToken }) => {
    const [token, setToken] = useState(initialToken || localStorage.getItem('access_token') || '');
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    const [authError, setAuthError] = useState('');
    const [authBusy, setAuthBusy] = useState(false);
    const [user, setUser] = useState(null);
    const [activeTab, setActiveTab] = useState('dashboard');

    const role = user?.role || getRoleFromToken(token) || null;

    useEffect(() => {
        if (initialToken) setToken(initialToken);
    }, [initialToken]);

    const handleLogin = async (event) => {
        event.preventDefault();
        setAuthBusy(true);
        setAuthError('');
        try {
            const res = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(credentials),
            });
            if (!res.ok) {
                setAuthError('Sign-in failed (check username and password).');
                return;
            }
            const data = await res.json();
            if (data.access_token) {
                localStorage.setItem('access_token', data.access_token);
                setToken(data.access_token);
                setUser({ username: data.username, role: data.role });
                setCredentials({ username: '', password: '' });
            } else {
                setAuthError('Sign-in returned no token.');
            }
        } catch (err) {
            setAuthError('Sign-in failed: API unreachable.');
        } finally {
            setAuthBusy(false);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('access_token');
        setToken('');
        setUser(null);
    };

    const renderContent = () => {
        switch (activeTab) {
            case 'dashboard':
                return <GuardianDashboard token={token} />;
            case 'policies':
                return <PolicyBrowser token={token} role={role} />;
            case 'simulate':
                return <SimulatePanel token={token} role={role} />;
            case 'conflicts':
                return <ConflictViewer token={token} />;
            case 'executions':
                return <ExecutionBrowser token={token} />;
            case 'incidents':
                return <IncidentQueue token={token} />;
            case 'approvals':
                return <ApprovalQueue token={token} role={role} />;
            default:
                return <GuardianDashboard token={token} />;
        }
    };

    return (
        <div style={styles.container}>
            <GuardianNav currentTab={activeTab} setTab={setActiveTab} />
            <div style={styles.authBar}>
                {token ? (
                    <>
                        <span style={styles.authText}>
                            Signed in{user?.username ? ` as ${user.username}` : ''}{role ? ` (${role})` : ' (role unknown — backend RBAC remains authoritative)'}
                        </span>
                        <span style={styles.hint}>Hiding a button is not access control. AI is advisory-only.</span>
                        <button style={styles.authButton} onClick={handleLogout} aria-label="Sign out of Guardian">Sign out</button>
                    </>
                ) : (
                    <form style={styles.loginForm} onSubmit={handleLogin} aria-label="Guardian sign in">
                        <span style={styles.authText}>Sign in for Guardian operations (auditor read-only, analyst / responder / administrator as authorized):</span>
                        <input
                            aria-label="Username"
                            placeholder="Username"
                            autoComplete="username"
                            value={credentials.username}
                            onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
                            style={styles.input}
                        />
                        <input
                            aria-label="Password"
                            placeholder="Password"
                            type="password"
                            autoComplete="current-password"
                            value={credentials.password}
                            onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
                            style={styles.input}
                        />
                        <button type="submit" disabled={authBusy} style={styles.authButton} aria-label="Sign in">
                            {authBusy ? 'Signing in…' : 'Sign in'}
                        </button>
                        {authError && <span style={styles.authError} role="alert">{authError}</span>}
                    </form>
                )}
            </div>
            <div style={styles.content}>
                {renderContent()}
            </div>
        </div>
    );
};

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        backgroundColor: '#0D1117',
        color: '#C9D1D9',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
    },
    authBar: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        flexWrap: 'wrap',
        padding: '10px 24px',
        borderBottom: '1px solid #2A303C',
        backgroundColor: '#161B22',
    },
    authText: { fontSize: '13px', color: '#C9D1D9' },
    hint: { fontSize: '12px', color: '#8B949E' },
    authButton: {
        border: '1px solid #2A303C',
        padding: '6px 12px',
        borderRadius: '6px',
        cursor: 'pointer',
        fontSize: '13px',
        fontWeight: '600',
        backgroundColor: '#2A303C',
        color: '#FFF',
    },
    loginForm: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
    input: { backgroundColor: '#0D1117', border: '1px solid #2A303C', borderRadius: '6px', color: '#C9D1D9', padding: '6px 10px', fontSize: '13px' },
    authError: { color: '#F85149', fontSize: '13px' },
    content: {
        flex: 1,
        padding: '24px',
        overflowY: 'auto',
    },
};

export default GuardianOps;
