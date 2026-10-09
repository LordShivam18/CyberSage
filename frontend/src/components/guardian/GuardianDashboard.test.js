import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import GuardianDashboard from './GuardianDashboard';

global.IS_REACT_ACT_ENVIRONMENT = true;

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function render(element) {
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    act(() => {
        root.render(element);
    });
    return { container, root };
}

describe('GuardianDashboard', () => {
    const realFetch = global.fetch;

    afterEach(() => {
        global.fetch = realFetch;
        document.body.innerHTML = '';
        jest.useRealTimers();
    });

    test('shows sign-in prompt without a token and no data', () => {
        const { container, root } = render(<GuardianDashboard token="" />);
        expect(container.textContent).toContain('Sign in');
        act(() => root.unmount());
    });

    test('renders backend-grounded sections and distinguishes unavailable from zero', async () => {
        global.fetch = jest.fn(async (url) => {
            if (String(url).includes('/dashboard')) {
                return { ok: true, json: async () => ({ status: 'online', collectors: [], recent_automation_runs: [], active_incidents_count: null, pending_approvals_count: 0 }) };
            }
            if (String(url).includes('/collectors/health')) {
                return { ok: true, json: async () => ({ collectors: [] }) };
            }
            if (String(url).includes('/guardian/stats')) {
                return { ok: false, status: 403, json: async () => ({ detail: 'Forbidden' }) };
            }
            if (String(url).includes('/guardian/incidents')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/api/v1/incidents')) {
                return { ok: true, json: async () => ({ total: 1, items: [{ id: 1, severity: 'high', status: 'new' }] }) };
            }
            if (String(url).includes('/approvals')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/evaluations')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/executions')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/safety/status')) {
                return { ok: true, json: async () => ({ kill_switches: [], circuit_breakers: {}, rate_limiter: {}, execution_modes: [] }) };
            }
            return { ok: true, json: async () => ({}) };
        });

        const { container, root } = render(<GuardianDashboard token="test-token" />);
        await act(async () => {
            await flush();
            await flush();
        });
        expect(container.textContent).toContain('Guardian Operations Overview');
        expect(container.textContent).toContain('unavailable');
        expect(container.textContent).toContain('Severity Distribution');
        act(() => root.unmount());
    });

    test('shows loading state initially', () => {
        global.fetch = jest.fn(() => new Promise(() => {}));
        const { container, root } = render(<GuardianDashboard token="test-token" />);
        expect(container.textContent).toContain('Loading');
        act(() => root.unmount());
    });
});
