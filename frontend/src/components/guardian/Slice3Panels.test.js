import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import PolicyBrowser from './PolicyBrowser';
import SimulatePanel from './SimulatePanel';
import ConflictViewer from './ConflictViewer';
import ExecutionBrowser from './ExecutionBrowser';

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

describe('PolicyBrowser', () => {
    const realFetch = global.fetch;
    afterEach(() => {
        global.fetch = realFetch;
        document.body.innerHTML = '';
    });

    test('lists policies with version and empty-state handling', async () => {
        global.fetch = jest.fn(async (url) => {
            if (String(url).includes('/conflicts')) {
                return { ok: true, json: async () => ({ total: 0, conflicts: 0, advisories: 0, items: [] }) };
            }
            return {
                ok: true,
                json: async () => ({
                    total: 1,
                    items: [{
                        policy_id: 'p-demo', name: 'Demo', description: 'd', mode: 'approval_required',
                        enabled: true, version: 2, priority: 100, expires_at: null, rules: [],
                    }],
                }),
            };
        });
        const { container, root } = render(<PolicyBrowser token="t" role="read_only_auditor" />);
        await act(async () => { await flush(); await flush(); });
        expect(container.textContent).toContain('p-demo');
        expect(container.textContent).toContain('v2');
        expect(container.textContent).toContain('read-only for policy mutations');
        act(() => root.unmount());
    });

    test('admin sees mutation controls', async () => {
        global.fetch = jest.fn(async (url) => {
            if (String(url).includes('/policies/p-')) {
                return { ok: true, json: async () => ({ policy_id: 'p-1', name: 'N', description: '', mode: 'approval_required', enabled: true, version: 1, priority: 100, expires_at: null, rules: [] }) };
            }
            if (String(url).includes('/evaluations')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/conflicts')) {
                return { ok: true, json: async () => ({ total: 0, conflicts: 0, advisories: 0, items: [] }) };
            }
            return { ok: true, json: async () => ({ total: 1, items: [{ policy_id: 'p-1', name: 'N', description: '', mode: 'approval_required', enabled: true, version: 1, priority: 100, expires_at: null, rules: [] }] }) };
        });
        const { container, root } = render(<PolicyBrowser token="t" role="administrator" />);
        await act(async () => { await flush(); await flush(); });
        // Select the policy row to load detail with admin controls.
        const row = container.querySelector('tbody tr');
        await act(async () => { row?.dispatchEvent(new MouseEvent('click', { bubbles: true })); await flush(); await flush(); });
        expect(container.textContent).toContain('Policy Detail');
        act(() => root.unmount());
    });
});

describe('SimulatePanel', () => {
    const realFetch = global.fetch;
    afterEach(() => {
        global.fetch = realFetch;
        document.body.innerHTML = '';
    });

    test('labels simulated outcomes and never calls executions', async () => {
        const calls = [];
        global.fetch = jest.fn(async (url, options) => {
            calls.push(String(url));
            if (String(url).includes('/actions/registry')) {
                return { ok: true, json: async () => ({ actions: [] }) };
            }
            return {
                ok: true,
                json: async () => ({
                    decision: 'require_approval', reason: 'rule:r-a', matched_policy_id: 'p-demo',
                    matched_policy_version: 1, matched_rule_id: 'r-a', approval_mode: 'required',
                    would_require_approval: true, would_execute: false, blocked_reason: 'simulation',
                    safety_checks: ['kill_switch'], evaluated_policies: 1, candidate_rules: 1,
                    scope_specificity: 0, explanation: 'simulation explanation',
                    evaluation_id: 'evl-1', existing: false, kill_switch_active: false,
                }),
            };
        });
        const { container, root } = render(<SimulatePanel token="t" role="security_analyst" />);
        await act(async () => { await flush(); });
        const form = container.querySelector('form');
        await act(async () => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await flush(); await flush(); });
        expect(container.textContent).toContain('SIMULATED');
        expect(container.textContent).toContain('never executes');
        expect(calls.some((u) => u.includes('/simulate'))).toBe(true);
        expect(calls.some((u) => u.includes('/executions'))).toBe(false);
        act(() => root.unmount());
    });

    test('auditor role sees disabled simulation notice', async () => {
        global.fetch = jest.fn(async () => ({ ok: true, json: async () => ({ actions: [] }) }));
        const { container, root } = render(<SimulatePanel token="t" role="read_only_auditor" />);
        await act(async () => { await flush(); });
        expect(container.textContent).toContain('cannot simulate');
        act(() => root.unmount());
    });
});

describe('ConflictViewer', () => {
    const realFetch = global.fetch;
    afterEach(() => {
        global.fetch = realFetch;
        document.body.innerHTML = '';
    });

    test('renders advisory notice and conflict badges', async () => {
        global.fetch = jest.fn(async (url) => {
            if (String(url).includes('/automation/v5/policies')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            return {
                ok: true,
                json: async () => ({
                    total: 1, conflicts: 1, notices: 0,
                    items: [{
                        conflict_id: 'cfx-abc', type: 'deny_conflict', is_conflict: true,
                        runtime_impact: true, severity: 'high',
                        rules: [
                            { policy_id: 'p-a', rule_id: 'r-d', decision: 'deny', priority: 100, action_type: 'network', action_name: 'block_destination' },
                            { policy_id: 'p-b', rule_id: 'r-a', decision: 'allow', priority: 100, action_type: 'network', action_name: 'block_destination' },
                        ],
                        overlap: { risk_range: [0, 100], severities: [], scope_keys: [], action_type: ['network', 'network'], action_name: ['block_destination', 'block_destination'] },
                        precedence: { winner_rule_id: 'r-d', winner_policy_id: 'p-a', winner_policy_version: 1, reason: 'deny_overrides_non_deny' },
                        shadowed: { policy_id: 'p-b', rule_id: 'r-a', coverage: 'full' },
                        ambiguous: false, advisory: 'Advisory only', explanation: 'Deny overrides.',
                    }],
                }),
            };
        });
        const { container, root } = render(<ConflictViewer token="t" />);
        await act(async () => { await flush(); await flush(); });
        expect(container.textContent).toContain('Advisory only');
        expect(container.textContent).toContain('conflict');
        act(() => root.unmount());
    });

    test('shows empty state when no overlaps', async () => {
        global.fetch = jest.fn(async () => ({ ok: true, json: async () => ({ total: 0, conflicts: 0, notices: 0, items: [], policies: [], }) }));
        const { container, root } = render(<ConflictViewer token="t" />);
        await act(async () => { await flush(); await flush(); });
        expect(container.textContent).toContain('No overlapping rule pairs');
        act(() => root.unmount());
    });
});

describe('ExecutionBrowser', () => {
    const realFetch = global.fetch;
    afterEach(() => {
        global.fetch = realFetch;
        document.body.innerHTML = '';
    });

    test('paginates and shows verification without inferring success', async () => {
        global.fetch = jest.fn(async (url) => {
            if (String(url).includes('/executions/exe-')) {
                return {
                    ok: true, json: async () => ({
                        execution_id: 'exe-1', evaluation_id: 'evl-1', policy_id: 'p-a', policy_version: 1,
                        rule_id: 'r-a', incident_id: null, decision_id: 'dec-1', approval_id: 'apr-1',
                        action_id: 'act-1', actor: 'responder', action_type: 'network', action_name: 'block_destination',
                        target: { destination_ip: '203.0.113.66' }, parameters: {}, status: 'blocked',
                        gates: [{ gate: 'target_validation', passed: false, reason: 'target_invalid' }],
                        execution_result: null, verification: null, rollback: null, error: 'target_invalid: loopback',
                        correlation_id: null, created_at: '2026-01-01T00:00:00', updated_at: '2026-01-01T00:00:00',
                    }),
                };
            }
            if (String(url).includes('/actions')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            if (String(url).includes('/audit')) {
                return { ok: true, json: async () => ({ total: 0, items: [] }) };
            }
            return {
                ok: true, json: async () => ({
                    total: 1, limit: 20, offset: 0,
                    items: [{ execution_id: 'exe-1', policy_id: 'p-a', policy_version: 1, action_type: 'network', action_name: 'block_destination', status: 'blocked', error: 'target_invalid', created_at: '2026-01-01T00:00:00' }],
                }),
            };
        });
        const { container, root } = render(<ExecutionBrowser token="t" />);
        await act(async () => { await flush(); await flush(); });
        expect(container.textContent).toContain('exe-1'.slice(0, 6));
        const row = container.querySelector('tbody tr');
        await act(async () => { row?.dispatchEvent(new MouseEvent('click', { bubbles: true })); await flush(); await flush(); });
        expect(container.textContent).toContain('Safety gates');
        expect(container.textContent).toContain('target_invalid');
        // Status badge for this execution must be blocked (not succeeded).
        expect(container.textContent).toContain('Stateblocked');
        expect(container.textContent).toContain('No independent verification recorded');
        act(() => root.unmount());
    });
});
