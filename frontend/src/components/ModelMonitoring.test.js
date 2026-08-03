import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ModelMonitoring, { modelStateLabel } from './ModelMonitoring';

global.IS_REACT_ACT_ENVIRONMENT = true;

test('renders governed model quality and insufficient drift state', () => {
    const container = document.createElement('div');
    const root = createRoot(container);
    act(() => {
        root.render(
            <ModelMonitoring
                modelStatus={{
                    model: {
                        available: true,
                        state: 'active_trained',
                        model_version: 'benchmark-1-transformer',
                        feature_count: 4,
                        validation_metrics: { macro_f1: 0.8 },
                        test_metrics: { macro_f1: 0.7, per_class: [{ class: 'BENIGN', precision: 1, recall: 0.8, f1: 0.89, support: 5 }] },
                    },
                    governance: { drift: { status: 'insufficient_data', sample_window: 2, reason: 'Need more events' } },
                }}
            />
        );
    });
    expect(container.textContent).toContain('Active governed model');
    expect(container.textContent).toContain('Held-out Test Quality');
    expect(container.textContent).toContain('insufficient_data');
    act(() => root.unmount());
});

test('labels unavailable runtime as fallback', () => {
    expect(modelStateLabel({ available: false })).toBe('Fallback active');
});
