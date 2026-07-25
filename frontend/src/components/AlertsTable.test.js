import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AlertsTable from './AlertsTable';

global.IS_REACT_ACT_ENVIRONMENT = true;

test('renders alert rows with severity and route', () => {
    const container = document.createElement('div');
    const root = createRoot(container);
    act(() => {
        root.render(
            <AlertsTable
                alerts={[
                    {
                        id: 1,
                        timestamp: '2026-01-01T00:00:00Z',
                        severity: 'high',
                        status: 'new',
                        classification: 'ATTACK',
                        confidence: 0.91,
                        detection_source: 'hybrid',
                        source_ip: '10.0.0.1',
                        destination_ip: '203.0.113.66',
                    },
                ]}
                isLoading={false}
                error=""
            />
        );
    });

    expect(container.textContent).toContain('ATTACK');
    expect(container.textContent).toContain('10.0.0.1 -> 203.0.113.66');

    act(() => root.unmount());
});
