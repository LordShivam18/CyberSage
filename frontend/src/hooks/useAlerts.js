// frontend/src/hooks/useAlerts.js

import { useState, useEffect } from 'react';
import { fetchAlerts } from '../apiService';

export const useAlerts = (refreshInterval = 5000) => {
    const [alerts, setAlerts] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const getAlerts = async () => {
            try {
                const data = await fetchAlerts();
                setAlerts(data);
                setError(null);
            } catch (err) {
                console.error("Failed to fetch alerts:", err);
                setError("Could not load threat alerts.");
            } finally {
                setIsLoading(false);
            }
        };

        getAlerts(); // Initial fetch
        const intervalId = setInterval(getAlerts, refreshInterval);

        return () => clearInterval(intervalId); // Cleanup on unmount
    }, [refreshInterval]);

    return { alerts, isLoading, error };
};