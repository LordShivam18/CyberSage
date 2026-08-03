import axios from 'axios';

let authToken = '';
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';
const api = axios.create({ baseURL: API_BASE_URL });

export const setAuthToken = (token) => {
    authToken = token || '';
};

const authHeaders = () => (
    authToken ? { Authorization: `Bearer ${authToken}` } : {}
);

export const fetchAlerts = async () => {
    const response = await api.get('/api/v1/alerts?limit=100');
    return response.data.items || response.data;
};

export const fetchAlertPage = async (params = {}) => {
    const response = await api.get('/api/v1/alerts', { params });
    return response.data;
};

export const fetchIncidents = async (params = {}) => {
    const response = await api.get('/api/v1/incidents', { params });
    return response.data;
};

export const fetchEvents = async (params = {}) => {
    const response = await api.get('/api/v1/events', { params });
    return response.data;
};

export const fetchMetrics = async () => {
    const response = await api.get('/api/v1/metrics');
    return response.data;
};

export const fetchModelStatus = async () => {
    const response = await api.get('/api/v1/model/status');
    return response.data;
};

export const postPrediction = async (formData) => {
    const response = await api.post('/predict', formData);
    return response.data;
};

export const login = async (credentials) => {
    const response = await api.post('/api/v1/auth/login', credentials);
    setAuthToken(response.data.access_token);
    return response.data;
};

export const updateAlert = async (alertId, payload) => {
    const response = await api.patch(`/api/v1/alerts/${alertId}`, payload, { headers: authHeaders() });
    return response.data;
};

export const updateIncident = async (incidentId, payload) => {
    const response = await api.patch(`/api/v1/incidents/${incidentId}`, payload, { headers: authHeaders() });
    return response.data;
};

export const ingestEvent = async (payload, sourceHint) => {
    const response = await api.post(
        '/api/v1/events',
        { payload, source_hint: sourceHint },
        { headers: authHeaders() }
    );
    return response.data;
};

export const alertWebSocketUrl = () => {
    const appendToken = (url) => {
        if (!authToken) return url;
        const separator = url.includes('?') ? '&' : '?';
        return `${url}${separator}token=${encodeURIComponent(authToken)}`;
    };
    if (!API_BASE_URL) {
        const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
        return appendToken(`${scheme}://${window.location.host}/api/v1/ws/alerts`);
    }
    const url = new URL('/api/v1/ws/alerts', API_BASE_URL);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return appendToken(url.toString());
};
