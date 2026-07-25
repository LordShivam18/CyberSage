// frontend/src/apiService.js

import axios from 'axios';

// The API_BASE_URL constant is no longer needed
// const API_BASE_URL = 'http://localhost:8000';

/**
 * Fetches the latest threat alerts from the backend.
 */
export const fetchAlerts = async () => {
    // Use a relative path. The React dev server will proxy this to http://localhost:8000/alerts
    const response = await axios.get('/alerts');
    return response.data;
};

/**
 * Posts network flow data to get a live prediction.
 * @param {object} formData - The network flow data.
 */
export const postPrediction = async (formData) => {
    // Use a relative path for this endpoint as well
    const response = await axios.post('/predict', formData);
    return response.data;
};