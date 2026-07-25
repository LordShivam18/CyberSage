// frontend/src/components/PredictionForm.js

import React, { useState, useCallback } from 'react';
import { postPrediction } from '../apiService';

const initialFormState = {
    flow_duration: 83, tot_fwd_pkts: 2, tot_bwd_pkts: 2,
    totlen_fwd_pkts: 12, fwd_pkt_len_max: 6, fwd_pkt_len_min: 6,
    fwd_pkt_len_mean: 6.0, bwd_pkt_len_max: 6, flow_iat_mean: 27.6,
    flow_iat_max: 80, fwd_iat_tot: 83.0,
};

const PredictionForm = () => {
    const [formData, setFormData] = useState(initialFormState);
    const [prediction, setPrediction] = useState(null);
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleInputChange = useCallback((e) => {
        const { name, value } = e.target;
        setFormData(prevData => ({
            ...prevData,
            [name]: parseFloat(value) || 0,
        }));
    }, []);

    const handleSubmit = useCallback(async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        setPrediction(null);
        try {
            const data = await postPrediction(formData);
            setPrediction(data);
        } catch (err) {
            setError('Failed to get a prediction. Is the backend server running?');
        } finally {
            setIsLoading(false);
        }
    }, [formData]);

    return (
        <div className="prediction-form-container">
            <h2>🔬 Live Prediction Analysis</h2>
            <p>Enter network flow data to classify it in real-time.</p>
            <form onSubmit={handleSubmit} className="prediction-form">
                <div className="form-grid">
                    {Object.keys(initialFormState).map((key) => (
                        <div className="form-field" key={key}>
                            <label htmlFor={key}>{key.replace(/_/g, ' ')}</label>
                            <input
                                type="number" step="any" id={key} name={key}
                                value={formData[key]} onChange={handleInputChange}
                            />
                        </div>
                    ))}
                </div>
                <button type="submit" disabled={isLoading}>
                    {isLoading ? 'Analyzing...' : 'Analyze Flow'}
                </button>
            </form>
            <div className="results-display">
                <h3>Analysis Result</h3>
                {isLoading && <p>Loading...</p>}
                {error && <p className="error-message">{error}</p>}
                {prediction && (
                    <div className={`prediction-result ${prediction.prediction.toLowerCase()}`}>
                        <h4>Prediction: <span>{prediction.prediction}</span></h4>
                        <p>Confidence: <span>{(prediction.probability * 100).toFixed(2)}%</span></p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PredictionForm;