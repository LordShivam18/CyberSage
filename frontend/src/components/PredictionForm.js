import React, { useCallback, useState } from 'react';
import { postPrediction } from '../apiService';

const initialFormState = {
    flow_duration: 83,
    tot_fwd_pkts: 2,
    tot_bwd_pkts: 2,
    totlen_fwd_pkts: 12,
    fwd_pkt_len_max: 6,
    fwd_pkt_len_min: 6,
    fwd_pkt_len_mean: 6.0,
    bwd_pkt_len_max: 6,
    flow_iat_mean: 27.6,
    flow_iat_max: 80,
    fwd_iat_tot: 83.0,
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
            setError('Prediction failed. Confirm the backend API is reachable.');
        } finally {
            setIsLoading(false);
        }
    }, [formData]);

    return (
        <div className="prediction-tool">
            <div className="section-heading">
                <h2>Live Prediction Analysis</h2>
                <span className="section-kicker">Legacy-compatible /predict</span>
            </div>
            <form onSubmit={handleSubmit} className="prediction-form">
                <div className="form-grid">
                    {Object.keys(initialFormState).map((key) => (
                        <label className="form-field" key={key} htmlFor={key}>
                            <span>{key.replace(/_/g, ' ')}</span>
                            <input
                                type="number"
                                step="any"
                                id={key}
                                name={key}
                                value={formData[key]}
                                onChange={handleInputChange}
                            />
                        </label>
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
                    <div className={`prediction-result ${String(prediction.prediction).toLowerCase()}`}>
                        <h4>Prediction: <span>{prediction.prediction}</span></h4>
                        <p>Confidence: <span>{(prediction.probability * 100).toFixed(2)}%</span></p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PredictionForm;
