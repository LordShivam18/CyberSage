# AI-Enhanced Cybersecurity Threat Detector

**Project Overview:** A full-stack web application that uses a Transformer-based AI model to detect and analyze cybersecurity threats from a real-time data stream. The system features a live dashboard for monitoring alerts and performing on-demand analysis.

---

##  Features

-   **Real-Time Threat Analysis:** Ingests and analyzes network data streams via Apache Kafka.
-   **Advanced AI Model:** Utilizes a custom-built Transformer model in PyTorch to understand the context and sequence of network events, providing high-accuracy threat classification.
-   **Persistent Alert Storage:** Detected threats are automatically saved to a PostgreSQL database for historical review.
-   **Interactive Web Dashboard:** A modern, dark-themed frontend built with React for visualizing alerts and testing the model with live data.
-   **Decoupled & Scalable Architecture:** The use of Kafka allows for a flexible and scalable system where data producers and consumers are independent.

---

##  Tech Stack

| Component           | Technology                                                              | Purpose                                          |
| ------------------- | ----------------------------------------------------------------------- | ------------------------------------------------ |
| **AI & Data Science** | PyTorch, Pandas, Scikit-learn                                           | Building, training, and evaluating the AI model. |
| **Backend** | Python, FastAPI                                                         | Serving the AI model and RESTful API endpoints.  |
| **Data Pipeline** | Apache Kafka, Zookeeper                                                 | Real-time data streaming and management.         |
| **Database** | PostgreSQL                                                              | Storing and retrieving threat alert records.     |
| **Frontend** | React.js, Axios, Lucide-React                                           | Building the interactive user interface.         |
| **Environment** | Node.js/npm, Python Virtual Environment (`venv`), Java (for Kafka)      | Local development and dependency management.     |

---

##  System Architecture & Data Flow

The application operates as a distributed system with a clear, linear data flow:

1.  **Data Simulation (`kafka_producer.py`):** A script simulates a network event by sending a JSON message to a Kafka topic.
2.  **Real-Time Ingestion (Kafka):** The message is published to the `network_traffic` topic. Kafka acts as the central, high-throughput message broker.
3.  **Backend Consumption (`main.py`):** The FastAPI backend runs a background Kafka consumer that listens for new messages on the `network_traffic` topic.
4.  **AI-Powered Analysis:** Upon receiving a message, the backend uses the pre-trained PyTorch Transformer model to classify the network flow as "BENIGN" or "ATTACK".
5.  **Persistent Storage (PostgreSQL):** If a flow is classified as an "ATTACK", a new alert is saved to the `alerts` table in the PostgreSQL database.
6.  **Frontend Visualization (React):**
    -   The dashboard periodically fetches data from the `/alerts` API endpoint to display the latest threats.
    -   A separate form allows users to make manual requests to the `/predict` API endpoint to test the model.

---

##  AI Model Details

-   **Model Type:** A custom **Transformer Encoder** model built with PyTorch, specifically designed for numerical sequence classification.
-   **Dataset:** The model is trained on the **CIC-IDS2017** dataset, which contains a wide variety of modern network attacks. The individual daily CSV files are first merged into a single `MachineLearningCVE.csv` file using the `combine_csv.py` script.
-   **Training (`backend/train_model.py`):**
    1.  The script loads a random sample of the data to manage memory usage.
    2.  It preprocesses the data by cleaning it and normalizing numerical features using `MinMaxScaler`.
    3.  It converts the data into sequences of 10 consecutive network flows.
    4.  The Transformer model is trained on these sequences for 3 epochs.
    5.  The final trained model (`transformer_model.pth`) and the data scaler (`scaler.gz`) are saved to the `results/` directory.

---

## Project Structure

/├── backend/│   ├── main.py               # FastAPI application, Kafka consumer, API endpoints│   ├── train_model.py        # Script to train the AI model│   ├── kafka_producer.py     # Script to simulate an attack│   └── requirements.txt      # Python dependencies│├── data/│   ├── MachineLearningCVE/   # Folder with daily CSV files│   └── MachineLearningCVE.csv  # The combined dataset│├── frontend/│   ├── public/               # Static assets (index.html, background image)│   ├── src/│   │   ├── components/       # Reusable React components│   │   ├── hooks/            # Custom React hooks│   │   ├── App.js            # Main application component│   │   ├── Dashboard.js      # Main dashboard layout│   │   └── apiService.js     # Handles communication with the backend│   └── package.json          # Frontend dependencies and scripts│├── results/│   ├── model/│   │   └── transformer_model.pth # The trained PyTorch model│   └── scaler.gz             # The saved data scaler│├── combine_csv.py            # Script to merge the dataset files└── README.md                 # This file
---

##  How to Run the Application

### Prerequisites
-   Python 3.10+
-   Node.js and npm
-   PostgreSQL (with a database named `threatdb` created)
-   Java JDK 11+ (for Kafka)
-   Apache Kafka downloaded and extracted

### Step-by-Step Guide

You will need **four separate terminals** running simultaneously.

1.  **Start Zookeeper:**
    -   Open Terminal 1.
    -   Navigate to your Kafka directory.
    -   Run: `.\bin\windows\zookeeper-server-start.bat .\config\zookeeper.properties`

2.  **Start Kafka Server:**
    -   Open Terminal 2.
    -   Navigate to your Kafka directory.
    -   Run: `.\bin\windows\kafka-server-start.bat .\config\server.properties`

3.  **Start the Backend Server:**
    -   Open Terminal 3.
    -   Navigate to the project's root directory.
    -   Activate the virtual environment: `.\venv\Scripts\activate`
    -   Run the server: `python -m uvicorn backend.main:app --reload --host 0.0.0.0`

4.  **Start the Frontend Server:**
    -   Open Terminal 4.
    -   Navigate to the `frontend` directory.
    -   Run: `npm start`
    -   Your browser will open to `http://localhost:3000` (or another port).

### How to Test
-   **Live Prediction:** Use the form on the dashboard to analyze the default data or enter your own.
-   **Real-Time Alerts:** To see an alert appear in the table, open a fifth terminal, activate the `venv`, and run: `python backend/kafka_producer.py`. The table on the dashboard will update within 5 seconds.
