# Sentinel-AI

Machine Learning Based Network Traffic Classification and Cyber Security Dashboard.

## About
Sentinel AI is a machine learning-based cybersecurity project that analyzes network traffic data and classifies traffic as BENIGN or ATTACK using a trained Random Forest model.

## Features
- Network traffic overview dashboard
- Benign and attack traffic analysis
- Attack distribution visualization
- Machine learning-based traffic prediction
- Risk level and confidence display
- Model performance metrics

## Technologies Used
- Python
- Streamlit
- Pandas
- Scikit-learn
- Plotly
- NumPy
- Joblib

## Dataset
CIC-IDS2017 network traffic dataset.

The dashboard analyzes dataset records and supports prediction using manually entered network traffic features. It does not capture live network packets.

## How to Run

1. Install Python.
2. Install dependencies:

   `pip install -r requirements.txt`

3. Run the application:

   `python -m streamlit run app.py`

4. Open the local URL shown in the terminal.

## Project Structure

- `app.py` — Streamlit dashboard
- `train_model.py` — Model training script
- `requirements.txt` — Required Python libraries
- `models/` — Trained model and supporting files
- `dataset/` — Dataset location

## Disclaimer
This project is developed for educational and demonstration purposes. It is not a production-ready real-time intrusion detection system.
