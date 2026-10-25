
import os
import json
import joblib
import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="Sentinel AI | Cybersecurity",
    page_icon="🛡️",
    layout="wide"
)

MODEL_PATH = "models/sentinel_model.pkl"
ENCODER_PATH = "models/label_encoder.pkl"
FEATURE_PATH = "models/feature_names.pkl"

PERFORMANCE_PATH = "models/model_performance.json"

DATA_PATH = (
    "MachineLearningCVE/"
    "Tuesday-WorkingHours.pcap_ISCX.csv"
)
model = None
encoder = None
feature_names = None

try:

    if (
        os.path.exists(MODEL_PATH)
        and os.path.exists(ENCODER_PATH)
        and os.path.exists(FEATURE_PATH)
    ):

        model = joblib.load(MODEL_PATH)

        encoder = joblib.load(ENCODER_PATH)

        feature_names = joblib.load(FEATURE_PATH)

except Exception as e:

    st.error("Unable to load the ML model.")

    st.code(str(e))
st.markdown(
    """
    <style>

    .stApp {
        background-color: #0b1120;
        color: #e2e8f0;
    }

    .block-container {
        padding-top: 2rem;
    }

    [data-testid="stMetric"] {
        background: #151f32;
        border: 1px solid #263650;
        padding: 18px;
        border-radius: 12px;
    }

    h1, h2, h3 {
        color: #e2e8f0;
    }

    </style>
    """,
    unsafe_allow_html=True
)
st.sidebar.title("🛡️ Sentinel AI")

st.sidebar.caption(
    "Intelligent Threat Detection"
)

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Threat Analysis",
        "ML Prediction",
        "Model Performance",
        "About"
    ]
)

st.sidebar.divider()

st.sidebar.caption(
    "AI-Powered Network Security"
)
@st.cache_data
def load_dataset():

    if not os.path.exists(DATA_PATH):

        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    data = pd.read_csv(
        DATA_PATH,
        low_memory=False
    )

    data.columns = data.columns.str.strip()

    if "Label" not in data.columns:

        raise ValueError(
            "Label column not found in dataset."
        )

    data["Label"] = (
        data["Label"]
        .astype(str)
        .str.strip()
    )

    return data
if page == "Overview":

    st.title("🛡️ Sentinel AI")

    st.subheader(
        "Intelligent Cyber Threat Detection System"
    )

    st.write(
        "Machine Learning powered network security "
        "analytics and threat classification."
    )

    try:

        data = load_dataset()

        total_flows = len(data)

        benign_flows = (
            data["Label"].str.upper() == "BENIGN"
        ).sum()

        attack_flows = (
            total_flows - benign_flows
        )

        attack_percentage = (
            attack_flows / total_flows * 100
            if total_flows > 0
            else 0
        )

        st.subheader("Network Traffic Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Network Flows",
            f"{total_flows:,}"
        )

        col2.metric(
            "Normal Traffic",
            f"{benign_flows:,}"
        )

        col3.metric(
            "Attack Traffic",
            f"{attack_flows:,}"
        )

        col4.metric(
            "Attack Percentage",
            f"{attack_percentage:.2f}%"
        )

        st.divider()

        left, right = st.columns(2)

        # THREAT DISTRIBUTION

        with left:

            st.subheader("Threat Distribution")

            threat_data = pd.DataFrame(
                {
                    "Category": [
                        "BENIGN",
                        "ATTACK"
                    ],
                    "Count": [
                        benign_flows,
                        attack_flows
                    ]
                }
            )

            fig = px.pie(
                threat_data,
                names="Category",
                values="Count",
                hole=0.55,
                title="CIC-IDS2017 Traffic"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0b1120",
                plot_bgcolor="#0b1120"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        # ATTACK DISTRIBUTION

        with right:

            st.subheader("Attack Distribution")

            attack_data = data[
                data["Label"].str.upper() != "BENIGN"
            ]

            attack_counts = (
                attack_data["Label"]
                .value_counts()
                .head(10)
                .reset_index()
            )

            attack_counts.columns = [
                "Attack Type",
                "Count"
            ]

            if not attack_counts.empty:

                fig2 = px.bar(
                    attack_counts,
                    x="Attack Type",
                    y="Count",
                    title="Top 10 Attack Types"
                )

                fig2.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#0b1120",
                    plot_bgcolor="#0b1120"
                )

                st.plotly_chart(
                    fig2,
                    use_container_width=True
                )

            else:

                st.info(
                    "No attack records found."
                )

        st.divider()

        st.info(
            "Dataset: CIC-IDS2017 | "
            "Network Traffic Classification"
        )

    except Exception as e:

        st.error(
            "Dataset could not be loaded."
        )

        st.code(str(e))
   

elif page == "Threat Analysis":

    st.title("📊 Threat Analysis")

    st.caption(
        "CIC-IDS2017 Network Traffic Analytics"
    )

    try:

        data = load_dataset()

        total = len(data)

        benign = (
            data["Label"].str.upper() == "BENIGN"
        ).sum()

        attacks = total - benign

        attack_percentage = (
            attacks / total * 100
            if total > 0 else 0
        )

        st.subheader("Network Traffic Summary")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Flows",
            f"{total:,}"
        )

        col2.metric(
            "Normal Traffic",
            f"{benign:,}"
        )

        col3.metric(
            "Attack Traffic",
            f"{attacks:,}"
        )

        st.divider()

        st.subheader("Attack Types")

        attack_data = data[
            data["Label"].str.upper() != "BENIGN"
        ]

        attack_counts = (
            attack_data["Label"]
            .value_counts()
            .head(10)
            .reset_index()
        )

        attack_counts.columns = [
            "Attack Type",
            "Count"
        ]

        if not attack_counts.empty:

            fig = px.bar(
                attack_counts,
                x="Attack Type",
                y="Count",
                title="Top 10 Network Attack Types",
                hover_data=["Count"]
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0b1120",
                plot_bgcolor="#0b1120",
                xaxis_title="Attack Type",
                yaxis_title="Number of Flows"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

            st.divider()

            st.subheader("🛡️ Smart Security Insights")

            most_common_attack = (
                attack_counts.iloc[0]["Attack Type"]
            )

            st.metric(
                "Attack Traffic Percentage",
                f"{attack_percentage:.2f}%"
            )

            st.warning(
                f"Most common attack in this dataset: "
                f"{most_common_attack}"
            )

            attack_name = str(
                most_common_attack
            ).strip().upper()

            if "FTP-PATATOR" in attack_name:

                recommendation = (
                    "FTP-Patator is the most common attack "
                    "in this dataset. Review FTP services, "
                    "use secure file transfer protocols, "
                    "and monitor repeated login failures."
                )

            elif "SSH-PATATOR" in attack_name:

                recommendation = (
                    "SSH-Patator is the most common attack "
                    "in this dataset. Use strong authentication, "
                    "review SSH access settings, and monitor "
                    "repeated login attempts."
                )

            elif "DOS" in attack_name:

                recommendation = (
                    "DoS-related traffic is the most common "
                    "attack in this dataset. Review traffic "
                    "spikes, apply rate limiting, and monitor "
                    "network availability."
                )

            elif "BOT" in attack_name:

                recommendation = (
                    "Bot-related traffic is the most common "
                    "attack in this dataset. Review suspicious "
                    "connections, endpoint activity, and "
                    "network communication patterns."
                )

            elif "PORTSCAN" in attack_name:

                recommendation = (
                    "Port scanning is the most common attack "
                    "in this dataset. Review exposed services, "
                    "restrict unnecessary ports, and monitor "
                    "repeated connection attempts."
                )

            else:

                recommendation = (
                    f"{most_common_attack} is the most common "
                    "attack in this dataset. Review related "
                    "network activity, investigate suspicious "
                    "connections, and apply suitable security "
                    "controls."
                )

            st.info(recommendation)

            st.caption(
                "These insights are generated from the "
                "CIC-IDS2017 dataset, not live network traffic."
            )

        else:

            st.success(
                "No attack records found in the dataset."
            )

        st.divider()

        st.info(
            "Dataset: CIC-IDS2017 | "
            "Network Traffic Classification"
        )

    except Exception as e:

        st.error(
            "Unable to load threat analytics."
        )

        st.code(str(e))

       


# --------------------------------------------------
# MACHINE LEARNING PREDICTION PAGE
# --------------------------------------------------

elif page == "ML Prediction":

    st.title("🤖 ML Threat Prediction")

    st.caption(
        "Machine Learning Network Traffic Classification"
    )

    if model is None or encoder is None:

        st.error(
            "ML model not found. "
            "Please check your model files."
        )

    else:

        st.write(
            "Enter network traffic features to classify "
            "the traffic using the trained ML model."
        )

        with st.form("prediction_form"):

            col1, col2 = st.columns(2)

            with col1:

                flow_duration = st.number_input(
                    "Flow Duration",
                    min_value=0.0,
                    value=5000.0
                )

                fwd_packets = st.number_input(
                    "Total Forward Packets",
                    min_value=0.0,
                    value=100.0
                )

                bwd_packets = st.number_input(
                    "Total Backward Packets",
                    min_value=0.0,
                    value=80.0
                )

            with col2:

                flow_bytes = st.number_input(
                    "Flow Bytes per Second",
                    min_value=0.0,
                    value=5000.0
                )

                flow_packets = st.number_input(
                    "Flow Packets per Second",
                    min_value=0.0,
                    value=100.0
                )

                packet_mean = st.number_input(
                    "Packet Length Mean",
                    min_value=0.0,
                    value=50.0
                )

            submitted = st.form_submit_button(
                "🔍 Analyze Network Traffic",
                use_container_width=True
            )

        if submitted:

            try:

                input_data = pd.DataFrame(
                    [
                        {
                            "Flow Duration": flow_duration,
                            "Total Fwd Packets": fwd_packets,
                            "Total Backward Packets": bwd_packets,
                            "Flow Bytes/s": flow_bytes,
                            "Flow Packets/s": flow_packets,
                            "Packet Length Mean": packet_mean
                        }
                    ]
                )

                # Match trained model feature order

                if feature_names is not None:

                    input_data = input_data[
                        list(feature_names)
                    ]

                prediction = model.predict(
                    input_data
                )

                predicted_label = (
                    encoder.inverse_transform(
                        prediction
                    )[0]
                )

                probability = model.predict_proba(
                    input_data
                )

                confidence = (
                    max(probability[0]) * 100
                )

                st.divider()

                st.subheader("Prediction Result")

                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Predicted Traffic",
                    predicted_label
                )

                col2.metric(
                    "Confidence Score",
                    f"{confidence:.2f}%"
                )

                if predicted_label.upper() == "BENIGN":

                    col3.metric(
                        "Risk Level",
                        "NORMAL"
                    )

                    st.success(
                        "✅ BENIGN CLASSIFIED"
                    )

                else:

                    col3.metric(
                        "Risk Level",
                        "HIGH"
                    )

                    st.error(
                        "⚠️ ATTACK CLASSIFIED"
                    )

                st.info(
                    "Sentinel AI uses CIC-IDS2017 "
                    "network traffic data for classification. "
                    "This prediction is for educational "
                    "and research purposes."
                )

            except Exception as e:

                st.error(
                    "Prediction could not be completed."
                )

                st.code(str(e))


# --------------------------------------------------
# MODEL PERFORMANCE PAGE
# --------------------------------------------------

elif page == "Model Performance":

    st.title("📊 Model Performance")

    st.caption(
        "Machine Learning Model Evaluation"
    )

    if os.path.exists(PERFORMANCE_PATH):

        try:

            with open(
                PERFORMANCE_PATH,
                "r"
            ) as file:

                performance = json.load(file)

            report = performance[
                "classification_report"
            ]

            st.subheader("Model Evaluation")

            col1, col2, col3, col4 = (
                st.columns(4)
            )

            col1.metric(
                "Accuracy",
                f"{performance['accuracy'] * 100:.2f}%"
            )

            if "ATTACK" in report:

                col2.metric(
                    "Attack Precision",
                    f"{report['ATTACK']['precision'] * 100:.2f}%"
                )

                col3.metric(
                    "Attack Recall",
                    f"{report['ATTACK']['recall'] * 100:.2f}%"
                )

                col4.metric(
                    "Attack F1 Score",
                    f"{report['ATTACK']['f1-score'] * 100:.2f}%"
                )

            else:

                st.warning(
                    "ATTACK metrics are not available "
                    "in the saved report."
                )

            st.divider()

            st.subheader("Classification Report")

            report_df = pd.DataFrame(
                report
            ).transpose()

            st.dataframe(
                report_df,
                use_container_width=True
            )

        except Exception as e:

            st.error(
                "Unable to read model performance."
            )

            st.code(str(e))

    else:

        st.warning(
            "Model performance file not found. "
            "Please train the model first."
        )


# --------------------------------------------------
# ABOUT PAGE
# --------------------------------------------------

elif page == "About":

    st.title("About Sentinel AI")

    st.markdown(
        """
        ## 🛡️ AI-Powered Network Security

        Sentinel AI is a machine learning based
        cybersecurity project designed to analyze
        network traffic and identify suspicious activity
        using the CIC-IDS2017 dataset.

        ### 🚀 Key Features

        - Network Traffic Classification
        - Machine Learning Threat Detection
        - Prediction Interface
        - Confidence Score Analysis
        - Risk Level Assessment
        - Interactive Security Dashboard
        - Model Performance Evaluation

        ### 🧠 Technology Stack

        - Python
        - Streamlit
        - Pandas
        - Scikit-learn
        - Plotly
        - CIC-IDS2017 Dataset

        ### 🎯 Project Objective

        To build an interactive machine learning
        dashboard that helps analyze network traffic
        and identify potentially suspicious activity.

        **Note:** This project is developed for
        educational and research purposes.
        """
    )

    st.divider()

    st.info(
        "Dataset: CIC-IDS2017 | "
        "Network Traffic Classification"
    )
