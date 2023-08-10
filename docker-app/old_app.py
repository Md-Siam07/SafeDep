import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix
import streamlit as st

# Read in data
f_path = "/app/conn_attack.csv"
df = pd.read_csv(f_path, names=[
                 "record ID", "duration_", "src_bytes", "dst_bytes"], header=None)

# Calculate statistics on data
median_duration = df['duration_'].median()
std_duration = df['duration_'].std()
median_src_b = df['src_bytes'].median()
std_src_b = df['src_bytes'].std()
median_dst_b = df['dst_bytes'].mean()
std_dst_b = df['dst_bytes'].std()
total_samples = df.count()

# Calculate suspected share of outliers in dataset
num_of_suspected_outliers = df[df['src_bytes']
                               > (median_src_b + std_dst_b)].count()
estimate_contamination = num_of_suspected_outliers / total_samples
estimate_contamination = estimate_contamination[0]
print("estimate_contamination:", estimate_contamination)
n_estimators = 50
data = df[["duration_", "src_bytes", "dst_bytes"]]

accuracy = 0
while (accuracy < 0.999):
    # trains the model
    model = IsolationForest(
        contamination=estimate_contamination, n_estimators=n_estimators)
    model.fit(data)

    # predicts
    df["is_anomaly?_"] = pd.Series(model.predict(data))
    # maps the predictions from 1->0 and from -1->1
    df["is_anomaly?_"] = df["is_anomaly?_"].map({1: 0, -1: 1})

    # loads the anomaly_labels file
    f_path = "/app/conn_attack_anomaly_labels.csv"
    df_labels = pd.read_csv(f_path, names=['record ID', 'anomaly'], header=None)
    y_test, y_pred = df_labels['anomaly'], df["is_anomaly?_"]

    # Display model accuracy
    accuracy = accuracy_score(df_labels['anomaly'], df['is_anomaly?_'])
    # st.text(f'Model Accuracy: {accuracy}')

# Get input from user
record_ID = st.number_input("record ID", value=0)
duration_ = st.number_input("Duration", value=0)
src_bytes = st.number_input("Source bytes", value=0)
dst_bytes = st.number_input("Destination bytes", value=0)

if st.button("Predict"):
    # Predict result
    sample_data = [duration_, src_bytes, dst_bytes]
    columns = ['duration_', 'src_bytes', 'dst_bytes']
    df_data = pd.DataFrame([sample_data], columns=columns)

    prediction = model.predict(df_data)[0]
    prediction_label = None
    if prediction == -1:
        prediction_label = 'Anomaly'
    else:
        prediction_label = 'Benign'

    # Display prediction
    if prediction_label == 'Anomaly':
        st.markdown(
            f'Prediction Result: <font color="red"> {prediction_label}</font>', unsafe_allow_html=True)
    else:
        st.markdown(
            f'Prediction Result: <font color="green"> {prediction_label}</font>', unsafe_allow_html=True)
