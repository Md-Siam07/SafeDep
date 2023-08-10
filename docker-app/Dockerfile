FROM python:3.10
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
EXPOSE 8501 

# Add the csv files to the image
COPY conn_attack.csv /app/conn_attack.csv
COPY conn_attack_anomaly_labels.csv /app/conn_attack_anomaly_labels.csv

COPY . /app
ENTRYPOINT ["streamlit", "run"]
CMD ["app.py"]

# build image: docker build -t ml-app:latest .
# run container: docker run -p 8501:8501 ml-app:latest
# source: https://www.youtube.com/watch?v=doCia_CKcko
