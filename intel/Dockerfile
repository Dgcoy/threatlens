FROM python:3.12-slim

WORKDIR /app

COPY intel/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ shared/
COPY intel/*.py ./

CMD ["python3", "main.py"]
