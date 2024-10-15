
FROM python:3.10-slim


WORKDIR /app

COPY requirements.txt /app
COPY main.py /app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 80

ENV HOST=0.0.0.0 \
    PORT=8081

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"]
