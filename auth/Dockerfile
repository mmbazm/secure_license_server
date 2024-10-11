FROM python:3.8-slim

COPY /app /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app

EXPOSE 45000

CMD ["python", "authentication_service.py"]