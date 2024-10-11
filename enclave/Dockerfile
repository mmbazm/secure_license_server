FROM python:3.8-slim

COPY /app /app
COPY /files /files
COPY /config /config

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the working directory
WORKDIR /app

# Expose the gRPC port (55000)
EXPOSE 55000

CMD ["python", "enclave_operations_service.py"]