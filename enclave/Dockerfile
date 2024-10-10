FROM python:3.9-slim

COPY /app /app
COPY /files /files

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the working directory
WORKDIR /app

# Expose the gRPC port (55000)
EXPOSE 55000

CMD ["python", "enclave_operations_service.py"]