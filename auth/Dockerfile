# Use the official Python image from the Docker Hub
FROM python:3.9-slim

COPY /app /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the working directory
WORKDIR /app

# Expose the gRPC port (50051)
EXPOSE 50051

# Command to run the application
CMD ["python", "authentication_service.py"]