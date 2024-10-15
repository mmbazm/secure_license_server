import os
from fastapi import FastAPI, HTTPException, Response
import uvicorn
import tempfile
import base64

app = FastAPI()

# Get the path to the TLS certificate file from environment variables
certfile_path = os.getenv("tls.crt")


@app.get("/")
def read_root():
    return {"message": "Hello from Enclave World"}


@app.get("/get-certificate")
def get_certificate():
    """
    Endpoint to return the TLS certificate contents to the client.
    """
    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.crt', delete=False) as temp_file:
            # Write the certificate content to the temporary file
            temp_file.write(certfile_path)
            temp_file.flush()

            # Read the content back from the temporary file
            temp_file.seek(0)
            certificate_content = temp_file.read()

        # Remove the temporary file
        os.unlink(temp_file.name)
        return Response(content=certificate_content, media_type="text/plain")

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificate not found")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error reading certificate: {str(e)}")@app.get("/get-certificate")
