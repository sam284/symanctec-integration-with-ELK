FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script into the container
COPY stream_events.py .

# Set environment variables (use real ENV or pass via `docker run`)
ENV SYMC_AUTH_HEADER=""
ENV SYMC_STREAM_GUID=""
ENV EVENT_TIMEOUT="120"
#ENV DEBUG=""
# Run the script
CMD ["python3", "stream_events.py"]
