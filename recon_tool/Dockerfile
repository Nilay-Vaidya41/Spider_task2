FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Install only required Python packages
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]
