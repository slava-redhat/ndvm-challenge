FROM python:3.12-slim
WORKDIR /app
RUN useradd -m -d /home/app app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R app:app /app
USER app
ENV HOME=/home/app PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
