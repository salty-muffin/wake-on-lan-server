FROM python:3.12-alpine

WORKDIR /app

# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt