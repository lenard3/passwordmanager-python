FROM python:3.10

WORKDIR /app

RUN pip install pyotp
RUN pip install cryptography

COPY . /app

CMD ["python", "main.py"]
