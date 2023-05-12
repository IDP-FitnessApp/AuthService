FROM python:3.10-slim-buster as builder

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

from builder as runner

COPY . .

ENV FLASK_APP=authservice.py

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
