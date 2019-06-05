FROM python:2.7

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install -r /tmp/requirements.txt

WORKDIR /spoofcheck
COPY . .

ENTRYPOINT ["./spoofcheck.py"]
