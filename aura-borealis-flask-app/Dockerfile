FROM python:3.8

COPY aura-borealis-flask-app/requirements.txt /

RUN pip3 install -r requirements.txt

WORKDIR app
COPY aura-borealis-flask-app/. /app/

#CMD [ "gunicorn", "--workers=4", "--threads=1", "-b 0.0.0.0:8050", "app"]
CMD python app.py
