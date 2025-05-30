setup:
	python3 -m venv venv
	. venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt && pipenv install python-dotenv

run: 
	. venv/bin/activate && FLASK_APP=app.py flask run --port=5001
