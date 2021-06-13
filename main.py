# libraries
from flask import Flask

app = Flask(__name__)


@app.route('/')
def hello_world():
    return {"ok": 200}


if __name__ == "__main__":
    app.run()
