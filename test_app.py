from flask import Flask

app = Flask(__name__)
app.secret_key = 'test'

@app.route('/matches')
def matches():
    return "Test matches page"

if __name__ == '__main__':
    app.run(debug=True, port=5001)