from flask import Flask,render_template

app=Flask(__name__)

@app.route("/")
def home():
    pass


app.route("/malware-url")
def malware_url():
    pass


app.route("/malware-file")
def malware_file():
    pass

app.route("/malware-snippet")
def malware_snippet():
    pass




if __name__=="__main__":
    app.run(debug=True)