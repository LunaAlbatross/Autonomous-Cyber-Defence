from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'dev-key'

VALID_CREDENTIALS = {
    'admin': 'adminpass',
    'user': 'userpass'
}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if VALID_CREDENTIALS.get(username) == password:
            flash('Login successful', 'success')
        else:
            flash('Login failed', 'danger')

        return redirect(url_for('login'))

    return render_template('blog_login.html')

if __name__ == '__main__':
    print("[*] Starting backend Blog Application on port 5001...")
    app.run(debug=True, host='0.0.0.0', port=5001)
