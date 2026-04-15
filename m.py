# Updated m.py

from flask import Flask, render_template

app = Flask(__name__)

# Removed admin_required decorator and authentication checks

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/admin/login')
def admin_login():
    return render_template('login.html')  # This route is now publicly accessible

@app.route('/admin/logout')
def admin_logout():
    return render_template('logout.html')  # This route is now publicly accessible

# Removed LOGIN_TEMPLATE and made routes open

if __name__ == '__main__':
    app.run(debug=True)