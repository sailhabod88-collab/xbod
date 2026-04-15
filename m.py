import functools
from flask import redirect

# Updated admin_required decorator

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# Deleted /admin/login route
# Deleted /admin/logout route

# Deleted LOGIN_TEMPLATE definition

# Updated admin_index function

@app.route('/')
def index():
    return redirect('/admin')

# Updated log_action calls